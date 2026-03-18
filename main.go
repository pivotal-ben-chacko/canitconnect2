package main

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	_ "github.com/sijms/go-ora/v2"
)

//go:embed web/templates/*
var templateFS embed.FS

var hostRegex = regexp.MustCompile(`^[a-zA-Z0-9.:_-]+$`)

type CheckRequest struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

type DBCheckRequest struct {
	DBType   string `json:"db_type"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Database string `json:"database"`
	Username string `json:"username"`
	Password string `json:"password"`
	Region   string `json:"region"`
}

type CheckResponse struct {
	Success    bool   `json:"success"`
	Output     string `json:"output"`
	Error      string `json:"error,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	tmpl := template.Must(template.ParseFS(templateFS, "web/templates/*"))
	r.SetHTMLTemplate(tmpl)

	r.GET("/", func(c *gin.Context) {
		cfInfo := parseCFInfo()
		c.HTML(http.StatusOK, "index.html", cfInfo)
	})

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	r.POST("/api/check/netcat", handleNetcat)
	r.POST("/api/check/openssl", handleOpenSSL)
	r.POST("/api/check/traceroute", handleTraceroute)
	r.POST("/api/check/ping", handlePing)
	r.POST("/api/check/telnet", handleTelnet)
	r.POST("/api/check/dig", handleDig)
	r.POST("/api/check/database", handleDatabase)
	r.POST("/api/check/portscan", handlePortScan)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}

func parseCFInfo() gin.H {
	vcap := os.Getenv("VCAP_APPLICATION")
	if vcap == "" {
		return gin.H{}
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(vcap), &data); err != nil {
		return gin.H{}
	}

	info := gin.H{}
	if v, ok := data["organization_name"].(string); ok {
		info["Org"] = v
	}
	if v, ok := data["space_name"].(string); ok {
		info["Space"] = v
	}
	if v, ok := data["application_name"].(string); ok {
		info["App"] = v
	}
	if v, ok := data["cf_api"].(string); ok {
		info["API"] = v
	}
	instanceIP := os.Getenv("CF_INSTANCE_IP")
	if instanceIP != "" {
		info["InstanceIP"] = instanceIP
	}

	return info
}

func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if len(host) > 253 {
		return fmt.Errorf("host too long")
	}
	if !hostRegex.MatchString(host) {
		return fmt.Errorf("invalid host: only alphanumeric, dots, hyphens, underscores, and colons allowed")
	}
	return nil
}

func validatePort(port string) error {
	if port == "" {
		return fmt.Errorf("port is required")
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port must be numeric")
	}
	if p < 1 || p > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func runCommand(timeout time.Duration, name string, args ...string) (string, error, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	start := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	return string(output), err, duration
}

func handleNetcat(c *gin.Context) {
	var req CheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "invalid request body"})
		return
	}

	if err := validateHost(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}
	if err := validatePort(req.Port); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}

	output, err, duration := runCommand(30*time.Second, "nc", "-zv", req.Host, req.Port)
	resp := CheckResponse{
		Output:     strings.TrimSpace(output),
		DurationMs: duration.Milliseconds(),
	}
	if err != nil {
		resp.Success = false
		resp.Error = err.Error()
	} else {
		resp.Success = true
	}

	c.JSON(http.StatusOK, resp)
}

func handleOpenSSL(c *gin.Context) {
	var req CheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "invalid request body"})
		return
	}

	if err := validateHost(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}
	if err := validatePort(req.Port); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}

	target := req.Host + ":" + req.Port
	output, err, duration := runCommand(30*time.Second, "openssl", "s_client", "-connect", target, "-showcerts")
	resp := CheckResponse{
		Output:     strings.TrimSpace(output),
		DurationMs: duration.Milliseconds(),
	}
	if err != nil {
		// openssl s_client often exits non-zero even on success
		resp.Success = len(output) > 0
		if !resp.Success {
			resp.Error = err.Error()
		}
	} else {
		resp.Success = true
	}

	c.JSON(http.StatusOK, resp)
}

func handlePing(c *gin.Context) {
	var req CheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "invalid request body"})
		return
	}

	if err := validateHost(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}

	output, err, duration := runCommand(30*time.Second, "ping", "-c", "4", req.Host)
	resp := CheckResponse{
		Output:     strings.TrimSpace(output),
		DurationMs: duration.Milliseconds(),
	}
	if err != nil {
		resp.Success = false
		resp.Error = err.Error()
	} else {
		resp.Success = true
	}

	c.JSON(http.StatusOK, resp)
}

func handleTelnet(c *gin.Context) {
	var req CheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "invalid request body"})
		return
	}

	if err := validateHost(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}
	if err := validatePort(req.Port); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}

	target := req.Host + ":" + req.Port
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	duration := time.Since(start)

	resp := CheckResponse{
		DurationMs: duration.Milliseconds(),
	}
	if err != nil {
		resp.Success = false
		resp.Output = fmt.Sprintf("Trying %s...\ntelnet: Unable to connect to remote host: %s", target, err.Error())
		resp.Error = err.Error()
	} else {
		conn.Close()
		resp.Success = true
		resp.Output = fmt.Sprintf("Trying %s...\nConnected to %s.\nConnection closed.", target, target)
	}

	c.JSON(http.StatusOK, resp)
}

func handleDig(c *gin.Context) {
	var req CheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "invalid request body"})
		return
	}

	if err := validateHost(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}

	output, err, duration := runCommand(30*time.Second, "dig", req.Host)
	resp := CheckResponse{
		Output:     strings.TrimSpace(output),
		DurationMs: duration.Milliseconds(),
	}
	if err != nil {
		resp.Success = false
		resp.Error = err.Error()
	} else {
		resp.Success = true
	}

	c.JSON(http.StatusOK, resp)
}

func handleDatabase(c *gin.Context) {
	var req DBCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "invalid request body"})
		return
	}

	if err := validateHost(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}
	if err := validatePort(req.Port); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}
	// Redis doesn't require database/username
	if req.DBType == "redis" {
		handleRedis(c, req)
		return
	}
	// S3 uses different fields
	if req.DBType == "s3" {
		handleS3(c, req)
		return
	}

	if req.Database == "" {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "database/service name is required"})
		return
	}
	if req.Username == "" {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "username is required"})
		return
	}

	var driverName, connStr, versionQuery, testQuery, dbLabel string

	switch req.DBType {
	case "oracle":
		driverName = "oracle"
		connStr = fmt.Sprintf("oracle://%s:%s@%s:%s/%s",
			req.Username, req.Password, req.Host, req.Port, req.Database)
		versionQuery = "SELECT banner FROM v$version WHERE ROWNUM = 1"
		testQuery = "SELECT 'OK' FROM DUAL"
		dbLabel = "Oracle"
	case "mysql":
		driverName = "mysql"
		connStr = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?timeout=30s",
			req.Username, req.Password, req.Host, req.Port, req.Database)
		versionQuery = "SELECT VERSION()"
		testQuery = "SELECT 'OK'"
		dbLabel = "MySQL"
	case "postgres":
		driverName = "postgres"
		connStr = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&connect_timeout=30",
			req.Username, req.Password, req.Host, req.Port, req.Database)
		versionQuery = "SELECT version()"
		testQuery = "SELECT 'OK'"
		dbLabel = "PostgreSQL"
	default:
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "invalid db_type: must be oracle, mysql, postgres, or redis"})
		return
	}

	start := time.Now()
	var output strings.Builder

	output.WriteString(fmt.Sprintf("Connecting to %s at %s:%s/%s as %s...\n", dbLabel, req.Host, req.Port, req.Database, req.Username))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := sql.Open(driverName, connStr)
	if err != nil {
		duration := time.Since(start)
		output.WriteString(fmt.Sprintf("Failed to initialize driver: %s\n", err.Error()))
		c.JSON(http.StatusOK, CheckResponse{
			Success:    false,
			Output:     output.String(),
			Error:      err.Error(),
			DurationMs: duration.Milliseconds(),
		})
		return
	}
	defer db.Close()

	err = db.PingContext(ctx)
	if err != nil {
		duration := time.Since(start)
		output.WriteString(fmt.Sprintf("Connection FAILED: %s\n", err.Error()))
		c.JSON(http.StatusOK, CheckResponse{
			Success:    false,
			Output:     output.String(),
			Error:      err.Error(),
			DurationMs: duration.Milliseconds(),
		})
		return
	}

	output.WriteString("Connection successful!\n\n")

	var dbVersion string
	err = db.QueryRowContext(ctx, versionQuery).Scan(&dbVersion)
	if err != nil {
		output.WriteString(fmt.Sprintf("Connected but could not query version: %s\n", err.Error()))
	} else {
		output.WriteString(fmt.Sprintf("Database Version: %s\n", dbVersion))
	}

	var testResult string
	err = db.QueryRowContext(ctx, testQuery).Scan(&testResult)
	if err != nil {
		output.WriteString(fmt.Sprintf("Test query failed: %s\n", err.Error()))
	} else {
		output.WriteString(fmt.Sprintf("Test query result: %s\n", testResult))
	}

	duration := time.Since(start)
	c.JSON(http.StatusOK, CheckResponse{
		Success:    true,
		Output:     output.String(),
		DurationMs: duration.Milliseconds(),
	})
}

var commonPorts = []struct {
	Port    int
	Service string
}{
	{21, "FTP"},
	{22, "SSH"},
	{23, "Telnet"},
	{25, "SMTP"},
	{53, "DNS"},
	{80, "HTTP"},
	{110, "POP3"},
	{143, "IMAP"},
	{443, "HTTPS"},
	{465, "SMTPS"},
	{587, "SMTP (Submission)"},
	{993, "IMAPS"},
	{995, "POP3S"},
	{1433, "MSSQL"},
	{1521, "Oracle DB"},
	{2049, "NFS"},
	{3306, "MySQL"},
	{3389, "RDP"},
	{5432, "PostgreSQL"},
	{5672, "RabbitMQ"},
	{6379, "Redis"},
	{8080, "HTTP Alt"},
	{8443, "HTTPS Alt"},
	{9090, "Prometheus"},
	{9200, "Elasticsearch"},
	{27017, "MongoDB"},
}

func handlePortScan(c *gin.Context) {
	var req CheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "invalid request body"})
		return
	}

	if err := validateHost(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}

	start := time.Now()

	type portResult struct {
		Port    int
		Service string
		Open    bool
		Err     string
	}

	results := make([]portResult, len(commonPorts))
	var wg sync.WaitGroup

	for i, p := range commonPorts {
		wg.Add(1)
		go func(idx int, port int, service string) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", req.Host, port)
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			r := portResult{Port: port, Service: service}
			if err != nil {
				r.Open = false
				r.Err = err.Error()
			} else {
				conn.Close()
				r.Open = true
			}
			results[idx] = r
		}(i, p.Port, p.Service)
	}

	wg.Wait()
	duration := time.Since(start)

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	var output strings.Builder
	output.WriteString(fmt.Sprintf("Port Scan Report for %s\n", req.Host))

	ips, err := net.LookupHost(req.Host)
	if err != nil {
		output.WriteString(fmt.Sprintf("DNS resolution failed: %s\n", err.Error()))
	} else {
		output.WriteString(fmt.Sprintf("Resolved IP: %s\n", strings.Join(ips, ", ")))
	}

	output.WriteString(fmt.Sprintf("Scanned %d common ports in %dms\n", len(commonPorts), duration.Milliseconds()))
	output.WriteString(strings.Repeat("─", 52) + "\n")
	output.WriteString(fmt.Sprintf("%-8s %-22s %s\n", "PORT", "SERVICE", "STATUS"))
	output.WriteString(strings.Repeat("─", 52) + "\n")

	openCount := 0
	for _, r := range results {
		status := "closed/filtered"
		if r.Open {
			status = "OPEN"
			openCount++
		}
		output.WriteString(fmt.Sprintf("%-8d %-22s %s\n", r.Port, r.Service, status))
	}

	output.WriteString(strings.Repeat("─", 52) + "\n")
	output.WriteString(fmt.Sprintf("\n%d open, %d closed/filtered out of %d ports scanned\n", openCount, len(commonPorts)-openCount, len(commonPorts)))

	c.JSON(http.StatusOK, CheckResponse{
		Success:    true,
		Output:     output.String(),
		DurationMs: duration.Milliseconds(),
	})
}

func handleS3(c *gin.Context, req DBCheckRequest) {
	// For S3: Host = endpoint, Username = access key, Password = secret key, Database = bucket (optional)
	if req.Username == "" {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "access key is required"})
		return
	}
	if req.Password == "" {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "secret key is required"})
		return
	}

	region := req.Region
	if region == "" {
		region = "us-east-1"
	}

	// Build endpoint — for AWS, normalize to regional endpoint
	endpoint := req.Host + ":" + req.Port
	useSSL := true
	if req.Host == "s3.amazonaws.com" || strings.HasSuffix(req.Host, ".amazonaws.com") {
		endpoint = "s3." + region + ".amazonaws.com"
		if req.Host != "s3.amazonaws.com" {
			parts := strings.TrimSuffix(req.Host, ".amazonaws.com")
			parts = strings.TrimPrefix(parts, "s3.")
			if parts != "" && req.Region == "" {
				region = parts
				endpoint = "s3." + region + ".amazonaws.com"
			}
		}
	}

	start := time.Now()
	var output strings.Builder

	output.WriteString(fmt.Sprintf("Connecting to S3-compatible store at %s (region: %s)...\n", endpoint, region))

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(req.Username, req.Password, ""),
		Secure: useSSL,
		Region: region,
	})
	if err != nil {
		duration := time.Since(start)
		output.WriteString(fmt.Sprintf("Failed to create client: %s\n", err.Error()))
		c.JSON(http.StatusOK, CheckResponse{
			Success:    false,
			Output:     output.String(),
			Error:      err.Error(),
			DurationMs: duration.Milliseconds(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if req.Database != "" {
		// Check specific bucket
		output.WriteString(fmt.Sprintf("Checking bucket: %s\n", req.Database))
		exists, err := client.BucketExists(ctx, req.Database)
		if err != nil {
			duration := time.Since(start)
			output.WriteString(fmt.Sprintf("Bucket check FAILED: %s\n", err.Error()))
			c.JSON(http.StatusOK, CheckResponse{
				Success:    false,
				Output:     output.String(),
				Error:      err.Error(),
				DurationMs: duration.Milliseconds(),
			})
			return
		}
		if !exists {
			duration := time.Since(start)
			output.WriteString(fmt.Sprintf("Bucket '%s' does not exist\n", req.Database))
			c.JSON(http.StatusOK, CheckResponse{
				Success:    false,
				Output:     output.String(),
				Error:      "bucket not found",
				DurationMs: duration.Milliseconds(),
			})
			return
		}
		output.WriteString("Connection successful!\n\n")
		output.WriteString(fmt.Sprintf("Bucket '%s' is accessible\n", req.Database))
		output.WriteString("Objects found (showing up to 5):\n")
		count := 0
		for obj := range client.ListObjects(ctx, req.Database, minio.ListObjectsOptions{MaxKeys: 5}) {
			if obj.Err != nil {
				output.WriteString(fmt.Sprintf("  Error listing: %s\n", obj.Err.Error()))
				break
			}
			output.WriteString(fmt.Sprintf("  %s (%d bytes)\n", obj.Key, obj.Size))
			count++
		}
		if count == 0 {
			output.WriteString("  (empty bucket)\n")
		}
	} else {
		// List buckets
		buckets, err := client.ListBuckets(ctx)
		if err != nil {
			duration := time.Since(start)
			output.WriteString(fmt.Sprintf("Connection FAILED: %s\n", err.Error()))
			c.JSON(http.StatusOK, CheckResponse{
				Success:    false,
				Output:     output.String(),
				Error:      err.Error(),
				DurationMs: duration.Milliseconds(),
			})
			return
		}
		output.WriteString("Connection successful!\n\n")
		output.WriteString(fmt.Sprintf("Buckets found: %d\n", len(buckets)))
		for _, b := range buckets {
			output.WriteString(fmt.Sprintf("  %s (created %s)\n", b.Name, b.CreationDate.Format(time.RFC3339)))
		}
	}

	duration := time.Since(start)
	c.JSON(http.StatusOK, CheckResponse{
		Success:    true,
		Output:     output.String(),
		DurationMs: duration.Milliseconds(),
	})
}

func handleRedis(c *gin.Context, req DBCheckRequest) {
	start := time.Now()
	var output strings.Builder

	output.WriteString(fmt.Sprintf("Connecting to Redis at %s:%s...\n", req.Host, req.Port))

	db, _ := strconv.Atoi(req.Database)

	opts := &redis.Options{
		Addr:        req.Host + ":" + req.Port,
		Password:    req.Password,
		DB:          db,
		DialTimeout: 10 * time.Second,
	}
	if req.Username != "" {
		opts.Username = req.Username
	}

	rdb := redis.NewClient(opts)
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		duration := time.Since(start)
		output.WriteString(fmt.Sprintf("Connection FAILED: %s\n", err.Error()))
		c.JSON(http.StatusOK, CheckResponse{
			Success:    false,
			Output:     output.String(),
			Error:      err.Error(),
			DurationMs: duration.Milliseconds(),
		})
		return
	}

	output.WriteString("Connection successful! PING returned PONG.\n\n")

	info, err := rdb.Info(ctx, "server").Result()
	if err != nil {
		output.WriteString(fmt.Sprintf("Connected but could not retrieve server info: %s\n", err.Error()))
	} else {
		for _, line := range strings.Split(info, "\n") {
			if strings.HasPrefix(line, "redis_version:") ||
				strings.HasPrefix(line, "redis_mode:") ||
				strings.HasPrefix(line, "os:") ||
				strings.HasPrefix(line, "uptime_in_days:") {
				output.WriteString(strings.TrimSpace(line) + "\n")
			}
		}
	}

	dbSize, err := rdb.DBSize(ctx).Result()
	if err == nil {
		output.WriteString(fmt.Sprintf("DB %d key count: %d\n", db, dbSize))
	}

	duration := time.Since(start)
	c.JSON(http.StatusOK, CheckResponse{
		Success:    true,
		Output:     output.String(),
		DurationMs: duration.Milliseconds(),
	})
}

func handleTraceroute(c *gin.Context) {
	var req CheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: "invalid request body"})
		return
	}

	if err := validateHost(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, CheckResponse{Error: err.Error()})
		return
	}

	output, err, duration := runCommand(30*time.Second, "traceroute", req.Host)
	resp := CheckResponse{
		Output:     strings.TrimSpace(output),
		DurationMs: duration.Milliseconds(),
	}
	if err != nil {
		resp.Success = false
		resp.Error = err.Error()
	} else {
		resp.Success = true
	}

	c.JSON(http.StatusOK, resp)
}
