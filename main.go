// ======================================================
// AxxCommunity Protection
// Credit to ChatGPT
// Build by Axxet
//
// ======================================================

package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dchest/captcha"
)

// ======================================================
// Konfigurasi Umum
// ======================================================
const (
	blacklistTimeout               = 100 * 10 * time.Second // Timeout blacklist (detik)
	maxRequests                    = 50                     // Maksimal request per IP (rate limiter)
	rateLimitTimeout               = 5 * time.Minute        // Interval reset counter rate limiter
	maxConcurrentConnections       = 10                     // Maksimum koneksi paralel per IP
	maxRequestBodyBytes      int64 = 1 * 1024 * 1024        // Batas ukuran request body (1 MB)
	floodThreshold                 = 20                     // Maksimum request per detik (untuk flood detection)
)

// ======================================================
// TLS & Logging
// ======================================================
func getTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair("./ssl/server.crt", "./ssl/server.key")
	if err != nil {
		return nil, fmt.Errorf("failed to load Certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}

func logWithTime(level, message string) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("[%s | %s]: %s\n", currentTime, level, message)
}

// ======================================================
// IP Blacklist & Rate Limiting
// ======================================================
var (
	blacklist   = make(map[string]int64)
	muBlacklist sync.Mutex

	requestCount = make(map[string]int)
	mu           sync.Mutex
)

func addAddressToBlacklist(address string) {
	muBlacklist.Lock()
	defer muBlacklist.Unlock()
	blacklist[address] = time.Now().Unix() + int64(blacklistTimeout.Seconds())
}

// ======================================================
// Flood Detection Middleware (per detik)
// ======================================================
var (
	floodRequestCount = make(map[string]int)
	floodMu           sync.Mutex
)

func floodDetectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		floodMu.Lock()
		floodRequestCount[ip]++
		count := floodRequestCount[ip]
		floodMu.Unlock()
		if count > floodThreshold {
			logWithTime("WARNING", fmt.Sprintf("Flood detected from IP: %s (requests: %d)", ip, count))
			addAddressToBlacklist(ip)
			http.Error(w, "Flood detected", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func resetFloodCounters() {
	for {
		time.Sleep(1 * time.Second)
		floodMu.Lock()
		floodRequestCount = make(map[string]int)
		floodMu.Unlock()
	}
}

// ======================================================
// Captcha System
// ======================================================
var (
	captchaVerifiedUsers = make(map[string]bool)
	muCaptcha            sync.Mutex
)

func generateCaptcha() (string, string) {
	id := captcha.New()
	return id, "/captcha/" + id + ".png"
}

func verifyCaptcha(id, userInput string) bool {
	return captcha.VerifyString(id, userInput)
}

func serveCaptcha(w http.ResponseWriter, r *http.Request) {
	captcha.Server(captcha.StdWidth, captcha.StdHeight).ServeHTTP(w, r)
}

func serveCaptchaForm(w http.ResponseWriter, captchaURL, captchaID string) {
	filePath := "./www/captcha.html"
	content, err := os.ReadFile(filePath)
	if err != nil {
		http.Error(w, "Error loading captcha form", http.StatusInternalServerError)
		return
	}
	htmlContent := strings.ReplaceAll(string(content), "{{CAPTCHA_URL}}", captchaURL)
	htmlContent = strings.ReplaceAll(htmlContent, "{{CAPTCHA_ID}}", captchaID)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(htmlContent))
}

// ======================================================
// Cache Functionality: Static File Handler
// ======================================================
func handleCacheRequests(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "AxxCommunity")
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		http.ServeFile(w, r, "./www/err/405.html")
		return
	}
	path := "." + r.URL.Path
	logWithTime("INFO", fmt.Sprintf("Cache downloading file: %s from IP: %s", r.URL.Path, r.RemoteAddr))
	stat, err := os.Stat(path)
	if err == nil {
		if !stat.IsDir() {
			data, err := ioutil.ReadFile(path)
			if err != nil {
				http.Error(w, "File Not Found", http.StatusNotFound)
				http.ServeFile(w, r, "./www/err/404.html")
			} else {
				w.Header().Set("Content-Type", "text/plain")
				w.Write(data)
			}
		} else {
			indexPath := path + "/index.html"
			if _, err := os.Stat(indexPath); err == nil {
				http.ServeFile(w, r, indexPath)
				return
			}
		}
	} else if os.IsNotExist(err) {
		logWithTime("INFO", fmt.Sprintf("File not found: %s, attempting download...", r.URL.Path))
		remoteURL := fmt.Sprintf("https://ubistatic-a.akamaihd.net/0098/0251220240%s", r.URL.Path)
		resp, err := http.Get(remoteURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			logWithTime("ERROR", fmt.Sprintf("Failed to download file: %s, Status: %d", remoteURL, resp.StatusCode))
			http.Error(w, "File Not Found", http.StatusNotFound)
			http.ServeFile(w, r, "./www/err/404.html")
			return
		}
		defer resp.Body.Close()
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logWithTime("ERROR", fmt.Sprintf("Failed to read content from URL: %s", remoteURL))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			http.ServeFile(w, r, "./www/err/500.html")
			return
		}
		go func() {
			cacheDir := "./cache" + r.URL.Path[:strings.LastIndex(r.URL.Path, "/")]
			if err := os.MkdirAll(cacheDir, 0755); err == nil {
				if err := ioutil.WriteFile(path, data, 0644); err != nil {
					logWithTime("ERROR", fmt.Sprintf("Failed to save file cache: %s", path))
				} else {
					logWithTime("INFO", fmt.Sprintf("File cached: %s", path))
				}
			}
		}()
		w.Header().Set("Content-Type", "text/plain")
		w.Write(data)
	} else {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		http.ServeFile(w, r, "./www/err/500.html")
	}
}

// ======================================================
// Middleware: Connection Limiter (Concurrent Connections)
// ======================================================
var (
	activeConnections   = make(map[string]int)
	muActiveConnections sync.Mutex
)

func connectionLimiter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		muActiveConnections.Lock()
		activeConnections[ip]++
		if activeConnections[ip] > maxConcurrentConnections {
			muActiveConnections.Unlock()
			http.Error(w, "Too many concurrent connections", http.StatusTooManyRequests)
			return
		}
		muActiveConnections.Unlock()
		defer func() {
			muActiveConnections.Lock()
			activeConnections[ip]--
			muActiveConnections.Unlock()
		}()
		next.ServeHTTP(w, r)
	})
}

// ======================================================
// Middleware: Request Body Size Limiter
// ======================================================
func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// ======================================================
// Middleware: Block HTTP Methods Tertentu
// ======================================================
func blockHTTPMethodsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		disallowedMethods := []string{
			"HEAD", "TCP", "DATAGRAM", "STREAM", "UDP", "DGRAM",
			"PURGE", "PUT", "OPTIONS", "PATCH", "DELETE", "OVH",
			"SPDY", "RST_STREAM", "ICMP", "SLOWLORIS", "SYN",
			"ACK", "SNMP", "NTP",
		}
		for _, method := range disallowedMethods {
			if r.Method == method {
				http.Error(w, "HTTP method not allowed", http.StatusMethodNotAllowed)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ======================================================
// Middleware: Block User-Agent Tertentu
// ======================================================
func blockUserAgentMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		blockedUserAgents := []string{
			"badagent", "evilcrawler", "maliciousbot",
		}
		ua := strings.ToLower(r.Header.Get("User-Agent"))
		for _, blocked := range blockedUserAgents {
			if strings.Contains(ua, strings.ToLower(blocked)) {
				http.Error(w, "User-Agent blocked", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ======================================================
// Middleware: Block Permintaan dari Proxy
// ======================================================
func blockProxyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-IP") != "" {
			http.Error(w, "Proxy requests blocked", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ======================================================
// Middleware: Secure Headers
// ======================================================
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

// ======================================================
// Middleware: Rate Limiter & Anti‑DDoS
// ======================================================
func rateLimiterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		muBlacklist.Lock()
		blockTime, found := blacklist[ip]
		muBlacklist.Unlock()
		if found && time.Now().Unix() < blockTime {
			http.Error(w, "Your IP has been blocked", http.StatusForbidden)
			return
		} else if found && time.Now().Unix() >= blockTime {
			muBlacklist.Lock()
			delete(blacklist, ip)
			muBlacklist.Unlock()
		}
		mu.Lock()
		count, exists := requestCount[ip]
		if exists && count > maxRequests {
			mu.Unlock()
			addAddressToBlacklist(ip)
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		if !exists {
			requestCount[ip] = 0
		}
		requestCount[ip]++
		mu.Unlock()
		go func(ip string) {
			time.Sleep(rateLimitTimeout)
			mu.Lock()
			requestCount[ip] = 0
			mu.Unlock()
		}(ip)
		next.ServeHTTP(w, r)
	})
}

// ======================================================
// Variabel Global untuk Penyimpanan Data Pengguna
// ======================================================
var (
	users   = make(map[string]string)
	muUsers sync.Mutex
)

// ======================================================
// API Internal Endpoints
// ======================================================

// Endpoint: /player/login/dashboard
func loginDashboardHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	// Asumsikan data dikirim dalam satu field "data" dengan format "key|value\n..."
	dataStr := r.FormValue("data")
	tData := make(map[string]string)
	if dataStr != "" {
		lines := strings.Split(dataStr, "\n")
		var uName, uPass string
		for _, line := range lines {
			parts := strings.Split(line, "|")
			if len(parts) >= 2 {
				key := parts[0]
				value := parts[1]
				tData[key] = value
				if key == "username" {
					uName = value
				}
				if key == "password" {
					uPass = value
				}
			}
		}
		// Jika username dan password ditemukan, redirect dengan menambahkan parameter query
		if uName != "" && uPass != "" {
			redirectURL := fmt.Sprintf("/player/growid/login/validate?growId=%s&password=%s&_token=%s",
				url.QueryEscape(uName), url.QueryEscape(uPass), url.QueryEscape("dummyToken"))
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}
	}
	// Render template dashboard (gunakan file dashboard.ejs di folder ./www)
	tmpl, err := template.ParseFiles(filepath.Join("www", "dashboard.ejs"))
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, tData)
}

// Endpoint: /player/growid/login/validate
func loginValidateHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	_token := r.FormValue("_token")
	growId := r.FormValue("growId")
	password := r.FormValue("password")

	// Validasi user: cek apakah username terdaftar dan password sesuai
	muUsers.Lock()
	storedPassword, exists := users[growId]
	muUsers.Unlock()
	if !exists || storedPassword != password {
		resp := map[string]string{
			"status":  "error",
			"message": "Invalid username or password.",
		}
		jsonResp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(jsonResp)
		return
	}

	token := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("_token=%s&growId=%s&password=%s", _token, growId, password)))
	resp := map[string]string{
		"status":      "success",
		"message":     "Account Validated.",
		"token":       token,
		"url":         "",
		"accountType": "growtopia",
	}
	jsonResp, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
}

// Endpoint: /player/growid/register (untuk registrasi akun)
func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Jika method GET, render form register (misalnya file register.ejs)
	if r.Method == http.MethodGet {
		tmpl, err := template.ParseFiles(filepath.Join("www", "register.ejs"))
		if err != nil {
			http.Error(w, "Template error", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	// Untuk POST, proses registrasi akun
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	username := r.FormValue("growId")
	password := r.FormValue("password")
	if username == "" || password == "" {
		resp := map[string]string{
			"status":  "error",
			"message": "Username and password required.",
		}
		jsonResp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(jsonResp)
		return
	}
	muUsers.Lock()
	defer muUsers.Unlock()
	if _, exists := users[username]; exists {
		resp := map[string]string{
			"status":  "error",
			"message": "Username already exists.",
		}
		jsonResp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		w.Write(jsonResp)
		return
	}
	users[username] = password
	resp := map[string]string{
		"status":  "success",
		"message": "Registration successful.",
	}
	jsonResp, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
}

// ======================================================
// Router untuk Endpoint /player/*
// ======================================================
func playerRouterHandler(w http.ResponseWriter, r *http.Request) {
	pathSuffix := strings.TrimPrefix(r.URL.Path, "/player/")
	switch {
	case strings.HasPrefix(pathSuffix, "info"):
		playerId := r.URL.Query().Get("playerId")
		if playerId == "" {
			playerId = "unknown"
		}
		resp := map[string]interface{}{
			"status":  "success",
			"message": "Player info retrieved successfully.",
			"data": map[string]interface{}{
				"playerId":   playerId,
				"username":   "Player_" + playerId,
				"level":      42,
				"experience": 123456,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		jsonResp, _ := json.Marshal(resp)
		w.Write(jsonResp)
	case strings.HasPrefix(pathSuffix, "update"):
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}
		playerId := r.FormValue("playerId")
		resp := map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Player %s updated successfully.", playerId),
			"data":    r.Form,
		}
		w.Header().Set("Content-Type", "application/json")
		jsonResp, _ := json.Marshal(resp)
		w.Write(jsonResp)
	case strings.HasPrefix(pathSuffix, "delete"):
		playerId := r.URL.Query().Get("playerId")
		if playerId == "" {
			playerId = "unknown"
		}
		resp := map[string]interface{}{
			"status":  "success",
			"message": fmt.Sprintf("Player %s deleted successfully.", playerId),
		}
		w.Header().Set("Content-Type", "application/json")
		jsonResp, _ := json.Marshal(resp)
		w.Write(jsonResp)
	default:
		w.WriteHeader(http.StatusNotFound)
		resp := map[string]string{
			"status":  "error",
			"message": "Endpoint not found under /player.",
		}
		jsonResp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonResp)
	}
}

// ======================================================
// Fungsi untuk Mencetak Banner ASCII dengan Efek Gradien
// ======================================================
func printBanner() {
	bannerLines := []struct {
		text  string
		color string
	}{
		{`   ___         _        ___ ___  _   _  ___  ___ ___  ___  `, "\033[38;2;255;0;0m"},
		{`  / _ \ _   _ | | _____/ __/ _ \| | | |/ _ \/ __/ __|/ _ \ `, "\033[38;2;255;100;0m"},
		{` | | | | | | || |/ / _ \ (_| (_) | |_| |  __/\__ \__ \  __/ `, "\033[38;2;255;200;0m"},
		{` | |_| | |_| ||   <  __/\___\___/ \__,_|\___||___/___/\___| `, "\033[38;2;0;255;0m"},
		{`  \__\_\\__,_||_|\_\                                        `, "\033[38;2;0;100;255m"},
	}
	reset := "\033[0m"
	for _, line := range bannerLines {
		fmt.Println(line.color + line.text + reset)
	}
	fmt.Println()
}

// ======================================================
// Server Data Handler (Contoh Endpoint Khusus)
// ======================================================
func serverDataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "AxxCommunity")
	logWithTime("INFO", fmt.Sprintf("Accessed server_data.php from IP: %s", r.RemoteAddr))
	allowedUserAgentPrefix := "UbiServices_SDK"
	if !strings.HasPrefix(r.UserAgent(), allowedUserAgentPrefix) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		http.ServeFile(w, r, "./www/err/403.html")
		return
	}
	filePath := "./www/growtopia/server_data.php"
	if r.Method == "POST" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			http.ServeFile(w, r, "./www/err/500.html")
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(data)
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		http.ServeFile(w, r, "./www/err/405.html")
	}
}

// ======================================================
// Main Handler: Captcha & Static File Serving
// ======================================================
func mainHandler(w http.ResponseWriter, r *http.Request) {
	ip := r.RemoteAddr
	muCaptcha.Lock()
	verified := captchaVerifiedUsers[ip]
	muCaptcha.Unlock()
	if !verified {
		captchaID := r.URL.Query().Get("captcha_id")
		userInput := r.URL.Query().Get("captcha")
		if captchaID != "" && userInput != "" {
			if verifyCaptcha(captchaID, userInput) {
				muCaptcha.Lock()
				captchaVerifiedUsers[ip] = true
				muCaptcha.Unlock()
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				return
			}
			http.Error(w, "Captcha verification failed", http.StatusForbidden)
			http.ServeFile(w, r, "./www/err/400.html")
			return
		}
		newCaptchaID, captchaURL := generateCaptcha()
		w.Header().Set("Content-Type", "text/html")
		serveCaptchaForm(w, captchaURL, newCaptchaID)
		return
	}
	path := "./www" + r.URL.Path
	w.Header().Set("Server", "AxxCommunity")
	if stat, err := os.Stat(path); err == nil {
		if !stat.IsDir() {
			http.ServeFile(w, r, path)
			return
		}
		indexPath := path + "/index.html"
		if _, err := os.Stat(indexPath); err == nil {
			http.ServeFile(w, r, indexPath)
			return
		}
	}
	http.Error(w, "Not Found", http.StatusNotFound)
	http.ServeFile(w, r, "./www/err/404.html")
}

// ======================================================
// Main Function: Setup Server & Middleware Chain
// ======================================================
func main() {
	tlsConfig, err := getTLSConfig()
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}

	// Mulai goroutine reset flood counter
	go resetFloodCounters()

	// Cetak banner ASCII dengan efek gradien
	printBanner()

	// Buat multiplexer utama
	mux := http.NewServeMux()
	// Route Captcha (gambar)
	mux.HandleFunc("/captcha/", serveCaptcha)
	// Endpoint khusus untuk file cache
	mux.HandleFunc("/cache/", handleCacheRequests)

	// Endpoint khusus (misal: server_data.php)
	mux.Handle("/growtopia/server_data.php", http.HandlerFunc(serverDataHandler))

	// Endpoint khusus untuk validasi login
	mux.HandleFunc("/player/growid/login/validate", loginValidateHandler)
	// Endpoint untuk registrasi akun
	mux.HandleFunc("/player/growid/register", registerHandler)
	// Endpoint untuk login dashboard
	mux.HandleFunc("/player/login/dashboard", loginDashboardHandler)
	// Router untuk API internal di bawah /player/*
	mux.HandleFunc("/player/", playerRouterHandler)
	// Root route
	mux.HandleFunc("/", mainHandler)

	// Rangkaian middleware anti-DDoS dan keamanan:
	finalHandler := secureHeaders(
		limitRequestBody(
			connectionLimiter(
				floodDetectionMiddleware(
					blockHTTPMethodsMiddleware(
						blockUserAgentMiddleware(
							blockProxyMiddleware(
								rateLimiterMiddleware(mux),
							),
						),
					),
				),
			),
		),
	)

	// Konfigurasi server dengan timeout dan TLS
	server := &http.Server{
		Addr:           ":443",
		Handler:        finalHandler,
		TLSConfig:      tlsConfig,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Tangani sinyal untuk shutdown bersih (SIGINT dan SIGTERM)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigs {
			logWithTime("INFO", fmt.Sprintf("Received signal: %s", sig))
		}
	}()

	// Nonaktifkan logging error bawaan (opsional)
	server.ErrorLog = log.New(ioutil.Discard, "", 0)

	logWithTime("INFO", "AxxCommunity server berjalan di https://localhost:443")
	err = server.ListenAndServeTLS("./ssl/server.crt", "./ssl/server.key")
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
