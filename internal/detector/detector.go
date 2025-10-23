package detector

import (
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cristophercervantes/cristoinjector/internal/crawler"
	"github.com/fatih/color"
)

var errorPatterns = []string{
	"SQL syntax", "mysql_fetch", "You have an error in your SQL", "ORA-", "PG::SyntaxError",
	"Microsoft OLE DB Provider", "Unclosed quotation mark", "SQLite", "DB2 SQL error",
	"Warning: mysql_", "Syntax error in query", "Invalid SQL statement",
}

// ScanTarget scans a single URL for SQLi vulnerabilities
func ScanTarget(target string, payloads map[string][]string, mode string, concurrency, threshold, verify, verifyDelay int) {
	parsed, err := url.Parse(target)
	if err != nil {
		color.Red("Invalid URL: %s", target)
		return
	}

	candidateURLs := []string{}
	if strings.Contains(target, "*") || len(parsed.Query()) > 0 {
		candidateURLs = append(candidateURLs, target)
	} else {
		candidateURLs = crawler.FindVulnerableURLs(target)
	}

	for _, cand := range candidateURLs {
		modesToRun := []string{}
		switch mode {
		case "time":
			modesToRun = []string{"time"}
		case "error":
			modesToRun = []string{"error"}
		case "union":
			modesToRun = []string{"union"}
		case "all":
			modesToRun = []string{"time", "error", "union"}
		}

		for _, m := range modesToRun {
			if pl, ok := payloads[m]; ok {
				testURLWithPayloads(cand, pl, m, concurrency, threshold, verify, verifyDelay)
			}
		}
	}
}

func testURLWithPayloads(baseURL string, payloads []string, mode string, concurrency, threshold, verify, verifyDelay int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	// For union mode, get baseline response
	baselineBody, baselineLen := "", 0
	if mode == "union" {
		cleanURL := strings.Replace(baseURL, "*", "", -1)
		resp, err := http.Get(cleanURL)
		if err == nil && resp.Body != nil {
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			baselineBody = string(body)
			baselineLen = len(baselineBody)
		}
	}

	for _, payload := range payloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			testURL := strings.Replace(baseURL, "*", p, -1)
			if isVulnerable(testURL, mode, baselineBody, baselineLen, threshold, verify, verifyDelay) {
				color.Green("%s SQLI DETECTED: %s with payload '%s'", strings.ToUpper(mode), testURL, p)
			}
		}(payload)
	}
	wg.Wait()
}

func isVulnerable(testURL, mode, baselineBody string, baselineLen, threshold, verify, verifyDelay int) bool {
	for i := 0; i < verify; i++ {
		start := time.Now()
		resp, err := http.Get(testURL)
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)
		bodyStr := string(body)
		duration := time.Since(start).Seconds()

		vuln := false
		switch mode {
		case "time":
			if duration >= float64(threshold) {
				vuln = true
			}
		case "error":
			for _, pattern := range errorPatterns {
				if strings.Contains(bodyStr, pattern) {
					vuln = true
					break
				}
			}
		case "union":
			if len(bodyStr) > baselineLen+50 || (strings.Contains(bodyStr, "1") && strings.Contains(bodyStr, "2") && strings.Contains(bodyStr, "3") && !strings.Contains(baselineBody, "1") && !strings.Contains(baselineBody, "2") && !strings.Contains(baselineBody, "3")) {
				vuln = true
			}
		}

		if !vuln {
			return false
		}

		time.Sleep(time.Duration(verifyDelay) * time.Millisecond)
	}
	return true
}
