// internal/detector/detector.go

package detector

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Detector holds configuration for SQL injection testing.
type Detector struct {
	concurrency int
	mrt         time.Duration
	verify      int
	verifyDelay time.Duration
	client      *http.Client
}

// NewDetector creates a new Detector instance.
func NewDetector(concurrency int, mrt time.Duration, verify int, verifyDelay time.Duration) *Detector {
	return &Detector{
		concurrency: concurrency,
		mrt:         mrt,
		verify:      verify,
		verifyDelay: verifyDelay,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// TestTimeBased tests for time-based SQL injection vulnerabilities.
func (d *Detector) TestTimeBased(url string, payloads []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, d.concurrency)

	for _, payload := range payloads {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore

			for i := 0; i < d.verify; i++ {
				start := time.Now()
				resp, err := d.client.Get(strings.Replace(url, "*", p, 1))
				duration := time.Since(start)
				if err != nil {
					fmt.Fprintf(color.Output, "%sError testing %s with payload %s: %v\n", color.RedString("[-] "), url, p, err)
					return
				}
				resp.Body.Close()
				if duration >= d.mrt {
					fmt.Fprintf(color.Output, "%sVulnerable (time-based): %s with payload %s (delay: %v)\n", color.GreenString("[+] "), url, p, duration)
					return
				}
				time.Sleep(d.verifyDelay)
			}
		}(payload)
	}
	wg.Wait()
}

// TestErrorBased tests for error-based SQL injection vulnerabilities.
func (d *Detector) TestErrorBased(url string, payloads []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, d.concurrency)

	for _, payload := range payloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			for i := 0; i < d.verify; i++ {
				resp, err := d.client.Get(strings.Replace(url, "*", p, 1))
				if err != nil {
					fmt.Fprintf(color.Output, "%sError testing %s with payload %s: %v\n", color.RedString("[-] "), url, p, err)
					return
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					fmt.Fprintf(color.Output, "%sError reading response for %s: %v\n", color.RedString("[-] "), url, err)
					return
				}
				if strings.Contains(string(body), "SQL syntax") || strings.Contains(string(body), "mysql_fetch") {
					fmt.Fprintf(color.Output, "%sVulnerable (error-based): %s with payload %s\n", color.GreenString("[+] "), url, p)
					return
				}
				time.Sleep(d.verifyDelay)
			}
		}(payload)
	}
	wg.Wait()
}

// TestUnionBased tests for union-based SQL injection vulnerabilities.
func (d *Detector) TestUnionBased(url string, payloads []string) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, d.concurrency)

	for _, payload := range payloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			for i := 0; i < d.verify; i++ {
				resp, err := d.client.Get(strings.Replace(url, "*", p, 1))
				if err != nil {
					fmt.Fprintf(color.Output, "%sError testing %s with payload %s: %v\n", color.RedString("[-] "), url, p, err)
					return
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					fmt.Fprintf(color.Output, "%sError reading response for %s: %v\n", color.RedString("[-] "), url, err)
					return
				}
				// Simple check for union-based injection (e.g., presence of injected values)
				if strings.Contains(string(body), "1,2,3") || strings.Contains(string(body), "NULL") {
					fmt.Fprintf(color.Output, "%sVulnerable (union-based): %s with payload %s\n", color.GreenString("[+] "), url, p)
					return
				}
				time.Sleep(d.verifyDelay)
			}
		}(payload)
	}
	wg.Wait()
}
