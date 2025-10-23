// cmd/cristoinjector/main.go

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/gocolly/colly/v2"
	"github.com/gocolly/colly/v2/extensions"

	"cristoinjector/internal/crawler"
	"cristoinjector/internal/detector"
	"cristoinjector/internal/utils"
)

const (
	version = "v0.2.0"
	banner  = `
   _____   _____   _____   _____   _____   _____   _____
  /     \ /     \ /     \ /     \ /     \ /     \ /     \
 /_______\/_______\/_______\/_______\/_______\/_______\/_______\
 |  cristoinjector - Automated SQL Injection Testing Tool     |
 |  Version: %s                                              |
 |  Author: Cristopher                                        |
 |  Use responsibly and only with explicit permission!        |
 |___________________________________________________________|
`
)

func main() {
	// Define command-line flags
	url := flag.String("u", "", "Single URL to scan (use * as payload placeholder)")
	list := flag.String("list", "", "File containing a list of URLs")
	timePayload := flag.String("time-payload", "", "File with time-based payloads")
	errorPayload := flag.String("error-payload", "", "File with error-based payloads")
	unionPayload := flag.String("union-payload", "", "File with union-based payloads")
	mode := flag.String("mode", "time", "Detection mode: time, error, union, all")
	concurrency := flag.Int("concurrency", 20, "Maximum concurrent payload scans")
	mrt := flag.Int("mrt", 10, "Response time threshold in seconds for time-based detection")
	verify := flag.Int("verify", 3, "Number of verification attempts")
	verifyDelay := flag.Int("verifydelay", 12000, "Delay between verification attempts (ms)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	// Print version and exit if requested
	if *showVersion {
		fmt.Printf("cristoinjector %s\n", version)
		os.Exit(0)
	}

	// Print banner
	fmt.Printf(banner, version)

	// Validate flags
	if *url == "" && *list == "" {
		fmt.Fprintln(os.Stderr, color.RedString("Error: -u or -list is required"))
		flag.Usage()
		os.Exit(1)
	}
	if *mode != "time" && *mode != "error" && *mode != "union" && *mode != "all" {
		fmt.Fprintln(os.Stderr, color.RedString("Error: -mode must be 'time', 'error', 'union', or 'all'"))
		os.Exit(1)
	}
	if *mode == "all" || *mode == "time" {
		if *timePayload == "" {
			fmt.Fprintln(os.Stderr, color.RedString("Error: -time-payload is required for mode '%s'", *mode))
			os.Exit(1)
		}
	}
	if *mode == "all" || *mode == "error" {
		if *errorPayload == "" {
			fmt.Fprintln(os.Stderr, color.RedString("Error: -error-payload is required for mode '%s'", *mode))
			os.Exit(1)
		}
	}
	if *mode == "all" || *mode == "union" {
		if *unionPayload == "" {
			fmt.Fprintln(os.Stderr, color.RedString("Error: -union-payload is required for mode '%s'", *mode))
			os.Exit(1)
		}
	}

	// Initialize payloads
	var timePayloads, errorPayloads, unionPayloads []string
	var err error
	if *timePayload != "" {
		timePayloads, err = utils.ReadPayloadFile(*timePayload)
		if err != nil {
			fmt.Fprintln(os.Stderr, color.RedString("Error reading time payloads: %v", err))
			os.Exit(1)
		}
	}
	if *errorPayload != "" {
		errorPayloads, err = utils.ReadPayloadFile(*errorPayload)
		if err != nil {
			fmt.Fprintln(os.Stderr, color.RedString("Error reading error payloads: %v", err))
			os.Exit(1)
		}
	}
	if *unionPayload != "" {
		unionPayloads, err = utils.ReadPayloadFile(*unionPayload)
		if err != nil {
			fmt.Fprintln(os.Stderr, color.RedString("Error reading union payloads: %v", err))
			os.Exit(1)
		}
	}

	// Initialize URLs
	var urls []string
	if *url != "" {
		if strings.Contains(*url, "*") {
			urls = append(urls, *url)
		} else {
			// Auto-discover URLs with query parameters
			fmt.Println(color.YellowString("Crawling for URLs with query parameters..."))
			c := colly.NewCollector(
				colly.UserAgent("cristoinjector/" + version),
			)
			extensions.RandomUserAgent(c)
			urls, err = crawler.CrawlURLs(*url, c)
			if err != nil {
				fmt.Fprintln(os.Stderr, color.RedString("Error crawling URLs: %v", err))
				os.Exit(1)
			}
		}
	} else if *list != "" {
		urls, err = utils.ReadURLFile(*list)
		if err != nil {
			fmt.Fprintln(os.Stderr, color.RedString("Error reading URL list: %v", err))
			os.Exit(1)
		}
	}

	// Initialize detector
	d := detector.NewDetector(*concurrency, time.Duration(*mrt)*time.Second, *verify, time.Duration(*verifyDelay)*time.Millisecond)

	// Run detection
	for _, u := range urls {
		fmt.Println(color.CyanString("Scanning URL: %s", u))
		if *mode == "all" || *mode == "time" {
			d.TestTimeBased(u, timePayloads)
		}
		if *mode == "all" || *mode == "error" {
			d.TestErrorBased(u, errorPayloads)
		}
		if *mode == "all" || *mode == "union" {
			d.TestUnionBased(u, unionPayloads)
		}
	}

	fmt.Println(color.GreenString("Scan completed."))
}
