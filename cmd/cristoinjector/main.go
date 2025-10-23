package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cristophercervantes/cristoinjector/internal/detector"
	"github.com/cristophercervantes/cristoinjector/internal/utils"
	"github.com/fatih/color"
)

const (
	version           = "0.2.0"
	defaultConcurrency = 20
	defaultThreshold   = 10 // seconds
	defaultVerify      = 3
	defaultVerifyDelay = 12000 // ms
)

var (
	u              = flag.String("u", "", "Single URL to scan (use * for payload placeholder)")
	list           = flag.String("list", "", "File containing list of URLs")
	timePayload    = flag.String("time-payload", "", "File containing time-based payloads")
	errorPayload   = flag.String("error-payload", "", "File containing error-based payloads")
	unionPayload   = flag.String("union-payload", "", "File containing union-based payloads")
	mode           = flag.String("mode", "time", "Detection mode: time, error, union, all")
	concurrency    = flag.Int("concurrency", defaultConcurrency, "Maximum concurrent payload scans")
	threshold      = flag.Int("mrt", defaultThreshold, "Response time threshold in seconds (for time mode)")
	verify         = flag.Int("verify", defaultVerify, "Number of verification attempts")
	verifyDelay    = flag.Int("verifydelay", defaultVerifyDelay, "Delay in ms between verifications")
	showVersion    = flag.Bool("version", false, "Print version and exit")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("cristoinjector v%s\n", version)
		os.Exit(0)
	}

	// Banner
	color.Cyan(`
   _____ _     _     _     _     _     _    
  / ____| |   (_)   | |   | |   | |   | |   
 | |    | |__  _ ___| |__ | |__ | |__ | | __
 | |    | '_ \| / __| '_ \| '_ \| '_ \| |/ /
 | |____| | | | \__ \ | | | | | | | | |   < 
  \_____|_| |_|_|___/_| |_|_| |_|_| |_|_|\_\
                                            
Creator: Cristopher
`)

	if *mode == "time" && *timePayload == "" ||
		*mode == "error" && *errorPayload == "" ||
		*mode == "union" && *unionPayload == "" ||
		*mode == "all" && (*timePayload == "" && *errorPayload == "" && *unionPayload == "") {
		fmt.Println("Error: Provide appropriate payload file(s) for the selected mode")
		os.Exit(1)
	}

	payloads := make(map[string][]string)
	if *mode == "time" || *mode == "all" {
		if *timePayload != "" {
			if pl, err := utils.LoadLines(*timePayload); err == nil {
				payloads["time"] = pl
			} else {
				fmt.Printf("Error loading time payloads: %v\n", err)
				os.Exit(1)
			}
		}
	}
	if *mode == "error" || *mode == "all" {
		if *errorPayload != "" {
			if pl, err := utils.LoadLines(*errorPayload); err == nil {
				payloads["error"] = pl
			} else {
				fmt.Printf("Error loading error payloads: %v\n", err)
				os.Exit(1)
			}
		}
	}
	if *mode == "union" || *mode == "all" {
		if *unionPayload != "" {
			if pl, err := utils.LoadLines(*unionPayload); err == nil {
				payloads["union"] = pl
			} else {
				fmt.Printf("Error loading union payloads: %v\n", err)
				os.Exit(1)
			}
		}
	}

	urls := []string{}
	if *u != "" {
		urls = append(urls, *u)
	} else if *list != "" {
		urlList, err := utils.LoadLines(*list)
		if err != nil {
			fmt.Printf("Error loading URL list: %v\n", err)
			os.Exit(1)
		}
		urls = urlList
	} else {
		fmt.Println("Error: Provide -u or -list")
		os.Exit(1)
	}

	for _, target := range urls {
		detector.ScanTarget(target, payloads, *mode, *concurrency, *threshold, *verify, *verifyDelay)
	}
}
