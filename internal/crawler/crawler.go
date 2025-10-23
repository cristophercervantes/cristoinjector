// internal/crawler/crawler.go

package crawler

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/fatih/color"
	"github.com/gocolly/colly/v2"
)

// CrawlURLs crawls a root URL to find URLs with query parameters.
func CrawlURLs(rootURL string, c *colly.Collector) ([]string, error) {
	var urls []string

	// Validate root URL
	if _, err := url.ParseRequestURI(rootURL); err != nil {
		return nil, fmt.Errorf("invalid root URL: %v", err)
	}

	// Set up collector
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		// Resolve relative URLs
		absURL, err := e.Request.AbsoluteURL(link)
		if err != nil {
			return
		}
		// Check for query parameters
		if strings.Contains(absURL, "?") {
			urls = append(urls, absURL)
		}
	})

	c.OnError(func(r *colly.Response, err error) {
		fmt.Fprintf(color.Output, "%sError crawling %s: %v\n", color.RedString("[-] "), r.Request.URL, err)
	})

	// Start crawling
	err := c.Visit(rootURL)
	if err != nil {
		return nil, fmt.Errorf("failed to start crawling: %v", err)
	}

	c.Wait()

	// Deduplicate URLs
	urlMap := make(map[string]struct{})
	for _, u := range urls {
		urlMap[u] = struct{}{}
	}
	var uniqueURLs []string
	for u := range urlMap {
		uniqueURLs = append(uniqueURLs, u)
	}

	if len(uniqueURLs) == 0 {
		return nil, fmt.Errorf("no URLs with query parameters found")
	}

	return uniqueURLs, nil
}
