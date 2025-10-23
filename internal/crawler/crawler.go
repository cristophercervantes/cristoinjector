package crawler

import (
	"net/url"
	"github.com/gocolly/colly"
)

// FindVulnerableURLs crawls a root URL to find URLs with query parameters
func FindVulnerableURLs(root string) []string {
	candidates := []string{}
	visited := make(map[string]bool)
	c := colly.NewCollector(
		colly.AllowedDomains(rootHost(root)),
		colly.MaxDepth(2),
	)

	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		parsed, err := url.Parse(link)
		if err == nil && len(parsed.Query()) > 0 && !visited[link] {
			visited[link] = true
			candidates = append(candidates, link+"*") // Append * for payload placeholder
		}
	})

	c.Visit(root)
	return candidates
}

func rootHost(root string) string {
	parsed, _ := url.Parse(root)
	return parsed.Host
}
