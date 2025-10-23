// internal/utils/utils.go

package utils

import (
	"bufio"
	"os"
	"strings"
)

// ReadPayloadFile reads a payload file and returns a slice of payloads.
func ReadPayloadFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			payloads = append(payloads, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(payloads) == 0 {
		return nil, os.ErrNotExist
	}
	return payloads, nil
}

// ReadURLFile reads a URL list file and returns a slice of URLs.
func ReadURLFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(urls) == 0 {
		return nil, os.ErrNotExist
	}
	return urls, nil
}
