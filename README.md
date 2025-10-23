# cristoinjector

A fast Go-based tool for detecting SQL injection vulnerabilities (time-based, error-based, union-based).

## Features
- Scans single URLs or lists with custom payloads.
- Auto-discovers URLs with query parameters for root URLs.
- Supports time-based, error-based, and union-based SQLi detection.
- Concurrent scanning with configurable options.
- Created by Cristopher.

## Installation

### Prerequisites
- Go 1.18 or later
- Git

### Install via `go install`
```bash
go install github.com/cristophercervantes/cristoinjector/cmd/cristoinjector@latest
