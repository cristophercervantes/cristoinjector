# cristoinjector

A fast, Go-based tool for detecting SQL injection vulnerabilities using time-based, error-based, and union-based techniques.

## Overview

`cristoinjector` is an automated tool designed to identify potential SQL injection vulnerabilities in web applications. It supports scanning single URLs or lists of URLs, auto-discovery of URLs with query parameters from root domains, and concurrent testing with customizable payloads. The tool is intended for security researchers and penetration testers with explicit permission to test target systems.

**Creator**: Cristopher

**Features**:
- Supports time-based, error-based, and union-based SQL injection detection.
- Auto-discovers URLs with query parameters when given a root URL.
- Concurrent scanning with configurable concurrency, response time thresholds, and verification attempts.
- Customizable payload files for flexible testing.
- Colored console output for clear results.

## Prerequisites

Before building and running `cristoinjector`, ensure you have the following:

- **Go**: Version 1.18 or later (1.21.3 recommended for compatibility). Install from [go.dev](https://go.dev/dl/) or via your package manager:
  ```bash
  sudo apt update
  sudo apt install golang-go
  go version
  ```
- **Git**: For cloning the repository.
  ```bash
  sudo apt install git
  ```
- **Access to Target Systems**: You must have explicit permission to test the systems you scan (e.g., `testphp.vulnweb.com`).

## Installation

### Build from Source

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/cristophercervantes/cristoinjector.git
   cd cristoinjector
   ```

2. **Fetch Dependencies**:
   Ensure all dependencies are downloaded:
   ```bash
   go mod tidy
   ```

3. **Build the Binary**:
   Compile the tool to create the `cristoinjector` executable:
   ```bash
   go build -o cristoinjector ./cmd/cristoinjector
   ```

4. **(Optional) Move Binary to `$GOPATH/bin`**:
   For global access, move the binary to your Go binary directory:
   ```bash
   mv cristoinjector $HOME/go/bin/
   ```

   Ensure `$GOPATH/bin` is in your `PATH`:
   ```bash
   export PATH=$PATH:$HOME/go/bin
   echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
   source ~/.bashrc
   ```

5. **Verify Installation**:
   Check the version to confirm the build:
   ```bash
   ./cristoinjector -version
   ```
   Expected output: `cristoinjector v0.2.0`

## Project Structure

The repository is organized as follows:
```
cristoinjector/
├── cmd/
│   └── cristoinjector/
│       └── main.go          # CLI entry point and banner
├── internal/
│   ├── crawler/
│   │   └── crawler.go      # URL crawling logic for auto-discovery
│   ├── detector/
│   │   └── detector.go     # SQL injection detection logic
│   └── utils/
│       └── utils.go        # Helper functions (e.g., file reading)
├── payloads/
│   ├── time_payloads.txt   # Sample time-based payloads
│   ├── error_payloads.txt  # Sample error-based payloads
│   └── union_payloads.txt  # Sample union-based payloads
├── go.mod                  # Go module dependencies
├── go.sum                  # Dependency checksums
└── README.md               # This file
```

## Usage

Run `cristoinjector` with various flags to customize scanning behavior. The tool requires either a single URL (`-u`) or a file with URLs (`-list`), along with appropriate payload files for the selected mode.

### Command Syntax
```bash
./cristoinjector [flags]
```

### Flags
- `-u <URL>`: Single URL to scan. Use `*` as a placeholder for payloads (e.g., `http://example.com/page.php?id=1*`).
- `-list <file>`: File containing a list of URLs (one per line).
- `-time-payload <file>`: File with time-based payloads.
- `-error-payload <file>`: File with error-based payloads.
- `-union-payload <file>`: File with union-based payloads.
- `-mode <mode>`: Detection mode (`time`, `error`, `union`, or `all`). Default: `time`.
- `-concurrency <int>`: Maximum concurrent payload scans. Default: `20`.
- `-mrt <int>`: Response time threshold in seconds for time-based detection. Default: `10`.
- `-verify <int>`: Number of verification attempts for detected vulnerabilities. Default: `3`.
- `-verifydelay <int>`: Delay between verification attempts in milliseconds. Default: `12000`.
- `-version`: Print the version and exit.

### Example Commands

1. **Single URL, Time-based Detection**:
   ```bash
   ./cristoinjector -u "http://testphp.vulnweb.com/artists.php?artist=1*" -time-payload payloads/time_payloads.txt -mode time
   ```

2. **Multiple URLs, Error-based Detection**:
   Create a file `urls.txt` with URLs (one per line), then:
   ```bash
   ./cristoinjector -list urls.txt -error-payload payloads/error_payloads.txt -mode error
   ```

3. **Root URL, Auto-Discovery, All Modes**:
   ```bash
   ./cristoinjector -u "http://testphp.vulnweb.com" -time-payload payloads/time_payloads.txt -error-payload payloads/error_payloads.txt -union-payload payloads/union_payloads.txt -mode all
   ```

### Payload Files
The `payloads/` directory includes sample payload files:
- `time_payloads.txt`:
  ```
  ' AND SLEEP(10)--
  " AND SLEEP(10)--
  ; WAITFOR DELAY '0:0:10'--
  ```
- `error_payloads.txt`:
  ```
  '
  ")
  ';--
  1' OR '1'='1
  ```
- `union_payloads.txt`:
  ```
  ' UNION SELECT 1,2,3--
  ' UNION ALL SELECT NULL,NULL--
  ```

You can create custom payload files, ensuring one payload per line.

## Detection Methods

- **Time-based**: Detects vulnerabilities by measuring response delays (e.g., `SLEEP(10)` causing a delay ≥ `-mrt` seconds).
- **Error-based**: Identifies vulnerabilities by checking for database error messages in responses (e.g., "SQL syntax error").
- **Union-based**: Detects vulnerabilities by analyzing response content changes (e.g., injected `1,2,3` appearing in output).

## Notes

- **Ethical Use**: Use `cristoinjector` only on systems you have explicit permission to test. Unauthorized scanning is illegal and unethical.
- **Payload Files**: Ensure payload files exist and are correctly formatted (one payload per line, no empty lines).
- **Dependencies**: The tool uses `github.com/gocolly/colly` for crawling and `github.com/fatih/color` for output formatting. These are automatically fetched by `go mod tidy`.
- **Troubleshooting**:
  - If the build fails, verify Go version (`go version`) and run `go mod tidy`.
  - Check file paths for payloads and URLs.
  - Clear Go cache if issues persist:
    ```bash
    go clean -cache -modcache
    ```

## Contributing

Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m "Add your feature"`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For issues or feature requests, open a GitHub issue at `github.com/cristophercervantes/cristoinjector`.
