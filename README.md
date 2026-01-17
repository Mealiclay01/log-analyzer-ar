# 📊 Log Analyzer AR

A powerful Linux CLI tool for analyzing log files with support for multiple formats including syslog, nginx access/error logs, and application logs. Generates comprehensive reports in JSON, CSV, and HTML formats, with optional Arabic AI-powered summaries.

## ✨ Features

- **Multi-format Support**: Analyzes syslog, nginx access/error logs, and generic application logs
- **Severity Detection**: Automatically detects ERROR, WARN, INFO, and DEBUG levels
- **Top Messages**: Identifies and counts the most frequent log messages
- **IP Analysis**: Extracts and ranks top IP addresses from logs
- **Status Code Tracking**: Analyzes HTTP status codes from nginx access logs
- **Timeline Generation**: Creates hourly timeline of log events
- **Multiple Output Formats**:
  - JSON: Complete analysis data
  - CSV: Separate files for summary, messages, IPs, status codes, and timeline
  - HTML: Interactive visual report with charts and tables
- **AI-Powered Summaries** (Optional): Generate Arabic summaries using OpenAI or Anthropic

## 📋 Requirements

- Python 3.7 or higher
- Optional: OpenAI or Anthropic API key for Arabic summaries

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/Mealiclay01/log-analyzer-ar.git
cd log-analyzer-ar
```

2. Install dependencies (optional, only needed for AI summaries):
```bash
pip install -r requirements.txt
```

3. Make the script executable:
```bash
chmod +x log_analyzer.py
```

## 📖 Usage

### Basic Usage

Analyze a single log file:
```bash
./log_analyzer.py examples/syslog.log
```

Analyze multiple log files:
```bash
./log_analyzer.py examples/syslog.log examples/nginx_access.log examples/app.log
```

Specify custom output directory:
```bash
./log_analyzer.py examples/syslog.log -o results/
```

### With Arabic AI Summary

Using OpenAI:
```bash
export AI_PROVIDER=openai
export AI_API_KEY=sk-your-api-key-here
./log_analyzer.py examples/app.log
```

Using Anthropic:
```bash
export AI_PROVIDER=anthropic
export AI_API_KEY=your-api-key-here
./log_analyzer.py examples/app.log
```

### Command-line Options

```
usage: log_analyzer.py [-h] [-o OUTPUT_DIR] log_files [log_files ...]

positional arguments:
  log_files             One or more log files to analyze

optional arguments:
  -h, --help           Show this help message and exit
  -o, --output-dir     Output directory for results (default: output/)
```

## 📂 Output Files

The tool generates the following files in the output directory:

- **analysis.json**: Complete analysis results in JSON format
- **summary.csv**: Overall summary statistics
- **top_messages.csv**: Top 10 most frequent messages
- **top_ips.csv**: Top 10 IP addresses
- **top_status_codes.csv**: Top 10 HTTP status codes
- **timeline.csv**: Events grouped by hour
- **report.html**: Interactive HTML report (open in browser)
- **summary.md**: Arabic AI-generated summary (if configured)

## 🔍 Supported Log Formats

### 1. Syslog
```
Jan 17 10:15:32 webserver sshd[1234]: Failed password for invalid user admin
```

### 2. Nginx Access Log
```
192.168.1.101 - - [17/Jan/2026:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1234
```

### 3. Nginx Error Log
```
2026/01/17 10:15:32 [error] 1234#0: *1 connect() failed (111: Connection refused)
```

### 4. Generic Application Log
```
2026-01-17 10:15:32.123 ERROR [database] Connection pool exhausted
```

## 📊 Example Output

After running the analyzer, you'll see output like:

```
🔍 Analyzing 3 log file(s)...
✅ Analysis complete!
   - Total lines: 60
   - Parsed lines: 60
   - Errors: 22
   - Warnings: 12

📝 Generating outputs in output/...
   ✓ JSON: output/analysis.json
   ✓ CSV: output/summary.csv
   ✓ CSV: output/top_messages.csv
   ✓ CSV: output/top_ips.csv
   ✓ CSV: output/top_status_codes.csv
   ✓ CSV: output/timeline.csv
   ✓ HTML: output/report.html
   ✓ Arabic Summary: output/summary.md

✨ All done! Open output/report.html to view the report.
```

## 🧪 Try It Out

Sample log files are provided in the `examples/` directory:

```bash
# Analyze all sample logs
./log_analyzer.py examples/*.log

# View the HTML report
open output/report.html  # macOS
xdg-open output/report.html  # Linux
```

## 🌍 Arabic Summary Feature

The optional Arabic summary feature uses AI to generate a concise summary in Arabic. To use it:

1. Set the `AI_PROVIDER` environment variable to either `openai` or `anthropic`
2. Set the `AI_API_KEY` environment variable with your API key
3. Run the analyzer as usual

The summary will be saved to `output/summary.md`.

## 🛠️ Development

The tool is built with Python and uses:
- Standard library for parsing and analysis
- OpenAI/Anthropic APIs for optional Arabic summaries (only if configured)

No dependencies are required for basic functionality!

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For issues, questions, or suggestions, please open an issue on GitHub.
