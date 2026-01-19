# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-19

### Added
- Production-ready Python package structure
- Enhanced CLI with comprehensive options:
  - `--format` for format hints (auto|syslog|nginx_access|nginx_error|app)
  - `--from/--to` for time filtering
  - `--timezone` support
  - `--top N` for ranking customization
  - `--max-lines` for quick analysis
  - `--no-json/--no-csv/--no-html` output control
  - `--quiet/-q` and `--verbose/-v` modes
- Advanced log parsing with auto-detection
- Robust error handling (continues on parse errors)
- Notable findings detection:
  - High error rate alerts
  - Traffic spike detection
  - Suspicious IP identification
  - Repeated 404/500 tracking
- Portfolio-grade HTML report:
  - Chart.js integration for interactive charts
  - Dark mode toggle with localStorage persistence
  - Tabbed interface (Overview, Timeline, IPs, Status Codes, Messages)
  - Search/filter functionality
  - Mobile-friendly responsive design
  - RTL support for Arabic content
- Enhanced analytics:
  - Top endpoints/paths extraction
  - Daily and hourly timelines
  - Improved message normalization
  - Parse rate tracking
  - Time range detection
- Production features:
  - Safe JSON generation (no string concatenation)
  - HTML escaping (XSS prevention)
  - Streaming for large files
  - CSV outputs for all analytics
- Arabic AI summary support:
  - OpenAI GPT-3.5 integration
  - Anthropic Claude integration
  - DevOps/SRE-focused summaries
  - Gulf/Arab market appropriate language
- Repository quality improvements:
  - Makefile for common tasks
  - Demo script (scripts/demo.sh)
  - Python package support (`python -m log_analyzer_ar`)
  - pyproject.toml for modern packaging
  - Comprehensive documentation

### Changed
- Refactored monolithic script into modular package
- Improved timestamp parsing with multiple format support
- Enhanced severity detection logic
- Better IP extraction from all log types

### Fixed
- Timestamp parsing errors with complex formats
- HTML validity issues (replaced invalid `<value>` tags)
- JSON serialization for non-standard types
- Control character handling in outputs

## [0.1.0] - 2026-01-17

### Added
- Initial basic log analyzer
- Support for syslog, nginx access/error, and app logs
- JSON, CSV, and HTML output generation
- Optional Arabic AI summary
- Example log files

[1.0.0]: https://github.com/Mealiclay01/log-analyzer-ar/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/Mealiclay01/log-analyzer-ar/releases/tag/v0.1.0
