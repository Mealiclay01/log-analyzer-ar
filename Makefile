# Makefile for log-analyzer-ar

.PHONY: help install test lint demo clean

help:  ## Show this help message
	@echo "📊 Log Analyzer AR - Makefile Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package locally
	pip install -e .

install-ai:  ## Install with AI dependencies
	pip install -e ".[ai]"

test:  ## Run unit tests
	python -m pytest tests/ -v

lint:  ## Run code linters
	@echo "Running flake8..."
	@flake8 log_analyzer_ar/ || true
	@echo "Running pylint..."
	@pylint log_analyzer_ar/ || true

demo:  ## Run demo analysis on example logs
	@echo "🔍 Running demo analysis..."
	@./scripts/demo.sh

clean:  ## Clean up generated files
	rm -rf output/ dist/ build/ *.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

run-examples:  ## Analyze example logs
	python -m log_analyzer_ar examples/*.log

run-verbose:  ## Run with verbose output
	python -m log_analyzer_ar examples/*.log -v

run-quiet:  ## Run with quiet output
	python -m log_analyzer_ar examples/*.log -q

run-custom:  ## Run with custom options
	python -m log_analyzer_ar examples/nginx_access.log --format nginx_access --top 15 -o custom_output/
