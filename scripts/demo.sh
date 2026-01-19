#!/bin/bash
# Demo script for log-analyzer-ar

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║       🔍 Log Analyzer AR - Demo & Validation            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Clean previous output
echo "🧹 Cleaning previous output..."
rm -rf output/
echo ""

# Run analysis
echo "📊 Analyzing example logs..."
python3 -m log_analyzer_ar examples/*.log -v
echo ""

# Verify outputs
echo "✅ Verifying generated files..."
if [ -f "output/analysis.json" ]; then
    echo "   ✓ analysis.json"
else
    echo "   ❌ analysis.json MISSING!"
    exit 1
fi

if [ -f "output/report.html" ]; then
    echo "   ✓ report.html"
else
    echo "   ❌ report.html MISSING!"
    exit 1
fi

# Count CSV files
csv_count=$(ls output/*.csv 2>/dev/null | wc -l)
echo "   ✓ $csv_count CSV files generated"

# Validate JSON
echo ""
echo "🔍 Validating JSON structure..."
python3 -c "
import json
with open('output/analysis.json', 'r') as f:
    data = json.load(f)
    print(f\"   ✓ Valid JSON with {len(data)} top-level keys\")
    print(f\"   ✓ Analyzed {data['summary']['total_lines']} total lines\")
    print(f\"   ✓ Found {data['summary']['total_errors']} errors\")
"

echo ""
echo "✨ Demo completed successfully!"
echo ""
echo "📁 Generated files in output/:"
ls -lh output/
echo ""
echo "🌐 Open output/report.html in your browser to view the report"
