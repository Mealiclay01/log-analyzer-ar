"""
Enhanced CLI for log-analyzer-ar with production-grade UX
"""

import argparse
import sys
import os
from typing import List
from pathlib import Path

from .analyzer import LogAnalyzer
from .reporter import OutputGenerator
from .ai_summary import ArabicSummaryGenerator


def create_parser() -> argparse.ArgumentParser:
    """Create enhanced argument parser"""
    parser = argparse.ArgumentParser(
        prog='log-analyzer-ar',
        description='🔍 Production-grade Linux log analyzer with Arabic AI summary support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  log-analyzer-ar access.log error.log
  
  # With custom output directory
  log-analyzer-ar /var/log/nginx/access.log -o reports/
  
  # Filter by time range
  log-analyzer-ar app.log --from "2026-01-01" --to "2026-01-31"
  
  # Analyze last 24 hours
  log-analyzer-ar syslog --from 24h
  
  # Specific format with custom top N
  log-analyzer-ar access.log --format nginx_access --top 20
  
  # Quick analysis (first 10000 lines only)
  log-analyzer-ar huge.log --max-lines 10000
  
  # With Arabic AI summary
  AI_PROVIDER=openai AI_API_KEY=sk-xxx log-analyzer-ar app.log
  
  # Disable specific outputs
  log-analyzer-ar app.log --no-html --no-csv
  
  # Quiet mode (minimal output)
  log-analyzer-ar app.log -q
  
For more information: https://github.com/Mealiclay01/log-analyzer-ar
        """
    )
    
    # Positional arguments
    parser.add_argument(
        'log_files',
        nargs='+',
        help='One or more log files to analyze'
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output-dir',
        default='output',
        help='Output directory for results (default: output/)'
    )
    output_group.add_argument(
        '--no-json',
        action='store_true',
        help='Disable JSON output generation'
    )
    output_group.add_argument(
        '--no-csv',
        action='store_true',
        help='Disable CSV output generation'
    )
    output_group.add_argument(
        '--no-html',
        action='store_true',
        help='Disable HTML report generation'
    )
    
    # Parsing options
    parse_group = parser.add_argument_group('Parsing Options')
    parse_group.add_argument(
        '--format',
        choices=['auto', 'syslog', 'nginx_access', 'nginx_error', 'app'],
        default='auto',
        help='Log format hint (default: auto-detect)'
    )
    parse_group.add_argument(
        '--max-lines',
        type=int,
        metavar='N',
        help='Process only first N lines (for quick analysis)'
    )
    
    # Filter options
    filter_group = parser.add_argument_group('Filter Options')
    filter_group.add_argument(
        '--from',
        dest='from_time',
        metavar='TIME',
        help='Start time filter (ISO format or relative like "24h", "7d")'
    )
    filter_group.add_argument(
        '--to',
        dest='to_time',
        metavar='TIME',
        help='End time filter (ISO format)'
    )
    filter_group.add_argument(
        '--timezone',
        default='UTC',
        help='Timezone for time filters (default: UTC)'
    )
    
    # Analysis options
    analysis_group = parser.add_argument_group('Analysis Options')
    analysis_group.add_argument(
        '--top',
        type=int,
        default=10,
        metavar='N',
        help='Number of top items to show in rankings (default: 10)'
    )
    
    # Output control
    verbosity_group = parser.add_argument_group('Verbosity Options')
    verbosity_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode - minimal output'
    )
    verbosity_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose mode - detailed progress'
    )
    
    # Version
    parser.add_argument(
        '--version',
        action='version',
        version='log-analyzer-ar 1.0.0'
    )
    
    return parser


def validate_args(args) -> bool:
    """Validate command-line arguments"""
    # Check if log files exist
    for log_file in args.log_files:
        if not os.path.exists(log_file):
            print(f"❌ Error: Log file not found: {log_file}", file=sys.stderr)
            return False
        
        if not os.path.isfile(log_file):
            print(f"❌ Error: Not a file: {log_file}", file=sys.stderr)
            return False
    
    # Check output directory is writable
    try:
        output_path = Path(args.output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"❌ Error: Cannot create output directory: {e}", file=sys.stderr)
        return False
    
    return True


def print_header(quiet: bool):
    """Print application header"""
    if quiet:
        return
    
    print("╔══════════════════════════════════════════════════════════╗")
    print("║         🔍 Log Analyzer AR - Portfolio Edition          ║")
    print("║    Production-grade Linux log analysis with Arabic AI   ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()


def print_analysis_summary(analyzer: LogAnalyzer, quiet: bool, verbose: bool):
    """Print analysis summary"""
    if quiet:
        return
    
    print()
    print("✅ Analysis Complete!")
    print(f"   📊 Total lines processed:    {analyzer.total_lines:,}")
    print(f"   ✓  Successfully parsed:      {analyzer.parsed_lines:,}")
    
    if analyzer.skipped_lines > 0:
        print(f"   ⏭️  Skipped (unmatched):      {analyzer.skipped_lines:,}")
    
    parse_rate = (analyzer.parsed_lines / analyzer.total_lines * 100) if analyzer.total_lines > 0 else 0
    print(f"   📈 Parse rate:               {parse_rate:.1f}%")
    print()
    
    # Severity summary
    errors = analyzer.severity_counts.get('error', 0)
    warnings = analyzer.severity_counts.get('warn', 0)
    
    if errors > 0:
        print(f"   ⚠️  Errors found:             {errors:,}")
    if warnings > 0:
        print(f"   ⚡ Warnings found:           {warnings:,}")
    
    if verbose:
        print(f"   ℹ️  Info messages:           {analyzer.severity_counts.get('info', 0):,}")
        print(f"   🐛 Debug messages:          {analyzer.severity_counts.get('debug', 0):,}")
        print(f"   🌐 Unique IP addresses:     {len(analyzer.ip_counter):,}")
        print(f"   📍 Unique endpoints:        {len(analyzer.endpoint_counter):,}")


def print_output_summary(generated_files: List[str], quiet: bool):
    """Print generated output files"""
    if quiet:
        print(f"Generated {len(generated_files)} output files in {Path(generated_files[0]).parent if generated_files else 'output/'}")
        return
    
    print()
    print("📝 Generated Output Files:")
    for filepath in generated_files:
        filename = Path(filepath).name
        if filename.endswith('.json'):
            icon = '📄'
        elif filename.endswith('.csv'):
            icon = '📊'
        elif filename.endswith('.html'):
            icon = '🌐'
        elif filename.endswith('.md'):
            icon = '📝'
        else:
            icon = '📁'
        
        print(f"   {icon} {filepath}")


def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Set verbosity
    verbose = args.verbose
    quiet = args.quiet
    
    if verbose and quiet:
        print("❌ Error: Cannot use both --verbose and --quiet", file=sys.stderr)
        return 1
    
    # Print header
    print_header(quiet)
    
    # Validate arguments
    if not validate_args(args):
        return 1
    
    # Show what we're analyzing
    if not quiet:
        print(f"🔍 Analyzing {len(args.log_files)} log file(s)...")
        if verbose:
            for log_file in args.log_files:
                file_size = os.path.getsize(log_file)
                size_mb = file_size / (1024 * 1024)
                print(f"   📁 {log_file} ({size_mb:.1f} MB)")
        print()
    
    # Create analyzer
    analyzer = LogAnalyzer(
        format_hint=args.format,
        timezone=args.timezone,
        from_time=args.from_time,
        to_time=args.to_time,
        top_n=args.top,
        max_lines=args.max_lines
    )
    
    # Analyze each file
    for log_file in args.log_files:
        if verbose:
            print(f"📖 Processing: {log_file}")
        analyzer.analyze_file(log_file, verbose=verbose)
    
    # Get results
    results = analyzer.get_results()
    
    # Print analysis summary
    print_analysis_summary(analyzer, quiet, verbose)
    
    # Notable findings
    if not quiet and results.get('notable_findings', {}).get('has_findings'):
        print()
        print("⚠️  Notable Findings Detected:")
        findings = results['notable_findings']
        if findings.get('high_error_rate'):
            print("   • High error rate (>10%)")
        if findings.get('error_spike'):
            print("   • Unusual traffic spike detected")
        if findings.get('suspicious_ips'):
            print(f"   • Suspicious IP activity ({len(findings['suspicious_ips'])} IPs)")
        if findings.get('repeated_500s'):
            print("   • Multiple server errors (5xx)")
    
    # Generate outputs
    if not quiet:
        print()
        print(f"📝 Generating outputs in {args.output_dir}/...")
    
    generator = OutputGenerator(
        results,
        args.output_dir,
        generate_json=not args.no_json,
        generate_csv=not args.no_csv,
        generate_html=not args.no_html
    )
    
    generated_files = generator.generate_all()
    
    # Generate Arabic summary
    ai_gen = ArabicSummaryGenerator(results, args.output_dir)
    summary_file = ai_gen.generate_summary(verbose=verbose)
    if summary_file:
        generated_files.append(summary_file)
    
    # Print output summary
    print_output_summary(generated_files, quiet)
    
    # Final message
    if not quiet:
        html_file = next((f for f in generated_files if f.endswith('.html')), None)
        if html_file:
            print()
            print(f"✨ All done! Open {html_file} in your browser to view the report.")
        print()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
