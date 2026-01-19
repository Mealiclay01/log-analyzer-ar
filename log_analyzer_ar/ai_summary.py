"""
Arabic AI summary generator using OpenAI or Anthropic
"""

import os
from typing import Dict, Optional
from pathlib import Path


class ArabicSummaryGenerator:
    """Generate Arabic summary using AI providers"""
    
    def __init__(self, results: Dict, output_dir: str):
        self.results = results
        self.output_dir = Path(output_dir)
        self.ai_provider = os.getenv('AI_PROVIDER', '').lower()
        self.ai_api_key = os.getenv('AI_API_KEY', '')
    
    def can_generate(self) -> bool:
        """Check if AI summary can be generated"""
        return bool(self.ai_provider and self.ai_api_key)
    
    def generate_summary(self, verbose: bool = False) -> Optional[str]:
        """Generate Arabic summary if AI credentials are available"""
        if not self.can_generate():
            if verbose:
                print("⏭️  Skipping Arabic summary: AI_PROVIDER and AI_API_KEY not set")
            return None
        
        summary_text = self._create_summary_prompt()
        
        try:
            if self.ai_provider == 'openai':
                return self._generate_with_openai(summary_text, verbose)
            elif self.ai_provider == 'anthropic':
                return self._generate_with_anthropic(summary_text, verbose)
            else:
                if verbose:
                    print(f"❌ Unsupported AI provider: {self.ai_provider}")
                return None
        except Exception as e:
            if verbose:
                print(f"❌ Error generating Arabic summary: {e}")
            return None
    
    def _create_summary_prompt(self) -> str:
        """Create summary prompt for AI with DevOps/SRE focus"""
        summary = self.results['summary']
        notable = self.results.get('notable_findings', {})
        
        # Build findings list
        findings = []
        if notable.get('high_error_rate'):
            findings.append(f"High error rate: {summary.get('total_errors', 0)} errors")
        if notable.get('error_spike'):
            findings.append("Unusual traffic spike detected")
        if notable.get('suspicious_ips'):
            ips = ', '.join([ip['ip'] for ip in notable['suspicious_ips'][:3]])
            findings.append(f"Suspicious IPs: {ips}")
        if notable.get('repeated_500s'):
            findings.append("Multiple server errors (5xx status codes)")
        
        # Top IPs
        top_ips = self.results.get('top_ips', [])[:5]
        top_ips_str = ', '.join([f"{ip['ip']} ({ip['count']} requests)" for ip in top_ips])
        
        # Top status codes
        top_status = self.results.get('top_status_codes', [])[:5]
        top_status_str = ', '.join([f"{s['status_code']} ({s['count']})" for s in top_status])
        
        prompt = f"""
You are a DevOps/SRE expert creating an executive summary in Arabic for a log analysis report.

Log Analysis Results:
- Total lines analyzed: {summary.get('total_lines', 0):,}
- Successfully parsed: {summary.get('parsed_lines', 0):,} ({summary.get('parse_rate', 0)}%)
- Errors found: {summary.get('total_errors', 0):,}
- Warnings found: {summary.get('total_warnings', 0):,}
- Unique IP addresses: {summary.get('unique_ips', 0):,}
- Unique HTTP status codes: {summary.get('unique_status_codes', 0):,}

Notable Findings:
{chr(10).join(f'- {f}' for f in findings) if findings else '- No critical issues detected'}

Top IP Addresses:
{top_ips_str or 'N/A'}

Top HTTP Status Codes:
{top_status_str or 'N/A'}

Create a professional Arabic summary (250-300 words) with:
1. Executive Summary (3-4 bullets in Arabic)
2. Key Incidents (if any, in Arabic)
3. Top Offenders (IPs/status codes, in Arabic)
4. Recommended Actions (3-4 DevOps/SRE recommendations in Arabic)

Write in formal Arabic suitable for IT managers and DevOps teams in Gulf countries.
Use professional technical terminology.
Format with clear headers and bullet points.
"""
        return prompt
    
    def _generate_with_openai(self, prompt: str, verbose: bool) -> Optional[str]:
        """Generate summary using OpenAI"""
        try:
            import openai
        except ImportError:
            if verbose:
                print("❌ OpenAI package not installed. Install with: pip install openai")
            return None
        
        try:
            client = openai.OpenAI(api_key=self.ai_api_key)
            
            if verbose:
                print("🤖 Generating Arabic summary with OpenAI...")
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a DevOps/SRE expert who creates professional Arabic summaries of log analysis reports."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=800,
                temperature=0.7
            )
            
            arabic_summary = response.choices[0].message.content
            return self._save_summary(arabic_summary, verbose)
        
        except Exception as e:
            if verbose:
                print(f"❌ OpenAI API error: {e}")
            return None
    
    def _generate_with_anthropic(self, prompt: str, verbose: bool) -> Optional[str]:
        """Generate summary using Anthropic"""
        try:
            import anthropic
        except ImportError:
            if verbose:
                print("❌ Anthropic package not installed. Install with: pip install anthropic")
            return None
        
        try:
            client = anthropic.Anthropic(api_key=self.ai_api_key)
            
            if verbose:
                print("🤖 Generating Arabic summary with Anthropic Claude...")
            
            response = client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=800,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            arabic_summary = response.content[0].text
            return self._save_summary(arabic_summary, verbose)
        
        except Exception as e:
            if verbose:
                print(f"❌ Anthropic API error: {e}")
            return None
    
    def _save_summary(self, arabic_summary: str, verbose: bool) -> str:
        """Save Arabic summary to file"""
        summary_file = self.output_dir / 'summary.md'
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("# ملخص تحليل السجلات\n\n")
            f.write("---\n\n")
            f.write(arabic_summary)
            f.write("\n\n---\n\n")
            f.write(f"*تم إنشاء هذا الملخص تلقائياً بواسطة الذكاء الاصطناعي*\n")
        
        if verbose:
            print(f"   ✓ Arabic Summary: {summary_file}")
        
        return str(summary_file)
