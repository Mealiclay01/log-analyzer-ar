# 📊 Log Analyzer AR | محلل السجلات

<div align="center">

**Production-Grade Linux Log Analyzer | محلل السجلات الاحترافي لأنظمة لينكس**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)

*Portfolio-quality CLI tool for DevOps, SRE, and SOC teams*

[English](#english) | [العربية](#arabic)

</div>

---

<a name="english"></a>

## 🌟 Features

- **🔍 Multi-Format Support**: Auto-detects syslog, nginx access/error logs, and application logs
- **📊 Advanced Analytics**: Error detection, suspicious IP tracking, traffic spikes, endpoint analysis  
- **🎨 Interactive Reports**: Modern HTML dashboards with Chart.js, dark mode, mobile-responsive
- **🤖 AI Summaries**: Optional Arabic summaries using OpenAI or Anthropic
- **⚡ Production-Ready**: Streaming, robust error handling, comprehensive CLI options
- **📈 Portfolio-Grade**: Clean code, unit tests, proper packaging, professional docs

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/Mealiclay01/log-analyzer-ar.git
cd log-analyzer-ar

# Install (optional - core has no dependencies)
pip install -e .              # Basic
pip install -e ".[ai]"        # With AI support

# Run
python -m log_analyzer_ar examples/*.log
# or
./log_analyzer.py examples/*.log
```

## 📖 Usage

### Basic

```bash
log-analyzer-ar access.log error.log    # Multiple files
log-analyzer-ar app.log -v              # Verbose
log-analyzer-ar app.log -q              # Quiet
log-analyzer-ar app.log -o reports/     # Custom output dir
```

### Time Filtering

```bash
log-analyzer-ar app.log --from "2026-01-01" --to "2026-01-31"
log-analyzer-ar syslog --from 24h       # Last 24 hours
log-analyzer-ar app.log --from 7d       # Last 7 days
```

### Advanced

```bash
log-analyzer-ar access.log --format nginx_access  # Skip auto-detect
log-analyzer-ar app.log --top 20                 # Top 20 (default 10)
log-analyzer-ar huge.log --max-lines 10000       # Quick analysis
log-analyzer-ar app.log --no-html --no-csv       # Disable outputs
```

### With AI Summary

```bash
AI_PROVIDER=openai AI_API_KEY=sk-xxx log-analyzer-ar app.log
AI_PROVIDER=anthropic AI_API_KEY=key log-analyzer-ar app.log
```

## 📁 Output Files

Generated in `output/` directory:

- `analysis.json` - Complete data
- `summary.csv` - Statistics
- `top_messages.csv` - Message patterns
- `top_ips.csv` - IP addresses
- `top_status_codes.csv` - HTTP codes
- `top_endpoints.csv` - URL paths
- `timeline_hourly.csv` - Hourly events
- `timeline_daily.csv` - Daily events  
- `report.html` - Interactive dashboard ⭐
- `summary.md` - Arabic AI summary (optional)

## 🎨 HTML Report

Interactive report with:
- 📊 Dashboard with stats
- ⚠️ Auto-detected anomalies
- 📈 Chart.js visualizations
- 🔍 Live search/filter
- 🌓 Dark mode toggle
- 📱 Mobile-responsive
- 🌍 RTL support for Arabic
- 🔒 XSS prevention

## 🔍 Supported Formats

**Syslog**
```
Jan 17 10:15:32 webserver sshd[1234]: Failed password
```

**Nginx Access**
```
192.168.1.101 - - [17/Jan/2026:10:15:32] "GET /api/users HTTP/1.1" 200 1234
```

**Nginx Error**
```
2026/01/17 10:15:32 [error] 1234#0: connect() failed
```

**Application**
```
2026-01-17 10:15:32 ERROR [database] Connection pool exhausted
```

## 🛠️ Development

```bash
make install   # Install locally
make test      # Run tests (11 tests)
make lint      # Run linters
make demo      # Run demo analysis
make help      # Show all commands
```

## 📊 Notable Findings

Auto-detects:
- High error rate (>10%)
- Traffic spikes (3x average)
- Suspicious IPs (5x average)
- Repeated 404/500 errors

## 🔒 Security

✅ Safe JSON generation  
✅ HTML escaping (XSS prevention)  
✅ Streaming for large files  
✅ Error recovery  
✅ No hardcoded credentials

## 📦 Structure

```
log-analyzer-ar/
├── log_analyzer_ar/    # Main package
│   ├── parser.py       # Log parsers
│   ├── analyzer.py     # Analytics
│   ├── reporter.py     # Outputs
│   ├── cli.py          # CLI
│   └── ai_summary.py   # AI integration
├── tests/              # Unit tests
├── examples/           # Sample logs
├── Makefile            # Commands
└── pyproject.toml      # Config
```

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

<a name="arabic"></a>

<div dir="rtl" align="right">

## ✨ المميزات

- **🔍 دعم تنسيقات متعددة**: كشف تلقائي لسجلات syslog و nginx والتطبيقات
- **📊 تحليلات متقدمة**: كشف الأخطاء، تتبع IPs المشبوهة، قياس الزيادات المفاجئة
- **🎨 تقارير تفاعلية**: لوحات معلومات HTML حديثة مع رسوم بيانية ووضع ليلي
- **🤖 ملخصات ذكية**: ملخصات اختيارية بالعربية باستخدام AI
- **⚡ جاهز للإنتاج**: معالجة قوية، خيارات CLI شاملة
- **📈 جودة احترافية**: كود نظيف، اختبارات، توثيق احترافي

## 🚀 البدء السريع

```bash
# استنساخ المشروع
git clone https://github.com/Mealiclay01/log-analyzer-ar.git
cd log-analyzer-ar

# التثبيت (اختياري)
pip install -e .              # أساسي
pip install -e ".[ai]"        # مع دعم AI

# التشغيل
python -m log_analyzer_ar examples/*.log
```

## 📖 الاستخدام

### أوامر أساسية

```bash
log-analyzer-ar access.log error.log    # ملفات متعددة
log-analyzer-ar app.log -v              # إخراج مفصل
log-analyzer-ar app.log -q              # وضع هادئ
log-analyzer-ar app.log -o reports/     # مجلد مخصص
```

### فلترة حسب الوقت

```bash
log-analyzer-ar app.log --from "2026-01-01" --to "2026-01-31"
log-analyzer-ar syslog --from 24h       # آخر 24 ساعة
log-analyzer-ar app.log --from 7d       # آخر 7 أيام
```

### خيارات متقدمة

```bash
log-analyzer-ar access.log --format nginx_access  # تحديد التنسيق
log-analyzer-ar app.log --top 20                 # أفضل 20
log-analyzer-ar huge.log --max-lines 10000       # تحليل سريع
log-analyzer-ar app.log --no-html --no-csv       # تعطيل مخرجات
```

### مع الملخص العربي

```bash
AI_PROVIDER=openai AI_API_KEY=sk-xxx log-analyzer-ar app.log
AI_PROVIDER=anthropic AI_API_KEY=key log-analyzer-ar app.log
```

## 📁 ملفات الإخراج

يتم إنشاؤها في مجلد `output/`:

- `analysis.json` - البيانات الكاملة
- `summary.csv` - الإحصائيات
- `top_messages.csv` - أنماط الرسائل
- `top_ips.csv` - عناوين IP
- `top_status_codes.csv` - أكواد HTTP
- `top_endpoints.csv` - المسارات
- `timeline_hourly.csv` - الأحداث بالساعة
- `timeline_daily.csv` - الأحداث باليوم
- `report.html` - لوحة معلومات تفاعلية ⭐
- `summary.md` - ملخص عربي بالـ AI (اختياري)

## 🎨 تقرير HTML

يتضمن:
- 📊 لوحة معلومات مع إحصائيات
- ⚠️ كشف تلقائي للشذوذات  
- 📈 رسوم بيانية تفاعلية
- 🔍 بحث وفلترة مباشرة
- 🌓 وضع ليلي
- 📱 متجاوب مع الجوال
- 🌍 دعم RTL للعربية
- 🔒 حماية من XSS

## 🎯 الفئة المستهدفة

- فرق DevOps
- مهندسو SRE
- مراكز العمليات الأمنية (SOC)
- مديرو النظم
- شركات الاستضافة

## 📊 كشف النتائج الملحوظة

كشف تلقائي لـ:
- معدل أخطاء عالي (>10%)
- زيادة مفاجئة في حركة المرور (3 أضعاف)
- IPs مشبوهة (5 أضعاف)
- أخطاء 404/500 متكررة

## 🔒 الأمان

✅ توليد آمن لـ JSON  
✅ حماية HTML (منع XSS)  
✅ معالجة تدفقية للملفات الكبيرة  
✅ استرجاع من الأخطاء  
✅ لا توجد بيانات اعتماد مضمنة

## 📄 الترخيص

MIT License

</div>

---

<div align="center">

Made with ❤️ for DevOps, SRE, and SOC teams  
صُنع بـ ❤️ لفرق DevOps و SRE ومراكز العمليات الأمنية

**[⬆ Back to Top](#-log-analyzer-ar--محلل-السجلات)**

</div>
