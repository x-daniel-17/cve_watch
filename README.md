# CVE Watch

A macOS app that scans your installed applications for known CVE vulnerabilities using the [National Vulnerability Database](https://nvd.nist.gov/).

Built with SwiftUI (macOS 26 Liquid Glass) and a Python backend.

## Setup

Requires **macOS 26**, **Xcode 26+**, and **Python 3.10+**.

```bash
git clone https://github.com/YOUR_USERNAME/cve_watch.git
cd cve_watch
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cd gui && bash build.sh --install
```

This builds the app and installs it to `/Applications`. Open **CVE Watch** from your Dock, Launchpad, or Spotlight.

## Optional: NVD API Key

Scans work without a key but are rate-limited. Get a free key at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) for faster scans.

```bash
export NVD_API_KEY="your-key"
```

## CLI Usage

```bash
source .venv/bin/activate
python -m src.main            # Scan + terminal dashboard
python -m src.main --scan     # Scan only
python -m src.main --watch    # Periodic checks (every 6 hours)
```

## How It Works

1. Discovers installed apps from Homebrew and `/Applications`
2. Queries the NVD API using CPE matching (~35 supported apps)
3. Caches results in SQLite for 7 days
4. Displays a severity-coded dashboard with CVE details

## Tests

```bash
python -m pytest tests/ -v
```

## License

MIT
