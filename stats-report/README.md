# Stats Report Generator

A unified tool for collecting and analyzing message statistics. This tool combines the functionality of the message export and analysis scripts into a single, efficient solution.

## Features

- Direct API integration for fetching message data
- Support for processing exported CSV files
- Memory-efficient analysis with optional SQLite storage
- Configurable ASA/Attack Score verdict handling
- Rich output formats (JSON and Markdown)
- Async operations for better performance

## Installation

1. Clone the repository
2. Install the package in development mode:
```bash
cd stats_report
pip install -e .
```

## Usage

### API Configuration

When using `--mode api`, you'll need:

1. **Base URL**: Your Sublime deployment URL (e.g., https://example.sublime.security)
   - Provided via the `--input` parameter
   - Must include protocol (http:// or https://)
   - No trailing slash needed

2. **API Key**: Your Sublime API key
   - Will be prompted securely at runtime
   - Can be provided via SUBLIME_API_KEY environment variable to skip prompt
   - Never stored or logged
   - Must have appropriate permissions for message groups and org stats

Example with environment variable:
```bash
export SUBLIME_API_KEY="your-api-key"
python main.py --mode api --input https://example.sublime.security
```

### Fetching Data from API

```bash
# Generate JSON report from API
python main.py --mode api --input https://example.sublime.security --output-format json

# Generate markdown report from API
python main.py --mode api --input https://example.sublime.security --output-format markdown

# Use ASA verdict for analysis
python main.py --mode api --input https://example.sublime.security --use-asa

# Use SQLite storage for large datasets
python main.py --mode api --input https://example.sublime.security --storage sqlite
```

### Processing Exported Files

```bash
# Process existing CSV export file
python main.py --mode file --input exported_messages.csv --output-format markdown

# Process large file with SQLite storage
python main.py --mode file --input exported_messages.csv --storage sqlite
```

### Output Options

- `--output-format`: Choose between `json` or `markdown` output
- `--output-file`: Specify custom output file path (default: timestamp-based filename)
- `--use-asa`: Use ASA Verdict instead of Attack Score Verdict for user report analysis only
  - When this flag is used, ASA verdicts will be used for analyzing user reports
  - Attack Score verdicts are always used for flagged message analysis, regardless of this flag
- `--storage`: Choose between `memory` (default) or `sqlite` storage backend

## Input File Format

When using `--mode file`, the input CSV must match the format produced by the message export tool:

Required columns:
- created_at
- id
- attack_score_verdict
- classification
- review_status
- review_label
- review_comment
- subjects
- sender_email_addresses
- recipient_count
- message_count
- flagged_rules
- rule_severities

## Output Format

### JSON Output
The JSON output follows a structured format with sections for:
- Report metadata (including org stats)
- Attack score accuracy analysis
- Malicious messages overview
- User reports overview

### Markdown Output
The markdown output provides a human-readable report with:
- Key findings and statistics
- Detailed analysis tables
- Attack type distributions
- User reporting effectiveness

## Error Handling

The tool includes comprehensive error handling for:
- API connection issues
- File format validation
- Data processing errors
- Resource cleanup

Error messages are logged with appropriate context to help diagnose issues.
