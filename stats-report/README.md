# Stats Report Generator

A tool for collecting and analyzing message statistics in Sublime.

## Installation

1. Clone the repository
2. Install the package in development mode:
```bash
cd stats_report
pip install -e .
```

## Command Line Options

```bash
python main.py [OPTIONS]

Required Options:
  --mode {api,file}           Data source mode (API or file)
  --input TEXT               API base URL or input file path

Optional Arguments:
  --output-format {json,markdown}  Output format (default: markdown)
  --output-file TEXT              Custom output file path
  --storage {memory,sqlite}       Storage backend (default: memory)
  --use-asa                       Use ASA verdict for user reports
  --days-back INTEGER            Days of data to fetch (API mode only, default: 30)
  --hours-back INTEGER           Hours of data to fetch (API mode only, for high-volume instances)
                                Mutually exclusive with --days-back
  --debug                        Enable debug logging
  --ignore-ids TEXT              Comma-separated list of message group IDs to ignore
```

### Mode Selection

The tool operates in two modes:

1. **API Mode** (`--mode api`)
   - Fetches data directly from Sublime Security API
   - Requires base URL and API key
   - Supports date range filtering with `--days-back`
   - Automatically fetches organization statistics
   - Real-time data processing

2. **File Mode** (`--mode file`)
   - Processes previously exported CSV files
   - Compatible with flagged-message-export output format
   - Offline operation
   - Good for historical analysis
   - No API credentials needed

### Storage Options

The tool supports two storage backends:

1. **Memory Mode** (`--storage memory`, default)
   - Processes all data in memory
   - Faster for small to medium datasets
   - Lower I/O overhead
   - Good for most use cases
   - Memory usage scales with data size

2. **SQLite Mode** (`--storage sqlite`)
   - Uses SQLite database for data storage
   - Better for large datasets (millions of messages)
   - Reduced memory footprint
   - Slightly slower due to I/O
   - Persistent storage between runs

## API Configuration

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

# Fetch last 7 days of data with debug logging
python main.py --mode api --input https://example.sublime.security --days-back 7 --debug

# Fetch last 12 hours of data (for high-volume instances)
python main.py --mode api --input https://example.sublime.security --hours-back 12
```

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

### JSON Schema

The JSON output follows this schema:

```json
{
  "report_metadata": {
    "generated_at": "ISO8601 timestamp",
    "date_range": {
      "start": "ISO8601 timestamp",
      "end": "ISO8601 timestamp"
    },
    "org_stats": {
      "messages_processed": "integer",
      "active_mailboxes": "integer",
      "active_detection_rules": "integer"
    }
  },
  "attack_score_accuracy": {
    "overview": {
      "total_messages_with_asv_and_classification": "integer",
      "messages_with_agreement": "integer",
      "accuracy_rate": "float"
    },
    "classification_overrides": [
      {
        "attack_score_verdict": "string",
        "customer_classification": "string",
        "count": "integer",
        "percentage": "float"
      }
    ]
  },
  "malicious_messages_overview": {
    "key_findings": {
      "total_malicious_messages": {
        "groups": "integer",
        "individual_messages": "integer"
      },
      "malicious_not_in_spam": {
        "groups": "integer",
        "individual_messages": "integer",
        "percentage": "float"
      }
    },
    "attack_types": [
      {
        "attack_type": "string",
        "message_groups": "integer",
        "total_individual_messages": "integer",
        "percentage_of_total": "float"
      }
    ],
    "tactics_and_techniques": [
      {
        "tactic": "string",
        "message_groups": "integer",
        "total_individual_messages": "integer",
        "percentage_of_total": "float"
      }
    ],
    "detection_methods": [
      {
        "detection_method": "string",
        "message_groups": "integer",
        "total_individual_messages": "integer",
        "percentage_of_total": "float"
      }
    ],
    "top_senders": [
      {
        "domain": "string",
        "message_groups": "integer",
        "total_individual_messages": "integer",
        "percentage_of_total": "float"
      }
    ],
    "top_malicious_emails": [
      {
        "received_datetime": "ISO8601 timestamp",
        "subject": "string",
        "sender_email": "string",
        "url": "string",
        "total_messages": "integer"
      }
    ]
  },
  "user_reports_overview": {
    "key_findings": {
      "total_user_reported": {
        "groups": "integer",
        "individual_messages": "integer"
      },
      "malicious_verdicts": {
        "groups": "integer",
        "individual_messages": "integer",
        "percentage": "float",
        "verdict_type": "string"
      }
    },
    "classifications": [
      {
        "verdict": "string",
        "verdict_type": "string",
        "message_groups": "integer",
        "total_user_reported_messages": "integer",
        "percentage_of_total": "float"
      }
    ],
    "top_reporters": [
      {
        "reporter_email": "string",
        "report_groups": "integer",
        "total_reported_messages": "integer",
        "percentage_of_total": "float"
      }
    ],
    "top_reporters_effectiveness": [
      {
        "reporter_email": "string",
        "reported_messages": "integer",
        "total_individual_messages": "integer",
        "malicious_percentage": "float",
        "spam_percentage": "float",
        "graymail_percentage": "float",
        "benign_percentage": "float"
      }
    ]
  }
}
```

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

### Debug Mode

When troubleshooting, use the `--debug` flag to enable detailed logging:
- API request/response summaries
- Data processing steps
- Memory usage statistics
- Performance metrics
- Rule metadata parsing details
- Attack types, tactics, and detection methods found
- ASA verdict sampling and distribution
- User report processing details
- Message group filtering information

Debug logs are written to timestamped files in the `logs` directory, with both file and console output.