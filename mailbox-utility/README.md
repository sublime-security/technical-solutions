# Mailbox Utility Script

A comprehensive Python utility for managing mailboxes in Sublime Security from the command line.

**Version:** 2026.06.01.1
**Last Updated:** June 1, 2026
**Recent Changes:**
- **📄 Per-Email Status Report**: Activate/deactivate operations now export a timestamped CSV listing each attempted email address and its outcome (`activated`/`deactivated` or `failed`). The report is written to disk only — the CLI just prints the filename
- **`--base-url`**: Non-interactive full API base URL for any region host (e.g. `https://na-east-4.platform.sublime.security`); mutually exclusive with `--region`
- **⚡ Enhanced Parallel Processing**: Optimized concurrent operations with intelligent worker scaling (5-15 workers based on dataset size)
- **📊 Performance Metrics**: Real-time throughput reporting (60-80+ mailboxes/sec) with detailed processing statistics
- **🔧 Improved Error Handling**: Better resilience for large-scale operations with comprehensive retry logic
- **🎯 Comprehensive Mailbox Management**: Complete lifecycle management for mailboxes (activate, deactivate, export, import)
- **🌍 Dynamic Region Discovery**: Automatically discovers new Sublime Security regions via DNS with fallback system
- **🛡️ Safety Features**: Multiple confirmation steps and warnings for dangerous deactivation operations
- **📊 CSV Operations**: Full import/export with 18 mailbox fields and flexible filtering options
- **🔄 HIP Integration**: Automated HIP job creation for newly activated mailboxes with 2000+ mailbox warnings
- **🎨 User Experience**: Interactive menu system with progress tracking and color-coded output

## Overview

The Mailbox Utility Script provides Sales Engineers and Detection Engineers with a comprehensive interface for managing mailboxes in Sublime Security. This script consolidates functionality from multiple tools into a single, powerful utility for complete mailbox lifecycle management.

## What's New in v2026.06.01.1 🆕

- **Per-Email Status Report**: After activating or deactivating mailboxes, the utility writes a timestamped CSV report capturing the specific email address attempted and its resulting status. Applies to *Activate All*, *Activate by Domain*, *Import CSV to Activate*, and *Deactivate by Domain*. The report is saved to the current directory and is **not** listed in the terminal (only the filename is shown).
  - **Filename format**: `mailbox_activate_status_YYYYMMDD_HHMMSS.csv` / `mailbox_deactivate_status_YYYYMMDD_HHMMSS.csv`
  - **Columns**: `email_address`, `id`, `status` (`activated`/`deactivated`/`failed`), `error`
  - **Note**: User-group activate/deactivate and *Mass Deactivate All* use a single bulk API call and do not return per-mailbox outcomes, so no per-email report is generated for those operations.

## What's New in v2026.04.15.1

- **`--base-url`**: Point the utility at any deployment URL (custom `{prefix}.platform.sublime.security` or other) without using the region menu

## What's New in v2025.10.21.1

- **Self-Contained Virtual Environment**: Automatic venv setup for isolated dependencies
- **Automatic Dependency Installation**: No manual pip install commands needed

## Previous Updates (v2025.10.16.1)

Latest version includes enhanced parallel processing and performance optimizations:

| Feature | Description | Benefit |
|---------|-------------|---------|
| **⚡ Smart Worker Scaling** | 5 workers (< 500), 10 workers (500-999), 15 workers (1000+) | Optimal performance for any dataset size |
| **📊 Real-Time Metrics** | Live throughput reporting (60-80+ mailboxes/sec) | Transparent performance monitoring |
| **🔧 Enhanced Resilience** | Improved error handling for large-scale operations | Better reliability in production environments |
| **🎯 Unified Management** | Single tool for all mailbox operations | Eliminates need for multiple scripts |
| **🔄 Batch Operations** | Activate/deactivate hundreds of mailboxes efficiently | Time-saving for large environments |
| **🌍 Dynamic Discovery** | DNS-based region discovery with smart sorting | Always finds the latest regions |
| **📊 Rich CSV Support** | 18-field export with flexible filtering options | Comprehensive mailbox data analysis |
| **🛡️ Safety First** | Triple confirmation for dangerous operations | Prevents accidental data loss |
| **⚡ HIP Integration** | Automated HIP job creation post-activation | Seamless workflow integration |
| **🎨 Professional UX** | Color-coded output, progress tracking, URL display | Enhanced user experience |

## Features

### Core Mailbox Operations
- **Activate All Mailboxes** - Bulk activation of all inactive mailboxes with progress tracking
- **Activate by Domain** - Selective activation based on email domains with multi-domain support
- **Export Mailboxes to CSV** - Comprehensive data export with multiple filtering options
- **Import CSV to Activate** - Bulk activation from CSV email lists with validation and reporting

### Advanced Deactivation (With Safety Features)
- **Deactivate by Domain** - Selective deactivation with double confirmation and impact warnings
- **Mass Deactivate All** - Emergency deactivation with triple confirmation system
- **Safety Warnings** - Clear messaging about email detection impact and appropriate use cases

### Integration & Automation
- **HIP Job Creation** - Automated Historical Ingestion Processing jobs for newly activated mailboxes
- **2000+ Mailbox Warnings** - Performance warnings and options for large activation sets
- **Dynamic Region Discovery** - Automatic detection of new Sublime Security regions
- **SSL Fallback** - Corporate firewall compatibility with automatic SSL handling

### User Experience
- **Interactive Menu System** - Professional menu with mailbox URL display
- **Progress Tracking** - Real-time updates for batch operations
- **Color-Coded Output** - Green (success), Red (errors), Yellow (warnings), Blue (info)
- **Comprehensive Error Handling** - Detailed API error display and graceful failure handling

## Prerequisites

- Python 3.8+ (tested up to Python 3.13)
- An active Sublime Security account with API access
- API key with appropriate permissions for mailbox and HIP management

### Required API Permissions
- **Mailboxes**: Read, activate, deactivate access
- **Message Sources**: Read access
- **Historical Ingestion**: Create jobs (for HIP integration)

## Installation

1. Clone or download this repository:
   ```bash
   git clone https://github.com/sublime-security/technical-solutions.git
   cd technical-solutions/mailbox-utility
   ```

2. Install required dependencies:
   ```bash
   pip install aiohttp tabulate
   ```

   Note: The script will attempt to install these automatically if missing.

3. For Python 3.13+, the script automatically handles SSL certificate verification:
   ```bash
   pip install certifi  # Installed automatically if needed
   ```

## Usage

### Interactive Mode

Run the script without parameters to use the interactive menu:

```bash
python mailbox-utility.py
```

This will:
1. Check for script updates (unless `--disable-auto-update`)
2. Discover available regions via DNS
3. Prompt for region selection
4. Ask for your API key (or use `SUBLIME_API_TOKEN` environment variable)
5. Present the main menu with options

### Command Line Mode

For direct access with specific options:

#### Specify region directly
```bash
python mailbox-utility.py --region na-east-2
```

#### Custom base URL (any host before `.sublime.security`, including new region prefixes)
Use the full API origin your browser would use for the tenant (HTTPS recommended):

```bash
python mailbox-utility.py --base-url https://na-east-4.platform.sublime.security
```

This is equivalent to choosing **Custom** in the interactive region list and pasting the same URL. You cannot combine `--base-url` with `--region`.

#### Enable debug mode for troubleshooting
```bash
python mailbox-utility.py --debug
```

#### Disable region discovery
```bash
python mailbox-utility.py --disable-region-lookup
```

#### Disable auto-updates
```bash
python mailbox-utility.py --disable-auto-update
```

### Options

| Option | Description |
|--------|-------------|
| `--region` | Specify region directly (na-east, na-east-2, na-east-3, na-west, na-west-2, canada, europe, uk, australia) |
| `--base-url` | Full API base URL (e.g. `https://eu.platform.sublime.security`); use for hosts not covered by `--region`. Mutually exclusive with `--region`. |
| `--debug` | Enable debug mode for detailed API logging and error information |
| `--disable-region-lookup` | Skip DNS discovery and use only hardcoded regions |
| `--disable-auto-update` | Skip automatic git pull update check at startup |
| `--help` | Show comprehensive help message and examples |

## Environment Variables

- `SUBLIME_API_TOKEN`: If set, the script will use this API key without prompting

## Main Menu Options

### 1. Activate All Mailboxes

Activates all currently inactive mailboxes in the selected message source.

**Process:**
- Displays count of inactive mailboxes
- Requests confirmation before activation
- Shows real-time progress during batch activation
- Provides success/failure summary
- Offers HIP job creation for newly activated mailboxes

**Example Output:**
```
Found 1,247 inactive mailboxes to activate.

Are you sure you want to activate all inactive mailboxes? (y/N): y

Activating mailboxes...
Activating mailbox 1247/1247: user@company.com

Activation Results:
  Successful: 1,247
  Failed: 0
  Status report: mailbox_activate_status_20260601_143022.csv
```

### 2. Activate by Domain

Selectively activate mailboxes based on email domains.

**Process:**
- Displays all domains with inactive mailbox counts
- Supports multi-domain selection
- Shows preview of mailboxes to be activated
- Batch activation with progress tracking
- HIP job creation offer

**Example Workflow:**
```
Available domains (showing inactive mailbox counts):
1. company.com - 856 inactive, 12 active
2. subsidiary.com - 234 inactive, 8 active
3. partner.org - 157 inactive, 45 active

Select domain numbers (comma-separated) or 'all': 1,2

Found 1,090 inactive mailboxes to activate from 2 domains.

Preview (first 10 mailboxes):
  • user1@company.com
  • user2@company.com
  ...
```

### 3. Export Mailboxes to CSV

Export mailbox data to CSV with comprehensive field coverage and filtering options.

**Export Options:**
1. **All mailboxes** - Complete mailbox dataset
2. **Active mailboxes only** - Currently active mailboxes
3. **Inactive mailboxes only** - Currently inactive mailboxes
4. **Mailboxes by domain** - Filtered by specific domain

**CSV Fields (18 total):**
`active`, `created_at`, `display_name`, `email_address`, `external_created_at`, `external_id`, `external_subscription_error_status`, `first_name`, `full_name`, `has_unresolved_errors`, `id`, `is_external_admin`, `last_name`, `license_activated_at`, `marked_active`, `message_source_id`, `message_source_type`, `org_id`

**Generated Filename Format:**
- `mailboxes_all_20251003_143022.csv`
- `mailboxes_active_20251003_143022.csv`
- `mailboxes_domain_company_com_20251003_143022.csv`

### 4. Import CSV to Activate

Activate mailboxes from a CSV file containing email addresses.

**Process:**
- Reads email addresses from any column in the CSV
- Automatically detects and skips header rows
- Validates emails against existing mailboxes
- Reports found/not found/already active status
- Batch activation with progress tracking

**CSV Format Flexibility & Performance:**

The CSV import feature is designed to be extremely flexible and handle large datasets efficiently:

**📁 Supported CSV Formats:**
- **Any CSV format** - Standard comma-separated files (.csv)
- **Universal column support** - Email addresses detected in ANY column
- **Automatic header detection** - Intelligently skips header rows if present
- **Mixed content support** - Processes rows with emails in different columns
- **Multiple emails per row** - Extracts all valid email addresses found
- **Encoding support** - UTF-8 encoding with automatic handling

**⚡ Performance & Parallel Processing:**

For optimal performance with large CSV files:

| Dataset Size | Worker Count | Expected Performance | Features |
|--------------|-------------|---------------------|----------|
| < 100 mailboxes | 5 workers | ~25 mailboxes/sec | Conservative processing |
| 100-499 mailboxes | 8 workers | ~40 mailboxes/sec | Balanced approach |
| 500-999 mailboxes | 10 workers | ~60 mailboxes/sec | Standard parallel processing |
| 1000+ mailboxes | 15 workers | ~80+ mailboxes/sec | Aggressive parallel processing |

**🔄 Dynamic Rate Limiting Management:**
- **Automatic detection** of API rate limiting (429 errors)
- **Dynamic worker reduction** when rate limits are hit (15→8→5→3→1)
- **Smart retry system** with exponential backoff for failed activations
- **Worker scale-up** on sustained success (gradually increases workers)
- **Real-time progress tracking** with live worker count and rate display

**📊 Example CSV Formats Supported:**

```csv
# Format 1: Email in first column with header
Email,Name,Department
john@company.com,John Smith,IT
jane@company.com,Jane Doe,HR

# Format 2: Mixed columns, no header
Sales Team,alice@company.com,Manager,Active
bob@company.com,Developer,Engineering,True

# Format 3: Multiple emails per row
user1@company.com,user2@company.com,team@company.com
```

**🔍 Analysis & Reporting:**
```
Large dataset detected (2,341 mailboxes), using up to 15 workers

Activating mailboxes in parallel...
Starting with 15 workers for 2,341 mailboxes
Activating 2341/2341 mailboxes (12 workers, 67.3/sec)

Parallel Activation Results:
  Successful: 2,334
  Failed: 7
  Retries: 23
  Rate limit events: 3
  Total time: 34.7s
  Average rate: 67.4 mailboxes/sec
  Status report: mailbox_activate_status_20260601_143022.csv

Import Analysis:
  Emails in CSV: 2,500
  Found and inactive: 2,341
  Already active: 152
  Not found: 7

Emails not found in system:
  • olduser@company.com
  • contractor@external.com
  ...
```

**⚠️ Large Dataset Recommendations:**

For optimal performance with large CSV imports (1000+ mailboxes):
- **File preparation**: Use simple CSV format with minimal columns for faster parsing
- **Network considerations**: Run from a stable network connection to minimize retry overhead
- **API permissions**: Ensure your API key has sufficient rate limits for parallel processing
- **Monitoring**: Watch the real-time progress display for performance insights and rate limiting events

### 5. Start HIP for Mailboxes

Create Historical Ingestion Processing (HIP) jobs for active mailboxes to retroactively analyze historical emails.

**Process:**
- Select from active mailboxes in the current message source
- Configure HIP job parameters (mode, days back)
- Automatic handling for large mailbox sets (2000+)
- Job creation with progress tracking

**Example:**
```
Found 1,247 active mailboxes.

Create HIP job for all active mailboxes? (y/N): y

HIP Job Configuration:
  Mode: HISTORICALLY_MATCH
  Mailboxes: 1,247 active
  Days back: 90

✓ HIP job created successfully!
  Job ID: hip_abc123...
```

### 6. Activate Mailboxes by User Group

Activate all mailboxes belonging to a specific user group using progressive search.

**Progressive Search Features:**
- **Real-time Filtering**: Type to search through groups instantly
- **Keyboard Navigation**: Press 1-10 to select from top results, Enter for first match
- **Live Results**: See matching groups update as you type
- **Smart Matching**: Prioritizes exact name matches, then substring matches
- **Member Count Display**: Shows number of members and group status

**Process:**
1. Progressive search interface displays available groups
2. Type to filter groups by name
3. Select group using number keys (1-10) or Enter
4. Preview group details (name, member count, status)
5. Confirm activation
6. Batch activation of all group members
7. Optional HIP job creation

**Example Workflow:**
```
=== Activate Mailboxes by User Group ===
Start typing to search through 45 available groups...

Search groups: sales

Live Results (8 matches):
  1. Sales Team (234 members) - Inactive
  2. Sales Leadership (12 members) - Active
  3. Sales EMEA (89 members) - Inactive
  ...

Press 1-10 to select, Enter for first match, ESC to cancel, or continue typing...

[User presses 1]

Group Preview:
  Name: Sales Team
  Members: 234 mailboxes
  Status: Inactive
  Description: All sales department members

Activate Sales Team with 234 members? (y/N): y

Activating user group...

✓ Group Activation Successful!
  Group: Sales Team
  Activated: 234 mailboxes
```

**Features:**
- Filtered by selected message source (client-side)
- Only shows groups for current message source
- Progressive search with real-time results
- Keyboard-driven interface for efficiency
- Batch activation with single API call
- HIP job creation offer for activated mailboxes

### 7. Deactivate Specific Mailboxes by Domain ⚠️

**CAUTION:** This feature includes extensive warnings about the impact on email detection.

**Safety Features:**
- **Warning Messages**: Clear explanation of email detection impact
- **Use Case Guidance**: Explains appropriate scenarios (incidents, POC setup, before Live Flow)
- **Double Confirmation**: Two separate confirmation prompts
- **Typed Confirmation**: Must type "DEACTIVATE" to proceed
- **Domain Selection**: Only shows domains with active mailboxes

**Appropriate Use Cases:**
- **Security Incidents**: Temporarily disable compromised accounts
- **POC Setup**: Prepare environment for proof-of-concept testing
- **Live Flow Migration**: Deactivate before configuring Live Flow

**Process:**
```
⚠️  WARNING: Deactivating mailboxes should only be used in rare cases
(incidents, POC setup, before Live Flow) and will impact email detection.

Domains with active mailboxes:
1. company.com - 856 active mailboxes

This will deactivate 856 mailboxes from domain: company.com
This will impact email detection for these users.

Are you sure you want to deactivate 856 mailboxes from company.com? (y/N): y
Type DEACTIVATE to confirm this operation:
DEACTIVATE
```

### 8. Deactivate Mailboxes by User Group ⚠️

Deactivate mailboxes belonging to a specific user group with extensive safety warnings and confirmations.

**IMPORTANT:** Deactivating a user group will only deactivate mailboxes that are NOT members of other active groups. This prevents accidentally deactivating mailboxes with multiple group memberships.

**Progressive Search Interface:**
- Same progressive search as Option 6 (Activate by User Group)
- Real-time filtering and keyboard navigation
- Displays member count and current status

**Safety Features:**
- **Initial Warning**: Detailed explanation of impact before search begins
- **Use Case Guidance**: Clarifies appropriate scenarios for group deactivation
- **Impact Assessment**: Shows potential number of mailboxes affected
- **Double Confirmation**: Two separate confirmation prompts required
- **Typed Confirmation**: Must type "DEACTIVATE GROUP" to proceed
- **Smart Deactivation**: Only deactivates mailboxes not in other active groups

**Appropriate Use Cases:**
- **Security Incidents**: Group-level isolation for compromised accounts
- **POC Setup**: Preparing test environments
- **Organizational Changes**: Department or team deactivation
- **Live Flow Migration**: Pre-configuration cleanup

**Example Workflow:**
```
⚠️  WARNING: Group Deactivation Impact
Deactivating a user group will deactivate member mailboxes that are not
members of other active groups. This will impact email detection.

Appropriate use cases:
  • Security incidents requiring group-level isolation
  • POC setup and testing scenarios
  • Organizational changes (department deactivation)
  • Before Live Flow configuration

Do you want to proceed with group deactivation? (y/N): y

=== Deactivate Mailboxes by User Group ===
Start typing to search through 45 available groups...

Search groups: contractors

[User selects "External Contractors" group]

Group Deactivation Preview:
  Name: External Contractors
  Members: 89 mailboxes
  Current Status: Active
  Description: Third-party contractor accounts

⚠️  IMPACT ASSESSMENT:
  • Up to 89 mailboxes may be deactivated
  • Mailboxes in other active groups will remain active
  • Email detection will be impacted for deactivated mailboxes
  • This action affects group-level mail processing

This will deactivate the "External Contractors" group. Continue? (y/N): y

Type "DEACTIVATE GROUP" to confirm this operation: DEACTIVATE GROUP

Deactivating user group...

✓ Group Deactivation Completed!
  Group: External Contractors
  Processed: 89 mailboxes

Note: Only mailboxes not in other active groups were deactivated.
```

**Features:**
- Filtered by selected message source
- Progressive search with real-time filtering
- Detailed impact assessment before execution
- Protection for multi-group memberships
- Comprehensive safety confirmations

### 9. Deactivate All Mailboxes (Dangerous) 🚨

**EXTREME CAUTION:** This is the most dangerous operation with maximum safety measures.

**Safety Features:**
- **Triple Confirmation System**: Three separate confirmation steps
- **Danger Warnings**: Multiple warnings about severe impact
- **Typed Confirmation**: Must type "MASS DEACTIVATE" to proceed
- **Count Display**: Shows total active mailboxes that will be affected
- **Use Case Restrictions**: Clearly limited to emergencies and setup

**Message Source Handling:**
- **Single Message Source**: Uses `"all_message_sources": true`
- **Multiple Message Sources**: Uses `"all_message_sources": false` with specific message source ID

**Triple Confirmation Process:**
```
🚨 DANGER: This will deactivate ALL mailboxes and severely impact email detection!
This should ONLY be used for incidents, POC setup, or before Live Flow configuration.

This will deactivate 2,341 active mailboxes.

Are you sure you want to deactivate ALL mailboxes? This will severely impact email detection! (y/N): y
This is a dangerous operation that should only be used for incidents or POC setup. Continue? (y/N): y
Type MASS DEACTIVATE to confirm this dangerous operation:
MASS DEACTIVATE
```

### 10. Switch Message Source

Switch between different message sources without restarting the script (only displayed when multiple message sources are available).

**Purpose:**
Allows seamless switching between different email integrations (Microsoft 365, Google Workspace, etc.) in multi-source tenants without restarting the application.

**Features:**
- **Conditional Display**: Only shown when organization has multiple message sources
- **Current Source Display**: Menu shows currently selected message source
- **Cache Clearing**: Automatically clears all cached data on switch
  - Mailbox data
  - Domain information
  - User group cache
- **Confirmation Required**: Prompts for confirmation before switching
- **Immediate Effect**: All subsequent operations use the new message source

**Process:**
1. Displays current message source
2. Lists all available message sources in the organization
3. User selects new source by number
4. Confirmation prompt explains cache will be cleared
5. Switch occurs and cached data is invalidated
6. Returns to main menu with new message source active

**Example Workflow:**
```
=== Switch Message Source ===
Current message source: Microsoft 365 Production

Available message sources:
1. Microsoft 365 Production (microsoft) - msg_abc123... (current)
2. Google Workspace (google) - msg_def456...
3. Microsoft 365 Test (microsoft) - msg_ghi789...

Select message source (1-3, or press Enter to cancel): 2

Switch to Google Workspace? This will clear cached data. (y/N): y

✓ Switched to: Google Workspace
Note: Mailbox and group data will be fetched when needed.
```

**Use Cases:**
- **Multi-tenant Management**: Switch between production and test environments
- **Multiple Email Platforms**: Manage both Microsoft 365 and Google Workspace
- **POC Demonstrations**: Quickly switch between different customer environments
- **Troubleshooting**: Compare behavior across different message sources

**Technical Notes:**
- All cached data is cleared to prevent cross-source contamination
- Group searches will be filtered to the newly selected message source
- Mailbox counts and domain data will be re-fetched on next use
- Message source ID is used for all API calls after switch

### 11. Exit

Cleanly exits the application with a farewell message.

## HIP Integration

After successful mailbox activation, the script offers to create Historical Ingestion Processing (HIP) jobs.

### Automatic HIP Job Creation

**Process:**
- **Post-Activation Prompt**: Asks if you want to create HIP job for newly activated mailboxes
- **2000+ Mailbox Warning**: Special handling for large activation sets
- **Job Configuration**: Uses `HISTORICALLY_MATCH` mode with `active_mailboxes_only: true`

### Large Activation Warning (2000+)

For activations over 2000 mailboxes:
```
⚠️  WARNING: You activated more than 2,000 mailboxes!
Processing all mailboxes in a single HIP job may impact system performance.

Options:
1. Create HIP job for all 2,341 activated mailboxes
2. Create HIP job for a specific number of mailboxes
3. Skip HIP job creation
```

### HIP Job Parameters

```json
{
  "message_source_id": "selected-message-source-id",
  "mode": "HISTORICALLY_MATCH",
  "active_mailboxes_only": true
}
```

## User Interface Features

### URL Display

Above every menu, the script displays the direct URL to view mailboxes:
```
View Mailboxes: https://na-east-2.platform.sublime.security/mailboxes
```

### Progress Tracking

All batch operations show real-time progress:
```
Activating mailboxes...
Activating mailbox 1247/1247: user@company.com
```

### Color-Coded Output

- **🟢 Green**: Success messages and active counts
- **🔴 Red**: Errors and dangerous operations
- **🟡 Yellow**: Warnings and inactive counts
- **🔵 Blue**: Information and prompts
- **⚪ Gray**: Disabled or deleted items

### Error Handling

Comprehensive error display for API issues:
```
API Error Details:
  Method: POST
  Endpoint: v1/mailboxes/123/activate
  Error: 404 Not Found
  Response: {
    "error": {
      "message": "Mailbox not found"
    }
  }
```

## Troubleshooting

### Common Issues

1. **SSL Certificate Errors (Corporate Environments)**
   - The script automatically handles SSL fallback for Python 3.13+
   - For older versions, use `--debug` to see detailed SSL information

2. **API Permission Errors**
   - Ensure your API key has mailbox management permissions
   - Check message source access permissions

3. **Large Dataset Performance**
   - Script uses pagination (500 mailboxes per request) for efficiency
   - Progress tracking helps monitor large operations
   - Parallel processing automatically scales workers based on dataset size

4. **CSV Import Issues**
   - See detailed CSV import troubleshooting section below

4. **Region Discovery Issues**
   - Use `--disable-region-lookup` to use hardcoded regions
   - Use `--debug` to see detailed region discovery output

### Debug Mode

Use `--debug` for detailed troubleshooting information:

```bash
python mailbox-utility.py --debug
```

This enables:
- Full API request/response logging
- Detailed error information
- Region discovery debugging
- SSL troubleshooting information

### API Error Handling

The script provides comprehensive API error handling:
- **404 Errors**: No retry delays for deleted resources
- **Rate Limiting**: Automatic backoff for 429 errors
- **Network Issues**: Retry logic with exponential backoff
- **SSL Issues**: Automatic fallback for corporate environments

### Large CSV Import Troubleshooting

**Performance Issues:**

1. **Slow Processing Speed**
   - **Problem**: CSV activation taking longer than expected
   - **Solution**: Enable debug mode to see worker count and rate information:
     ```bash
     python mailbox-utility.py --debug
     ```
   - **Expected Rates**: 25-80+ mailboxes/sec depending on dataset size
   - **Check**: Network stability and API key rate limits

2. **Rate Limiting Encountered**
   - **Symptoms**: "Rate limiting detected, reducing to X workers" messages
   - **Normal Behavior**: Script automatically handles this by:
     - Reducing worker count dynamically
     - Implementing exponential backoff
     - Retrying failed mailboxes automatically
   - **Best Practice**: Let the script handle rate limiting automatically

3. **High Failure Rate**
   - **Causes**: Network issues, invalid mailbox IDs, or API connectivity problems
   - **Debug Steps**:
     ```bash
     python mailbox-utility.py --debug
     ```
   - **Check**: API error details in debug output for specific failure reasons

**CSV Format Issues:**

4. **No Emails Detected in CSV**
   - **Problem**: "Found 0 unique email addresses in CSV"
   - **Causes**:
     - File not in CSV format
     - Emails in unexpected format (no @ symbol or domain)
     - Encoding issues
   - **Solutions**:
     - Verify file is saved as .csv format
     - Check that emails contain @ and domain (e.g., user@company.com)
     - Try UTF-8 encoding if special characters are present

5. **Fewer Emails Than Expected**
   - **Problem**: CSV contains more rows than emails detected
   - **Causes**:
     - Header rows being processed incorrectly
     - Non-email data in columns
     - Duplicate email addresses (automatically deduplicated)
   - **Solution**: Check CSV format - script automatically handles headers and duplicates

6. **Large CSV File Parsing Slow**
   - **Problem**: Initial CSV reading takes a long time
   - **Optimization**: For files >10MB, consider:
     - Removing unnecessary columns
     - Breaking into smaller batches
     - Using simpler CSV format with just email addresses

**Retry and Recovery:**

7. **Handling Interrupted Processing**
   - **Problem**: Script stopped or network disconnection during processing
   - **Recovery**: Re-run the import - script will:
     - Skip already active mailboxes automatically
     - Only process remaining inactive mailboxes
     - Display updated counts in analysis

8. **Partial Success Scenarios**
   - **Understanding Results**:
     ```
     Parallel Activation Results:
       Successful: 2,334
       Failed: 7        ← Permanent failures (404 errors, etc.)
       Retries: 23      ← Temporary failures that were retried
       Rate limit events: 3  ← Times rate limiting was encountered
     ```
   - **Action**: Failed mailboxes are typically not found in system - check "Emails not found" list

**Optimization Tips:**

9. **Maximum Performance Setup**
   - **Network**: Stable, high-bandwidth connection
   - **CSV Format**: Simple format with minimal columns:
     ```csv
     user1@company.com
     user2@company.com
     user3@company.com
     ```
   - **File Size**: Process in batches of 1000-5000 for optimal performance
   - **Timing**: Run during off-peak hours to minimize rate limiting

10. **Monitoring Large Operations**
    - **Real-time Monitoring**: Watch for these indicators:
      ```
      Activating 1247/5000 mailboxes (8 workers, 45.2/sec)
      ```
    - **Healthy Signs**: Steady rate, stable worker count
    - **Concerning Signs**: Frequent worker reductions, very low rates (<10/sec)
    - **Action**: If performance is consistently poor, check network and API key limits

## Safety Considerations

### Deactivation Operations

**Think Twice Before Deactivating:**
- Deactivation **stops email analysis** for affected users
- Only appropriate for **incidents**, **POC setup**, or **before Live Flow configuration**
- **Not reversible** through this script (requires manual reactivation)

### Appropriate Use Cases for Deactivation

1. **Security Incidents**
   - Compromised accounts need immediate isolation
   - Suspected insider threats
   - Malware containment scenarios

2. **POC Environment Setup**
   - Clean slate for demonstration purposes
   - Testing specific user subsets
   - Performance testing scenarios

3. **Live Flow Migration**
   - Preparing to switch to Live Flow configuration
   - Avoiding duplicate processing during transition

### Inappropriate Use Cases

❌ **DO NOT** deactivate mailboxes for:
- Regular user offboarding (use proper account management)
- Performance troubleshooting (investigate root cause)
- Storage space concerns (contact support)
- Testing purposes in production environments

## Version History

### v2025.10.03.1 (Initial Release)
- Comprehensive mailbox management functionality
- Dynamic region discovery with DNS lookup
- All activation and deactivation operations
- CSV import/export with 18 fields
- HIP integration with 2000+ warnings
- Triple safety confirmation system
- Interactive menu with URL display
- Async performance optimization
- SSL fallback for corporate environments

## Security Notes

- **API Key Handling**: Never logged or stored by the script
- **Environment Variables**: Use `SUBLIME_API_TOKEN` for secure automation
- **Operation Logging**: All operations are logged for audit purposes
- **Permission Validation**: Script validates API permissions before operations

## Support

For questions or issues:
1. Use `--debug` mode for detailed troubleshooting information
2. Check API permissions and network connectivity
3. Review the troubleshooting section in this README
4. Contact the Sublime Security team for platform-specific issues

## License

This tool is provided for use with Sublime Security platforms and is subject to your Sublime Security license agreement.