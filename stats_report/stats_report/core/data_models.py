"""
Core data models for the stats report generator.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Union, Literal

VerdictType = Literal["ASA Verdict", "Attack Score Verdict"]
StorageType = Literal["memory", "sqlite"]
OutputFormat = Literal["json", "markdown", "csv"]

@dataclass
class OrgStats:
    """Organization statistics."""
    messages_processed_count: int
    active_mailbox_count: int
    active_detection_rule_count: int

@dataclass
class DateRange:
    """Date range for report data."""
    start: datetime
    end: datetime

@dataclass
class MessageGroup:
    """Message group data from API or file."""
    id: str
    created_at: datetime
    attack_score_verdict: str
    asa_verdict: Optional[str]
    classification: Optional[str]
    review_status: Optional[str]
    review_label: Optional[str]
    review_comment: Optional[str]
    subjects: List[str]
    sender_email_addresses: List[str]
    recipient_count: int
    message_count: int
    flagged_rules: List[Dict[str, str]]
    rule_severities: List[str]

@dataclass
class ReportConfig:
    """Configuration for report generation."""
    verdict_type: VerdictType
    storage_type: StorageType
    output_format: OutputFormat
    date_range: DateRange
    output_file: Optional[str] = None

@dataclass
class ReportData:
    """Container for all data needed to generate a report."""
    org_stats: OrgStats
    message_groups: List[MessageGroup]
    config: ReportConfig
