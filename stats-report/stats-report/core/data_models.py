"""
Core data models for the stats report generator.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Union, Literal, Any

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
class UserReport:
    """User report data."""
    reporter: str
    channel: str
    reported_at: datetime
    reported_by_message_id: str

@dataclass
class Message:
    """Individual message data."""
    id: str
    asa_verdict: Optional[str] = None

@dataclass
class MessageGroup:
    """Message group data from API or file."""
    id: str
    created_at: datetime
    attack_score_verdict: str
    classification: Optional[str]
    review_status: Optional[str]
    review_label: Optional[str]
    review_comment: Optional[str]
    subjects: List[str]
    sender_email_addresses: List[str]
    recipient_count: int
    message_count: int
    flagged_rules: List[Dict[str, Any]]  # Changed to Any since rule_meta has nested structure
    rule_severities: List[str]
    attack_types: List[str]  # From rule_meta.attack_types
    tactics_and_techniques: List[str]  # From rule_meta.tactics_and_techniques
    detection_methods: List[str]  # From rule_meta.detection_methods
    user_reports: List[UserReport]
    messages: List[Message]  # Individual messages in the group
    
    @property
    def asa_verdict(self) -> str:
        """
        Get the highest severity ASA verdict from all messages in the group.
        If no ASA verdicts are available, returns an empty string.
        """
        # Collect all non-empty ASA verdicts
        verdicts = [msg.asa_verdict for msg in self.messages if msg.asa_verdict]
        if not verdicts:
            return ""
            
        # Join verdicts with semicolons for deduplication
        verdict_str = ";".join(verdicts)
        
        # Define severity ranking (lower index = higher severity)
        severity_ranking = [
            'malicious',
            'spam', 
            'graymail',
            'benign',
            'likely_benign',
            'unknown'
        ]
        
        # Split and normalize verdicts
        all_verdicts = [v.strip().lower() for v in verdict_str.split(';') if v.strip()]
        if not all_verdicts:
            return ""
        
        # Find highest severity verdict
        highest_severity_index = float('inf')
        highest_verdict = ''
        
        for verdict in all_verdicts:
            try:
                severity_index = severity_ranking.index(verdict)
                if severity_index < highest_severity_index:
                    highest_severity_index = severity_index
                    highest_verdict = verdict
            except ValueError:
                # Unknown verdict type - treat as lowest priority
                if highest_severity_index == float('inf'):
                    highest_verdict = verdict
        
        return highest_verdict.capitalize() if highest_verdict else ""

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
