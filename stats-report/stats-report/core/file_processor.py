"""
File processor for handling CSV input files.
"""

import csv
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import aiofiles
import aiofiles.os

from .data_models import MessageGroup, OrgStats

logger = logging.getLogger(__name__)

class FileProcessingError(Exception):
    """Base exception for file processing errors."""
    pass

class CSVProcessor:
    """Processor for CSV input files."""
    
    REQUIRED_COLUMNS = {
        'created_at',
        'id',
        'attack_score_verdict',
        'classification',
        'review_status',
        'review_label',
        'review_comment',
        'subjects',
        'sender_email_addresses',
        'recipient_count',
        'message_count',
        'flagged_rules',
        'rule_severities'
    }
    
    def __init__(self, file_path: str):
        """
        Initialize the CSV processor.
        
        Args:
            file_path: Path to CSV file
        """
        self.file_path = Path(file_path)
    
    async def validate_file(self) -> Tuple[Set[str], int]:
        """
        Validate CSV file format and return column names.
        
        Returns:
            Tuple of (set of column names, total rows)
        
        Raises:
            FileProcessingError: If validation fails
        """
        if not self.file_path.exists():
            raise FileProcessingError(f"File not found: {self.file_path}")
        
        if self.file_path.suffix.lower() != '.csv':
            raise FileProcessingError(f"File must be a CSV file: {self.file_path}")
        
        try:
            async with aiofiles.open(self.file_path, mode='r', encoding='utf-8') as f:
                # Read header
                content = await f.read()
                lines = content.split('\n')
                if not lines:
                    raise FileProcessingError("CSV file is empty")
                
                reader = csv.DictReader(lines)
                if not reader.fieldnames:
                    raise FileProcessingError("CSV file has no headers")
                
                columns = set(reader.fieldnames)
                missing_columns = self.REQUIRED_COLUMNS - columns
                if missing_columns:
                    raise FileProcessingError(
                        f"Missing required columns: {', '.join(missing_columns)}"
                    )
                
                # Count rows
                total_rows = sum(1 for line in lines[1:] if line.strip())
                
                return columns, total_rows
                
        except (csv.Error, UnicodeDecodeError) as e:
            raise FileProcessingError(f"Error reading CSV file: {e}")
    
    async def process_file(self) -> Dict[str, any]:
        """
        Process CSV file and convert to MessageGroup objects.
        
        Returns:
            Dictionary containing message groups and org stats
        """
        columns, total_rows = await self.validate_file()
        logger.info(f"Processing {total_rows:,} rows from CSV file")
        
        message_groups: List[MessageGroup] = []
        messages_processed = 0
        active_mailboxes: Set[str] = set()
        active_rules: Set[str] = set()
        
        async with aiofiles.open(self.file_path, mode='r', encoding='utf-8') as f:
            content = await f.read()
            reader = csv.DictReader(content.splitlines())
            
            for row in reader:
                try:
                    # Extract and process rule information
                    flagged_rules = self._parse_rules(row.get('Flagged Rules', ''))
                    for rule in flagged_rules:
                        if rule.get('name'):
                            active_rules.add(rule['name'])
                    
                    # Create MessageGroup object
                    message_group = MessageGroup(
                        id=row.get('id', ''),
                        created_at=datetime.fromisoformat(
                            row['created_at'].replace('Z', '+00:00')
                        ) if row.get('created_at') else datetime.now(),
                        attack_score_verdict=row.get('attack_score_verdict', ''),
                        asa_verdict='',  # Not provided in original export
                        classification=row.get('classification', ''),
                        review_status=row.get('review_status', ''),
                        review_label=row.get('review_label', ''),
                        review_comment=row.get('review_comment', ''),
                        subjects=row.get('subjects', '').split(';') if row.get('subjects') else [],
                        sender_email_addresses=(
                            row.get('sender_email_addresses', '').split(';')
                            if row.get('sender_email_addresses') else []
                        ),
                        recipient_count=int(row.get('recipient_count', 0)),
                        message_count=int(row.get('message_count', 0)),
                        flagged_rules=self._parse_rules(row.get('flagged_rules', '')),
                        rule_severities=(
                            row.get('rule_severities', '').split(',')
                            if row.get('rule_severities') else []
                        )
                    )
                    
                    message_groups.append(message_group)
                    messages_processed += message_group.message_count
                    
                    # Track unique email addresses for mailbox count
                    if message_group.sender_email_addresses:
                        active_mailboxes.update(message_group.sender_email_addresses)
                    
                except (ValueError, KeyError) as e:
                    logger.warning(f"Error processing row: {e}")
                    continue
        
        # Create org stats
        org_stats = OrgStats(
            messages_processed_count=messages_processed,
            active_mailbox_count=len(active_mailboxes),
            active_detection_rule_count=len(active_rules)
        )
        
        logger.info(
            f"Processed {len(message_groups):,} message groups "
            f"with {messages_processed:,} total messages"
        )
        
        return {
            "message_groups": message_groups,
            "org_stats": org_stats
        }
    
    @staticmethod
    def _parse_rules(rules_str: str) -> List[Dict[str, str]]:
        """Parse rules string into list of rule dictionaries."""
        if not rules_str:
            return []
        
        try:
            # The original export stores this as a JSON string
            return json.loads(rules_str)
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse rules JSON: {rules_str}")
            return []
