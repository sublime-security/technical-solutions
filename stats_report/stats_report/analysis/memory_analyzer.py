"""
Memory-based implementation of the message analyzer.
"""

from collections import Counter, defaultdict
import logging
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

from .base import (
    BaseAnalyzer, AttackTypeAnalysis, TacticAnalysis,
    DetectionMethodAnalysis, TopSenderAnalysis, TopEmailAnalysis,
    UserReportAnalysis, AccuracyAnalysis
)
from ..core.data_models import MessageGroup, OrgStats, ReportConfig

class MemoryAnalyzer(BaseAnalyzer):
    """In-memory implementation of message analysis."""
    
    def __init__(self, config: ReportConfig):
        """Initialize the memory analyzer."""
        super().__init__(config)
        self.message_groups: List[MessageGroup] = []
        self.org_stats: Optional[OrgStats] = None
        
        # Analysis caches
        self._malicious_messages: Optional[List[MessageGroup]] = None
        self._user_reported_messages: Optional[List[MessageGroup]] = None
        self._total_malicious_count: Optional[int] = None
        self._total_user_reported_count: Optional[int] = None
    
    async def process_data(
        self,
        message_groups: List[MessageGroup],
        org_stats: OrgStats
    ) -> None:
        """Process and store message data in memory."""
        logger.debug(f"Processing {len(message_groups)} message groups")
        logger.info(f"Analysis configuration: Attack Score verdict for flagged messages, {self.config.verdict_type} for user reports")
        
        # Log a sample message to see its structure
        if message_groups:
            sample = message_groups[0]
            logger.debug(f"Sample message fields: attack_score_verdict={sample.attack_score_verdict}, asa_verdict={sample.asa_verdict}")
        
        self.message_groups = message_groups
        self.org_stats = org_stats
        
        # Reset caches
        self._malicious_messages = None
        self._user_reported_messages = None
        self._total_malicious_count = None
        self._total_user_reported_count = None
    
    def _get_malicious_messages(self) -> List[MessageGroup]:
        """
        Get cached list of malicious messages based on Attack Score verdict.
        Note: This always uses attack_score_verdict regardless of ASA configuration,
        as ASA verdicts are only used for user report analysis.
        """
        if self._malicious_messages is None:
            # Always use attack_score_verdict for malicious message stats
            logger.debug("Looking for malicious messages using attack_score_verdict")
            logger.debug(f"Processing {len(self.message_groups)} total messages")
            
            self._malicious_messages = []
            verdict_counts = {}
            
            for msg in self.message_groups:
                verdict = getattr(msg, "attack_score_verdict", None)
                if verdict:
                    verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
                if verdict and verdict.lower() == "malicious":
                    self._malicious_messages.append(msg)
            
            logger.debug(f"Found verdicts: {verdict_counts}")
            logger.debug(f"Found {len(self._malicious_messages)} malicious messages")
        return self._malicious_messages
    
    def _get_user_reported_messages(self) -> List[MessageGroup]:
        """Get cached list of user reported messages."""
        if self._user_reported_messages is None:
            self._user_reported_messages = [
                msg for msg in self.message_groups
                if msg.review_status  # Messages with review status are user-reported
            ]
        return self._user_reported_messages
    
    def _get_total_malicious_count(self) -> int:
        """Get cached total count of malicious messages."""
        if self._total_malicious_count is None:
            self._total_malicious_count = sum(
                msg.message_count for msg in self._get_malicious_messages()
            )
        return self._total_malicious_count
    
    def _get_total_user_reported_count(self) -> int:
        """Get cached total count of user reported messages."""
        if self._total_user_reported_count is None:
            self._total_user_reported_count = sum(
                msg.message_count for msg in self._get_user_reported_messages()
            )
        return self._total_user_reported_count
    
    async def get_attack_types(self) -> List[AttackTypeAnalysis]:
        """Analyze attack types from malicious messages."""
        malicious_messages = self._get_malicious_messages()
        total_messages = self._get_total_malicious_count()
        
        # Count attack types
        type_groups: Dict[str, Set[str]] = defaultdict(set)
        type_counts: Dict[str, int] = defaultdict(int)
        
        for msg in malicious_messages:
            for rule in msg.flagged_rules:
                if rule.get("name"):
                    attack_type = rule["name"]
                    type_groups[attack_type].add(msg.id)
                    type_counts[attack_type] += msg.message_count
        
        # Convert to analysis objects
        return [
            AttackTypeAnalysis(
                attack_type=attack_type,
                message_groups=len(groups),
                total_individual_messages=type_counts[attack_type],
                percentage_of_total=self.calculate_percentage(
                    type_counts[attack_type], total_messages
                )
            )
            for attack_type, groups in type_groups.items()
        ]
    
    async def get_tactics(self) -> List[TacticAnalysis]:
        """Analyze tactics from malicious messages."""
        malicious_messages = self._get_malicious_messages()
        total_messages = self._get_total_malicious_count()
        
        # Count tactics
        tactic_groups: Dict[str, Set[str]] = defaultdict(set)
        tactic_counts: Dict[str, int] = defaultdict(int)
        
        for msg in malicious_messages:
            for rule in msg.flagged_rules:
                if rule.get("name"):
                    tactic_groups[rule["name"]].add(msg.id)
                    tactic_counts[rule["name"]] += msg.message_count
        
        # Convert to analysis objects
        return [
            TacticAnalysis(
                tactic=tactic,
                message_groups=len(groups),
                total_individual_messages=tactic_counts[tactic],
                percentage_of_total=self.calculate_percentage(
                    tactic_counts[tactic], total_messages
                )
            )
            for tactic, groups in tactic_groups.items()
        ]
    
    async def get_detection_methods(self) -> List[DetectionMethodAnalysis]:
        """Analyze detection methods from malicious messages."""
        malicious_messages = self._get_malicious_messages()
        total_messages = self._get_total_malicious_count()
        
        # Count detection methods
        method_groups: Dict[str, Set[str]] = defaultdict(set)
        method_counts: Dict[str, int] = defaultdict(int)
        
        for msg in malicious_messages:
            for rule in msg.flagged_rules:
                severity = rule.get("severity", "unknown")
                method_groups[severity].add(msg.id)
                method_counts[severity] += msg.message_count
        
        # Convert to analysis objects
        return [
            DetectionMethodAnalysis(
                detection_method=method,
                message_groups=len(groups),
                total_individual_messages=method_counts[method],
                percentage_of_total=self.calculate_percentage(
                    method_counts[method], total_messages
                )
            )
            for method, groups in method_groups.items()
        ]
    
    async def get_top_senders(self, limit: int = 10) -> List[TopSenderAnalysis]:
        """Analyze top sender domains from malicious messages."""
        malicious_messages = self._get_malicious_messages()
        total_messages = self._get_total_malicious_count()
        
        # Count sender domains
        domain_groups: Dict[str, Set[str]] = defaultdict(set)
        domain_counts: Dict[str, int] = defaultdict(int)
        
        for msg in malicious_messages:
            for sender in msg.sender_email_addresses:
                domain = self.extract_domain(sender)
                domain_groups[domain].add(msg.id)
                domain_counts[domain] += msg.message_count
        
        # Sort and limit results
        top_domains = sorted(
            domain_groups.keys(),
            key=lambda d: (domain_counts[d], len(domain_groups[d])),
            reverse=True
        )[:limit]
        
        # Convert to analysis objects
        return [
            TopSenderAnalysis(
                domain=domain,
                message_groups=len(domain_groups[domain]),
                total_individual_messages=domain_counts[domain],
                percentage_of_total=self.calculate_percentage(
                    domain_counts[domain], total_messages
                )
            )
            for domain in top_domains
        ]
    
    async def get_top_emails(self, limit: int = 10) -> List[TopEmailAnalysis]:
        """Analyze top individual emails by message count."""
        malicious_messages = self._get_malicious_messages()
        
        # Sort messages by count and limit results
        top_messages = sorted(
            malicious_messages,
            key=lambda m: m.message_count,
            reverse=True
        )[:limit]
        
        # Convert to analysis objects
        return [
            TopEmailAnalysis(
                received_datetime=msg.created_at,
                subject=msg.subjects[0] if msg.subjects else "",
                sender_email=msg.sender_email_addresses[0] if msg.sender_email_addresses else "",
                url="",  # TODO: Add URL field to MessageGroup if needed
                total_messages=msg.message_count
            )
            for msg in top_messages
        ]
    
    async def get_user_reports(self) -> List[UserReportAnalysis]:
        """Analyze user reported messages."""
        logger.debug(f"Analyzing user reports using {self.config.verdict_type}")
        user_messages = self._get_user_reported_messages()
        total_messages = self._get_total_user_reported_count()
        
        # Group by reporter
        reporter_groups: Dict[str, List[MessageGroup]] = defaultdict(list)
        for msg in user_messages:
            if msg.review_status:  # Only include messages with review status
                reporter_groups[msg.review_status].append(msg)
        
        # Calculate effectiveness for each reporter
        results = []
        for reporter, messages in reporter_groups.items():
            total_reporter_messages = sum(msg.message_count for msg in messages)
            
            # Calculate verdict distributions
            verdict_counts: Dict[str, int] = defaultdict(int)
            for msg in messages:
                            verdict = self.get_verdict(msg, self.config.verdict_type == "ASA Verdict")
            if verdict:  # Only count if we have a verdict
                verdict_counts[verdict.lower()] += msg.message_count
            
            # Calculate percentages
            effectiveness = {
                verdict: self.calculate_percentage(count, total_reporter_messages)
                for verdict, count in verdict_counts.items()
            }
            
            results.append(UserReportAnalysis(
                reporter_email=reporter,
                report_groups=len(messages),
                total_reported_messages=total_reporter_messages,
                percentage_of_total=self.calculate_percentage(
                    total_reporter_messages, total_messages
                ),
                effectiveness=effectiveness
            ))
        
        return sorted(results, key=lambda x: x.total_reported_messages, reverse=True)
    
    async def get_accuracy_analysis(self) -> AccuracyAnalysis:
        """Analyze attack score accuracy."""
        # Filter messages with both verdicts
        messages_with_both = [
            msg for msg in self.message_groups
            if msg.attack_score_verdict and msg.classification
        ]
        
        total_messages = len(messages_with_both)
        
        # Count agreements
        agreements = sum(
            1 for msg in messages_with_both
            if msg.attack_score_verdict.lower() == msg.classification.lower()
        )
        
        # Analyze overrides
        overrides = defaultdict(lambda: defaultdict(int))
        for msg in messages_with_both:
            if msg.attack_score_verdict.lower() != msg.classification.lower():
                overrides[msg.attack_score_verdict][msg.classification] += 1
        
        # Convert overrides to list format
        override_list = [
            {
                "attack_score_verdict": asv,
                "customer_classification": cc,
                "count": count,
                "percentage": self.calculate_percentage(count, total_messages)
            }
            for asv, classifications in overrides.items()
            for cc, count in classifications.items()
        ]
        
        return AccuracyAnalysis(
            total_messages=total_messages,
            agreement_count=agreements,
            accuracy_rate=self.calculate_percentage(agreements, total_messages),
            classification_overrides=sorted(
                override_list,
                key=lambda x: x["count"],
                reverse=True
            )
        )
