"""
Base analyzer interface and common analysis functionality.
"""

from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any, TypeVar, Generic

from ..core.data_models import MessageGroup, OrgStats, ReportConfig

T = TypeVar('T')

@dataclass
class AnalysisResult(Generic[T]):
    """Container for analysis results."""
    total_count: int
    items: List[T]
    percentage: float

@dataclass
class AttackTypeAnalysis:
    """Analysis of attack types."""
    attack_type: str
    message_groups: int
    total_individual_messages: int
    percentage_of_total: float

@dataclass
class TacticAnalysis:
    """Analysis of tactics and techniques."""
    tactic: str
    message_groups: int
    total_individual_messages: int
    percentage_of_total: float

@dataclass
class DetectionMethodAnalysis:
    """Analysis of detection methods."""
    detection_method: str
    message_groups: int
    total_individual_messages: int
    percentage_of_total: float

@dataclass
class TopSenderAnalysis:
    """Analysis of top senders."""
    domain: str
    message_groups: int
    total_individual_messages: int
    percentage_of_total: float

@dataclass
class TopEmailAnalysis:
    """Analysis of top emails."""
    received_datetime: datetime
    subject: str
    sender_email: str
    url: str
    total_messages: int

@dataclass
class UserReportAnalysis:
    """Analysis of user reports."""
    reporter_email: str
    report_groups: int
    total_reported_messages: int
    percentage_of_total: float
    effectiveness: Dict[str, float]  # Verdict type -> percentage

@dataclass
class AccuracyAnalysis:
    """Analysis of attack score accuracy."""
    total_messages: int
    agreement_count: int
    accuracy_rate: float
    classification_overrides: List[Dict[str, Any]]

class BaseAnalyzer(ABC):
    """Base class for message analysis."""
    
    def __init__(self, config: ReportConfig):
        """
        Initialize the analyzer.
        
        Args:
            config: Report configuration
        """
        self.config = config
    
    @abstractmethod
    async def process_data(
        self,
        message_groups: List[MessageGroup],
        org_stats: OrgStats
    ) -> None:
        """
        Process the input data.
        
        Args:
            message_groups: List of message groups to analyze
            org_stats: Organization statistics
        """
        pass
    
    @abstractmethod
    async def get_attack_types(self) -> List[AttackTypeAnalysis]:
        """Get analysis of attack types."""
        pass
    
    @abstractmethod
    async def get_tactics(self) -> List[TacticAnalysis]:
        """Get analysis of tactics and techniques."""
        pass
    
    @abstractmethod
    async def get_detection_methods(self) -> List[DetectionMethodAnalysis]:
        """Get analysis of detection methods."""
        pass
    
    @abstractmethod
    async def get_top_senders(self, limit: int = 10) -> List[TopSenderAnalysis]:
        """Get analysis of top sender domains."""
        pass
    
    @abstractmethod
    async def get_top_emails(self, limit: int = 10) -> List[TopEmailAnalysis]:
        """Get analysis of top emails by message count."""
        pass
    
    @abstractmethod
    async def get_user_reports(self) -> List[UserReportAnalysis]:
        """Get analysis of user reports."""
        pass
    
    @abstractmethod
    async def get_accuracy_analysis(self) -> AccuracyAnalysis:
        """Get analysis of attack score accuracy."""
        pass
    
    @staticmethod
    def calculate_percentage(count: int, total: int) -> float:
        """Calculate percentage with proper handling of zero division."""
        return (count / total * 100) if total > 0 else 0.0
    
    @staticmethod
    def extract_domain(email: str) -> str:
        """Extract domain from email address."""
        try:
            return email.split('@')[1] if '@' in email else email
        except IndexError:
            return email
    
    @staticmethod
    def get_verdict(message: MessageGroup, use_asa: bool) -> str:
        """Get the appropriate verdict based on configuration."""
        return message.asa_verdict if use_asa else message.attack_score_verdict
