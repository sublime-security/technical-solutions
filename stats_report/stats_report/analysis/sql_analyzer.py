"""
SQLite-based implementation of the message analyzer.
"""

import asyncio
import aiosqlite
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from .base import (
    BaseAnalyzer, AttackTypeAnalysis, TacticAnalysis,
    DetectionMethodAnalysis, TopSenderAnalysis, TopEmailAnalysis,
    UserReportAnalysis, AccuracyAnalysis
)
from ..core.data_models import MessageGroup, OrgStats, ReportConfig

class SQLiteAnalyzer(BaseAnalyzer):
    """SQLite-based implementation of message analysis."""
    
    def __init__(self, config: ReportConfig, db_path: Optional[str] = None):
        """
        Initialize the SQLite analyzer.
        
        Args:
            config: Report configuration
            db_path: Path to SQLite database file. If None, uses in-memory database.
        """
        super().__init__(config)
        self.db_path = db_path or ":memory:"
        self._connection: Optional[aiosqlite.Connection] = None
    
    async def _get_connection(self) -> aiosqlite.Connection:
        """Get or create database connection."""
        if self._connection is None:
            self._connection = await aiosqlite.connect(self.db_path)
            await self._connection.execute("PRAGMA foreign_keys = ON")
        return self._connection
    
    async def _create_schema(self) -> None:
        """Create database schema."""
        conn = await self._get_connection()
        
        # Create tables
        await conn.executescript("""
            -- Main message groups table
            CREATE TABLE IF NOT EXISTS message_groups (
                id TEXT PRIMARY KEY,
                created_at TIMESTAMP,
                attack_score_verdict TEXT,
                asa_verdict TEXT,
                classification TEXT,
                review_status TEXT,
                review_label TEXT,
                review_comment TEXT,
                message_count INTEGER,
                recipient_count INTEGER
            );
            
            -- Normalized tables for array fields
            CREATE TABLE IF NOT EXISTS subjects (
                message_id TEXT,
                subject TEXT,
                FOREIGN KEY (message_id) REFERENCES message_groups(id)
            );
            
            CREATE TABLE IF NOT EXISTS sender_emails (
                message_id TEXT,
                email TEXT,
                domain TEXT,
                FOREIGN KEY (message_id) REFERENCES message_groups(id)
            );
            
            CREATE TABLE IF NOT EXISTS flagged_rules (
                message_id TEXT,
                rule_name TEXT,
                severity TEXT,
                FOREIGN KEY (message_id) REFERENCES message_groups(id)
            );
            
            -- Organization stats table
            CREATE TABLE IF NOT EXISTS org_stats (
                id INTEGER PRIMARY KEY,
                messages_processed_count INTEGER,
                active_mailbox_count INTEGER,
                active_detection_rule_count INTEGER
            );
            
            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_message_groups_verdict 
            ON message_groups(attack_score_verdict, asa_verdict);
            
            CREATE INDEX IF NOT EXISTS idx_message_groups_review 
            ON message_groups(review_status);
            
            CREATE INDEX IF NOT EXISTS idx_sender_emails_domain 
            ON sender_emails(domain);
            
            CREATE INDEX IF NOT EXISTS idx_flagged_rules_name 
            ON flagged_rules(rule_name);
        """)
        await conn.commit()
    
    async def process_data(
        self,
        message_groups: List[MessageGroup],
        org_stats: OrgStats
    ) -> None:
        """Process and store message data in SQLite database."""
        await self._create_schema()
        conn = await self._get_connection()
        
        async with conn.cursor() as cursor:
            # Store org stats
            await cursor.execute("""
                INSERT INTO org_stats (
                    id, messages_processed_count, active_mailbox_count, 
                    active_detection_rule_count
                ) VALUES (1, ?, ?, ?)
            """, (
                org_stats.messages_processed_count,
                org_stats.active_mailbox_count,
                org_stats.active_detection_rule_count
            ))
            
            # Store message groups
            for msg in message_groups:
                # Insert main message group
                await cursor.execute("""
                    INSERT INTO message_groups (
                        id, created_at, attack_score_verdict, asa_verdict,
                        classification, review_status, review_label,
                        review_comment, message_count, recipient_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    msg.id,
                    msg.created_at.isoformat(),
                    msg.attack_score_verdict,
                    msg.asa_verdict,
                    msg.classification,
                    msg.review_status,
                    msg.review_label,
                    msg.review_comment,
                    msg.message_count,
                    msg.recipient_count
                ))
                
                # Insert subjects
                await cursor.executemany(
                    "INSERT INTO subjects (message_id, subject) VALUES (?, ?)",
                    [(msg.id, subject) for subject in msg.subjects]
                )
                
                # Insert sender emails
                await cursor.executemany(
                    "INSERT INTO sender_emails (message_id, email, domain) VALUES (?, ?, ?)",
                    [(msg.id, email, self.extract_domain(email)) 
                     for email in msg.sender_email_addresses]
                )
                
                # Insert flagged rules
                await cursor.executemany(
                    "INSERT INTO flagged_rules (message_id, rule_name, severity) VALUES (?, ?, ?)",
                    [(msg.id, rule["name"], rule["severity"]) 
                     for rule in msg.flagged_rules]
                )
            
            await conn.commit()
    
    def _get_verdict_column(self) -> str:
        """Get the appropriate verdict column based on configuration."""
        return "asa_verdict" if self.config.verdict_type == "ASA Verdict" else "attack_score_verdict"
    
    async def get_attack_types(self) -> List[AttackTypeAnalysis]:
        """Analyze attack types from malicious messages."""
        conn = await self._get_connection()
        verdict_col = self._get_verdict_column()
        
        query = f"""
            WITH malicious_messages AS (
                SELECT id, message_count
                FROM message_groups
                WHERE {verdict_col} = 'malicious'
            ),
            total_messages AS (
                SELECT COALESCE(SUM(message_count), 0) as total
                FROM malicious_messages
            )
            SELECT 
                fr.rule_name as attack_type,
                COUNT(DISTINCT fr.message_id) as message_groups,
                SUM(mm.message_count) as total_messages,
                ROUND(CAST(SUM(mm.message_count) AS FLOAT) * 100 / 
                    NULLIF((SELECT total FROM total_messages), 0), 2) as percentage
            FROM flagged_rules fr
            JOIN malicious_messages mm ON fr.message_id = mm.id
            GROUP BY fr.rule_name
            ORDER BY total_messages DESC
        """
        
        async with conn.execute(query) as cursor:
            rows = await cursor.fetchall()
            
            return [
                AttackTypeAnalysis(
                    attack_type=row[0],
                    message_groups=row[1],
                    total_individual_messages=row[2],
                    percentage_of_total=row[3] or 0.0
                )
                for row in rows
            ]
    
    async def get_tactics(self) -> List[TacticAnalysis]:
        """Analyze tactics from malicious messages."""
        conn = await self._get_connection()
        verdict_col = self._get_verdict_column()
        
        query = f"""
            WITH malicious_messages AS (
                SELECT id, message_count
                FROM message_groups
                WHERE {verdict_col} = 'malicious'
            ),
            total_messages AS (
                SELECT COALESCE(SUM(message_count), 0) as total
                FROM malicious_messages
            )
            SELECT 
                fr.rule_name as tactic,
                COUNT(DISTINCT fr.message_id) as message_groups,
                SUM(mm.message_count) as total_messages,
                ROUND(CAST(SUM(mm.message_count) AS FLOAT) * 100 / 
                    NULLIF((SELECT total FROM total_messages), 0), 2) as percentage
            FROM flagged_rules fr
            JOIN malicious_messages mm ON fr.message_id = mm.id
            GROUP BY fr.rule_name
            ORDER BY total_messages DESC
        """
        
        async with conn.execute(query) as cursor:
            rows = await cursor.fetchall()
            
            return [
                TacticAnalysis(
                    tactic=row[0],
                    message_groups=row[1],
                    total_individual_messages=row[2],
                    percentage_of_total=row[3] or 0.0
                )
                for row in rows
            ]
    
    async def get_detection_methods(self) -> List[DetectionMethodAnalysis]:
        """Analyze detection methods from malicious messages."""
        conn = await self._get_connection()
        verdict_col = self._get_verdict_column()
        
        query = f"""
            WITH malicious_messages AS (
                SELECT id, message_count
                FROM message_groups
                WHERE {verdict_col} = 'malicious'
            ),
            total_messages AS (
                SELECT COALESCE(SUM(message_count), 0) as total
                FROM malicious_messages
            )
            SELECT 
                fr.severity as detection_method,
                COUNT(DISTINCT fr.message_id) as message_groups,
                SUM(mm.message_count) as total_messages,
                ROUND(CAST(SUM(mm.message_count) AS FLOAT) * 100 / 
                    NULLIF((SELECT total FROM total_messages), 0), 2) as percentage
            FROM flagged_rules fr
            JOIN malicious_messages mm ON fr.message_id = mm.id
            GROUP BY fr.severity
            ORDER BY total_messages DESC
        """
        
        async with conn.execute(query) as cursor:
            rows = await cursor.fetchall()
            
            return [
                DetectionMethodAnalysis(
                    detection_method=row[0],
                    message_groups=row[1],
                    total_individual_messages=row[2],
                    percentage_of_total=row[3] or 0.0
                )
                for row in rows
            ]
    
    async def get_top_senders(self, limit: int = 10) -> List[TopSenderAnalysis]:
        """Analyze top sender domains from malicious messages."""
        conn = await self._get_connection()
        verdict_col = self._get_verdict_column()
        
        query = f"""
            WITH malicious_messages AS (
                SELECT id, message_count
                FROM message_groups
                WHERE {verdict_col} = 'malicious'
            ),
            total_messages AS (
                SELECT COALESCE(SUM(message_count), 0) as total
                FROM malicious_messages
            )
            SELECT 
                se.domain,
                COUNT(DISTINCT se.message_id) as message_groups,
                SUM(mm.message_count) as total_messages,
                ROUND(CAST(SUM(mm.message_count) AS FLOAT) * 100 / 
                    NULLIF((SELECT total FROM total_messages), 0), 2) as percentage
            FROM sender_emails se
            JOIN malicious_messages mm ON se.message_id = mm.id
            GROUP BY se.domain
            ORDER BY total_messages DESC
            LIMIT ?
        """
        
        async with conn.execute(query, (limit,)) as cursor:
            rows = await cursor.fetchall()
            
            return [
                TopSenderAnalysis(
                    domain=row[0],
                    message_groups=row[1],
                    total_individual_messages=row[2],
                    percentage_of_total=row[3] or 0.0
                )
                for row in rows
            ]
    
    async def get_top_emails(self, limit: int = 10) -> List[TopEmailAnalysis]:
        """Analyze top individual emails by message count."""
        conn = await self._get_connection()
        verdict_col = self._get_verdict_column()
        
        query = f"""
            SELECT 
                mg.created_at,
                s.subject,
                se.email,
                mg.id as url,
                mg.message_count
            FROM message_groups mg
            LEFT JOIN subjects s ON mg.id = s.message_id
            LEFT JOIN sender_emails se ON mg.id = se.message_id
            WHERE mg.{verdict_col} = 'malicious'
            ORDER BY mg.message_count DESC
            LIMIT ?
        """
        
        async with conn.execute(query, (limit,)) as cursor:
            rows = await cursor.fetchall()
            
            return [
                TopEmailAnalysis(
                    received_datetime=datetime.fromisoformat(row[0]),
                    subject=row[1] or "",
                    sender_email=row[2] or "",
                    url=row[3] or "",
                    total_messages=row[4]
                )
                for row in rows
            ]
    
    async def get_user_reports(self) -> List[UserReportAnalysis]:
        """Analyze user reported messages."""
        conn = await self._get_connection()
        verdict_col = self._get_verdict_column()
        
        query = f"""
            WITH user_reports AS (
                SELECT 
                    review_status,
                    {verdict_col} as verdict,
                    message_count,
                    COUNT(*) as report_count,
                    SUM(message_count) as total_messages
                FROM message_groups
                WHERE review_status IS NOT NULL
                GROUP BY review_status, {verdict_col}
            ),
            total_reports AS (
                SELECT COALESCE(SUM(message_count), 0) as total
                FROM message_groups
                WHERE review_status IS NOT NULL
            )
            SELECT 
                review_status,
                GROUP_CONCAT(verdict || ':' || message_count) as verdict_counts,
                SUM(report_count) as total_reports,
                SUM(total_messages) as total_messages,
                ROUND(CAST(SUM(total_messages) AS FLOAT) * 100 / 
                    NULLIF((SELECT total FROM total_reports), 0), 2) as percentage
            FROM user_reports
            GROUP BY review_status
            ORDER BY total_messages DESC
        """
        
        async with conn.execute(query) as cursor:
            rows = await cursor.fetchall()
            
            results = []
            for row in rows:
                # Parse verdict counts into effectiveness dict
                effectiveness = {}
                if row[1]:  # verdict_counts
                    for item in row[1].split(','):
                        verdict, count = item.split(':')
                        total = row[3]  # total_messages
                        effectiveness[verdict.lower()] = (
                            int(count) / total * 100 if total > 0 else 0.0
                        )
                
                results.append(UserReportAnalysis(
                    reporter_email=row[0],  # review_status
                    report_groups=row[2],   # total_reports
                    total_reported_messages=row[3],  # total_messages
                    percentage_of_total=row[4] or 0.0,  # percentage
                    effectiveness=effectiveness
                ))
            
            return results
    
    async def get_accuracy_analysis(self) -> AccuracyAnalysis:
        """Analyze attack score accuracy."""
        conn = await self._get_connection()
        
        # Get overall statistics
        stats_query = """
            SELECT 
                COUNT(*) as total,
                SUM(CASE 
                    WHEN LOWER(attack_score_verdict) = LOWER(classification) 
                    THEN 1 ELSE 0 
                END) as agreements
            FROM message_groups
            WHERE attack_score_verdict IS NOT NULL 
                AND classification IS NOT NULL
        """
        
        # Get override details
        overrides_query = """
            SELECT 
                attack_score_verdict,
                classification,
                COUNT(*) as count
            FROM message_groups
            WHERE attack_score_verdict IS NOT NULL 
                AND classification IS NOT NULL
                AND LOWER(attack_score_verdict) != LOWER(classification)
            GROUP BY attack_score_verdict, classification
            ORDER BY count DESC
        """
        
        async with conn.execute(stats_query) as cursor:
            total, agreements = await cursor.fetchone()
            
        async with conn.execute(overrides_query) as cursor:
            override_rows = await cursor.fetchall()
            
        overrides = [
            {
                "attack_score_verdict": row[0],
                "customer_classification": row[1],
                "count": row[2],
                "percentage": self.calculate_percentage(row[2], total)
            }
            for row in override_rows
        ]
        
        return AccuracyAnalysis(
            total_messages=total,
            agreement_count=agreements,
            accuracy_rate=self.calculate_percentage(agreements, total),
            classification_overrides=overrides
        )
    
    async def close(self) -> None:
        """Close database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None
