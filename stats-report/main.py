#!/usr/bin/env python3
"""
Stats Report Generator
A unified tool for collecting and analyzing message statistics.
"""

import argparse
import asyncio
import getpass
import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Union

from stats_report.core.api_client import APIClient, APIError
from stats_report.core.data_models import DateRange, ReportConfig, VerdictType
from stats_report.core.file_processor import CSVProcessor, FileProcessingError
from stats_report.analysis.memory_analyzer import MemoryAnalyzer
from stats_report.analysis.sql_analyzer import SQLiteAnalyzer
from stats_report.output.factory import create_formatter

# Configure logging
log_level = logging.DEBUG if '--debug' in sys.argv else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
logger = logging.getLogger(__name__)

def setup_cli() -> argparse.ArgumentParser:
    """Configure and return the command line interface parser."""
    parser = argparse.ArgumentParser(
        description='Stats Report Generator - Analyze message statistics and generate reports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate JSON report from API:
  python main.py --mode api --input https://example.sublime.security --output-format json
  
  # Generate markdown report from API:
  python main.py --mode api --input https://example.sublime.security --output-format markdown
  
  # Use ASA verdict for analysis:
  python main.py --mode api --input https://example.sublime.security --use-asa
  
  # Use SQLite storage for large datasets:
  python main.py --mode api --input https://example.sublime.security --storage sqlite
'''
    )
    
    # Data source options
    parser.add_argument('--mode', 
                       choices=['api', 'file'],
                       required=True,
                       help='Data source: API or existing file')
    
    parser.add_argument('--input',
                       type=str,
                       required=True,
                       help='API URL or input file path')
    
    # Processing options
    parser.add_argument('--storage',
                       choices=['memory', 'sqlite'],
                       default='memory',
                       help='Storage backend to use')
    
    parser.add_argument('--use-asa',
                       action='store_true',
                       default=False,
                       help='Use ASA Verdict instead of Attack Score Verdict for user report analysis')
    
    # Output options
    parser.add_argument('--output-format',
                       choices=['json', 'markdown'],
                       default='markdown',
                       help='Output format for the report (json or markdown)')
    
    parser.add_argument('--output-file',
                       type=str,
                       help='Path to output file. If not specified, will use timestamp-based filename')
    
    # API specific options
    parser.add_argument('--days-back',
                       type=int,
                       default=30,
                       help='Number of days to look back when fetching from API')
    
    # Debug options
    parser.add_argument('--debug',
                       action='store_true',
                       help='Enable debug logging')
    
    return parser

def validate_args(args: argparse.Namespace) -> bool:
    """
    Validate command line arguments.
    Returns True if arguments are valid, False otherwise.
    """
    # Validate input path/url
    if args.mode == 'file':
        input_path = Path(args.input)
        if not input_path.exists():
            logger.error(f"Input file '{args.input}' does not exist")
            return False
        if not input_path.is_file():
            logger.error(f"'{args.input}' is not a file")
            return False
    elif args.mode == 'api':
        # Basic URL validation
        if not args.input.startswith(('http://', 'https://')):
            logger.error("API URL must start with http:// or https://")
            return False
    
    # Validate days_back
    if args.days_back <= 0:
        logger.error("--days-back must be greater than 0")
        return False
    
    return True

def get_default_output_file(output_format: str) -> str:
    """Generate default output filename based on format and timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"reports/stats_report_{timestamp}.{output_format}"

async def fetch_api_data(args: argparse.Namespace) -> dict:
    """
    Fetch data from the API.
    
    Args:
        args: Command line arguments
    
    Returns:
        Dictionary containing fetched data
    
    Raises:
        APIError: If API request fails
    """
    # Get API key from environment or prompt
    api_key = os.environ.get('SUBLIME_API_KEY')
    if not api_key:
        api_key = getpass.getpass("Enter your API key: ")
    
    # Calculate date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=args.days_back)
    date_range = DateRange(start=start_date, end=end_date)
    
    # Initialize API client
    async with APIClient(args.input, api_key) as client:
        try:
            logger.info("Fetching data from API...")
            return await client.fetch_all_data(date_range)
        except APIError as e:
            logger.error(f"API request failed: {e}")
            raise

async def main():
    """Main entry point for the stats report generator."""
    parser = setup_cli()
    args = parser.parse_args()
    
    if not validate_args(args):
        sys.exit(1)
    
    try:
        # Create reports directory if it doesn't exist
        Path("reports").mkdir(exist_ok=True)
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=args.days_back)
        date_range = DateRange(start=start_date, end=end_date)

        # Set up configuration
        config = ReportConfig(
            verdict_type="ASA Verdict" if args.use_asa else "Attack Score Verdict",
            storage_type=args.storage,
            output_format=args.output_format,
            date_range=date_range,
            output_file=args.output_file or get_default_output_file(args.output_format)
        )
        
        # Initialize appropriate analyzer
        analyzer_class = MemoryAnalyzer if args.storage == 'memory' else SQLiteAnalyzer
        analyzer = analyzer_class(config)
        
        try:
            # Get data from appropriate source
            if args.mode == 'api':
                data = await fetch_api_data(args)
                if not data:
                    logger.error("No data returned from API")
                    sys.exit(1)
                if 'message_groups' not in data:
                    logger.error("API response missing 'message_groups' key")
                    sys.exit(1)
                if 'org_stats' not in data:
                    logger.error("API response missing 'org_stats' key")
                    sys.exit(1)
                
                logger.debug(f"API returned {len(data['message_groups'])} message groups")
            else:
                try:
                    processor = CSVProcessor(args.input)
                    data = await processor.process_file()
                except FileProcessingError as e:
                    logger.error(f"Error processing CSV file: {e}")
                    sys.exit(1)
            
            # Process data
            logger.info("Processing data...")
            await analyzer.process_data(
                message_groups=data['message_groups'],
                org_stats=data['org_stats']
            )
            
            # Generate and save report
            logger.info(f"Generating {args.output_format} report...")
            formatter = create_formatter(args.output_format, analyzer, config)
            await formatter.save(config.output_file)
            
            logger.info(f"Report saved to: {config.output_file}")
            
        finally:
            # Cleanup if using SQLite
            if isinstance(analyzer, SQLiteAnalyzer):
                await analyzer.close()
        
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())