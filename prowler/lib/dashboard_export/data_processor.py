#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dashboard Data Processor

This module handles the processing of Prowler CSV output files, converting them
into structured data suitable for dashboard export.
"""

import csv
import json
import os
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from prowler.lib.logger import logger


class DashboardDataProcessor:
    """Processes Prowler CSV output files for dashboard export"""
    
    def __init__(self, output_directory: str):
        """
        Initialize data processor
        
        Args:
            output_directory: Path to directory containing Prowler CSV files
        """
        self.output_directory = output_directory
        self.compliance_directory = os.path.join(output_directory, "compliance")
        
    def process_all_data(self) -> Dict[str, Any]:
        """
        Process all available data files and return structured dashboard data
        
        Returns:
            Dict containing processed dashboard data
        """
        dashboard_data = {
            'export_timestamp': datetime.now().isoformat(),
            'source_directory': self.output_directory,
            'findings_data': [],
            'compliance_data': {},
            'summary_stats': {},
            'provider_data': {},
            'total_findings': 0
        }
        
        try:
            # Process main findings CSV files
            findings_files = self._discover_findings_files()
            if findings_files:
                dashboard_data['findings_data'] = self._process_findings_files(findings_files)
                dashboard_data['total_findings'] = len(dashboard_data['findings_data'])
            
            # Process compliance CSV files  
            compliance_files = self._discover_compliance_files()
            if compliance_files:
                dashboard_data['compliance_data'] = self._process_compliance_files(compliance_files)
            
            # Generate summary statistics
            dashboard_data['summary_stats'] = self._generate_summary_stats(dashboard_data['findings_data'])
            
            # Generate provider-specific data
            dashboard_data['provider_data'] = self._generate_provider_data(dashboard_data['findings_data'])
            
            logger.info(f"Processed {dashboard_data['total_findings']} findings from {len(findings_files)} files")
            
        except Exception as e:
            logger.error(f"Failed to process dashboard data: {str(e)}")
            
        return dashboard_data
    
    def _discover_findings_files(self) -> List[str]:
        """Discover main Prowler output CSV files"""
        files = []
        
        # Look for prowler-output CSV files
        for file_path in Path(self.output_directory).glob("prowler-output-*.csv"):
            files.append(str(file_path))
        
        # Also look for any other CSV files that might contain findings
        for file_path in Path(self.output_directory).glob("*.csv"):
            if "prowler-output" not in file_path.name and file_path.name not in [f.name for f in Path(files)]:
                # Check if it looks like a findings file by examining headers
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        reader = csv.reader(f)
                        headers = next(reader, [])
                        # Check for typical Prowler CSV headers
                        if any(header in ['STATUS', 'CHECK_ID', 'SEVERITY', 'PROVIDER'] for header in headers):
                            files.append(str(file_path))
                except Exception:
                    continue
        
        return sorted(files)
    
    def _discover_compliance_files(self) -> List[str]:
        """Discover compliance framework CSV files"""
        files = []
        
        if os.path.exists(self.compliance_directory):
            for file_path in Path(self.compliance_directory).glob("*.csv"):
                files.append(str(file_path))
        
        return sorted(files)
    
    def _process_findings_files(self, files: List[str]) -> List[Dict[str, Any]]:
        """
        Process findings CSV files into structured data
        
        Args:
            files: List of CSV file paths
            
        Returns:
            List of finding dictionaries
        """
        all_findings = []
        
        for file_path in files:
            try:
                # Read CSV file
                df = pd.read_csv(file_path, encoding='utf-8', on_bad_lines='skip')
                
                # Convert DataFrame to list of dictionaries
                findings = df.to_dict('records')
                
                # Add metadata
                for finding in findings:
                    finding['_source_file'] = os.path.basename(file_path)
                    finding['_processed_timestamp'] = datetime.now().isoformat()
                    
                    # Clean up any NaN values
                    for key, value in finding.items():
                        if pd.isna(value):
                            finding[key] = ""
                
                all_findings.extend(findings)
                logger.debug(f"Processed {len(findings)} findings from {file_path}")
                
            except Exception as e:
                logger.warning(f"Failed to process findings file {file_path}: {str(e)}")
                continue
        
        return all_findings
    
    def _process_compliance_files(self, files: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Process compliance CSV files
        
        Args:
            files: List of compliance CSV file paths
            
        Returns:
            Dict mapping compliance framework names to their findings
        """
        compliance_data = {}
        
        for file_path in files:
            try:
                # Extract compliance framework name from filename
                framework_name = Path(file_path).stem
                
                # Read CSV file
                df = pd.read_csv(file_path, encoding='utf-8', on_bad_lines='skip')
                
                # Convert to list of dictionaries
                findings = df.to_dict('records')
                
                # Clean up NaN values
                for finding in findings:
                    for key, value in finding.items():
                        if pd.isna(value):
                            finding[key] = ""
                
                compliance_data[framework_name] = findings
                logger.debug(f"Processed {len(findings)} compliance findings for {framework_name}")
                
            except Exception as e:
                logger.warning(f"Failed to process compliance file {file_path}: {str(e)}")
                continue
        
        return compliance_data
    
    def _generate_summary_stats(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics from findings data
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Dict containing summary statistics
        """
        if not findings:
            return {}
        
        # Convert to DataFrame for easier analysis
        df = pd.DataFrame(findings)
        
        stats = {
            'total_findings': len(findings),
            'by_status': {},
            'by_severity': {},
            'by_provider': {},
            'by_service': {},
            'by_region': {},
            'by_account': {},
            'latest_scan_date': None,
            'scan_summary': {}
        }
        
        try:
            # Status breakdown
            if 'STATUS' in df.columns:
                stats['by_status'] = df['STATUS'].value_counts().to_dict()
            
            # Severity breakdown
            if 'SEVERITY' in df.columns:
                stats['by_severity'] = df['SEVERITY'].value_counts().to_dict()
            
            # Provider breakdown
            if 'PROVIDER' in df.columns:
                stats['by_provider'] = df['PROVIDER'].value_counts().to_dict()
            
            # Service breakdown (top 10)
            if 'SERVICE_NAME' in df.columns:
                stats['by_service'] = df['SERVICE_NAME'].value_counts().head(10).to_dict()
            
            # Region breakdown (top 10)
            if 'REGION' in df.columns:
                stats['by_region'] = df['REGION'].value_counts().head(10).to_dict()
            
            # Account breakdown
            account_col = None
            for col in ['ACCOUNT_UID', 'ACCOUNT_ID', 'ACCOUNTID']:
                if col in df.columns:
                    account_col = col
                    break
            
            if account_col:
                stats['by_account'] = df[account_col].value_counts().to_dict()
            
            # Latest scan date
            if 'TIMESTAMP' in df.columns:
                try:
                    latest_timestamp = df['TIMESTAMP'].max()
                    stats['latest_scan_date'] = latest_timestamp
                except Exception:
                    pass
            
            # Scan summary
            stats['scan_summary'] = {
                'pass_rate': round((stats['by_status'].get('PASS', 0) / len(findings)) * 100, 1) if stats['by_status'] else 0,
                'fail_rate': round((stats['by_status'].get('FAIL', 0) / len(findings)) * 100, 1) if stats['by_status'] else 0,
                'critical_findings': stats['by_severity'].get('Critical', 0),
                'high_findings': stats['by_severity'].get('High', 0),
                'providers_scanned': len(stats['by_provider']) if stats['by_provider'] else 0,
                'accounts_scanned': len(stats['by_account']) if stats['by_account'] else 0
            }
            
        except Exception as e:
            logger.warning(f"Failed to generate some summary statistics: {str(e)}")
        
        return stats
    
    def _generate_provider_data(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate provider-specific data for dashboard cards
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Dict containing provider-specific data
        """
        if not findings:
            return {}
        
        df = pd.DataFrame(findings)
        provider_data = {}
        
        try:
            if 'PROVIDER' in df.columns:
                for provider in df['PROVIDER'].unique():
                    provider_df = df[df['PROVIDER'] == provider]
                    
                    provider_stats = {
                        'total_findings': len(provider_df),
                        'pass_count': 0,
                        'fail_count': 0,
                        'critical_count': 0,
                        'high_count': 0,
                        'services': [],
                        'accounts': []
                    }
                    
                    # Status counts
                    if 'STATUS' in provider_df.columns:
                        status_counts = provider_df['STATUS'].value_counts()
                        provider_stats['pass_count'] = status_counts.get('PASS', 0)
                        provider_stats['fail_count'] = status_counts.get('FAIL', 0)
                    
                    # Severity counts
                    if 'SEVERITY' in provider_df.columns:
                        severity_counts = provider_df['SEVERITY'].value_counts()
                        provider_stats['critical_count'] = severity_counts.get('Critical', 0)
                        provider_stats['high_count'] = severity_counts.get('High', 0)
                    
                    # Services
                    if 'SERVICE_NAME' in provider_df.columns:
                        provider_stats['services'] = provider_df['SERVICE_NAME'].unique().tolist()[:10]
                    
                    # Accounts
                    account_col = None
                    for col in ['ACCOUNT_UID', 'ACCOUNT_ID', 'ACCOUNTID']:
                        if col in provider_df.columns:
                            account_col = col
                            break
                    
                    if account_col:
                        provider_stats['accounts'] = provider_df[account_col].unique().tolist()
                    
                    provider_data[provider] = provider_stats
                    
        except Exception as e:
            logger.warning(f"Failed to generate provider data: {str(e)}")
        
        return provider_data
    
    def to_json(self, data: Any) -> str:
        """
        Convert data to JSON string, handling datetime serialization
        
        Args:
            data: Data to convert to JSON
            
        Returns:
            JSON string
        """
        def json_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif pd.isna(obj):
                return None
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        return json.dumps(data, default=json_serializer, ensure_ascii=False)