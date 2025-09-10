#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main Dashboard Export Orchestrator

This module coordinates the export of Prowler dashboard data into various self-contained formats.
It discovers data files, processes them, and generates standalone HTML deliverables.
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from colorama import Fore, Style

from prowler.lib.logger import logger
from .data_processor import DashboardDataProcessor
from .static_generator import StaticHTMLGenerator


class DashboardExporter:
    """Main class for orchestrating dashboard exports"""
    
    def __init__(self, 
                 output_directory: str = None,
                 export_format: str = "static",
                 export_directory: str = None):
        """
        Initialize the Dashboard Exporter
        
        Args:
            output_directory: Path to Prowler output directory containing CSV files
            export_format: Export format (static, portable, report)
            export_directory: Directory to save exported dashboard
        """
        self.output_directory = output_directory or os.path.join(os.getcwd(), "output")
        self.export_format = export_format
        self.export_directory = export_directory or os.path.join(os.getcwd(), "dashboard-export")
        
        self.data_processor = DashboardDataProcessor(self.output_directory)
        self.html_generator = StaticHTMLGenerator()
        
        # Validate output directory exists
        if not os.path.exists(self.output_directory):
            raise ValueError(f"Output directory does not exist: {self.output_directory}")
    
    def export_dashboard(self) -> bool:
        """
        Main export orchestration method
        
        Returns:
            bool: True if export was successful, False otherwise
        """
        try:
            logger.info(f"Starting dashboard export in {self.export_format} format")
            print(f"{Fore.BLUE}🔄 Starting dashboard export...{Style.RESET_ALL}")
            
            # Step 1: Discover and validate data files
            if not self._discover_data_files():
                print(f"{Fore.RED}❌ No Prowler output files found in {self.output_directory}{Style.RESET_ALL}")
                return False
            
            # Step 2: Process CSV data
            print(f"{Fore.YELLOW}📊 Processing CSV data files...{Style.RESET_ALL}")
            dashboard_data = self.data_processor.process_all_data()
            
            if not dashboard_data:
                print(f"{Fore.RED}❌ Failed to process dashboard data{Style.RESET_ALL}")
                return False
            
            # Step 3: Generate export based on format
            success = self._generate_export(dashboard_data)
            
            if success:
                print(f"{Fore.GREEN}✅ Dashboard export completed successfully!{Style.RESET_ALL}")
                print(f"{Fore.CYAN}📁 Export location: {self.export_directory}{Style.RESET_ALL}")
                self._print_usage_instructions()
            else:
                print(f"{Fore.RED}❌ Dashboard export failed{Style.RESET_ALL}")
            
            return success
            
        except Exception as e:
            logger.error(f"Dashboard export failed: {str(e)}")
            print(f"{Fore.RED}❌ Export failed: {str(e)}{Style.RESET_ALL}")
            return False
    
    def _discover_data_files(self) -> bool:
        """
        Discover and validate Prowler output files
        
        Returns:
            bool: True if valid data files are found
        """
        csv_files = []
        
        # Look for CSV files in main output directory
        for file_path in Path(self.output_directory).glob("*.csv"):
            if "prowler-output" in file_path.name:
                csv_files.append(str(file_path))
        
        # Look for compliance CSV files
        compliance_dir = os.path.join(self.output_directory, "compliance")
        if os.path.exists(compliance_dir):
            for file_path in Path(compliance_dir).glob("*.csv"):
                csv_files.append(str(file_path))
        
        if csv_files:
            print(f"{Fore.GREEN}📄 Found {len(csv_files)} CSV data files{Style.RESET_ALL}")
            for file_path in csv_files[:5]:  # Show first 5 files
                print(f"  • {os.path.basename(file_path)}")
            if len(csv_files) > 5:
                print(f"  • ... and {len(csv_files) - 5} more files")
            return True
        
        return False
    
    def _generate_export(self, dashboard_data: Dict) -> bool:
        """
        Generate the export based on the specified format
        
        Args:
            dashboard_data: Processed dashboard data
            
        Returns:
            bool: True if generation was successful
        """
        # Create export directory
        os.makedirs(self.export_directory, exist_ok=True)
        
        if self.export_format == "static":
            return self._generate_static_export(dashboard_data)
        elif self.export_format == "portable":
            return self._generate_portable_export(dashboard_data)
        elif self.export_format == "report":
            return self._generate_report_export(dashboard_data)
        else:
            raise ValueError(f"Unsupported export format: {self.export_format}")
    
    def _generate_static_export(self, dashboard_data: Dict) -> bool:
        """Generate a single static HTML file with everything embedded"""
        try:
            print(f"{Fore.YELLOW}🔧 Generating static HTML export...{Style.RESET_ALL}")
            
            # Generate the static HTML
            html_content = self.html_generator.generate_static_html(dashboard_data)
            
            # Write to file
            output_file = os.path.join(self.export_directory, "prowler-dashboard.html")
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"{Fore.GREEN}📄 Static HTML generated: prowler-dashboard.html{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate static export: {str(e)}")
            return False
    
    def _generate_portable_export(self, dashboard_data: Dict) -> bool:
        """Generate a portable package with multiple files"""
        try:
            print(f"{Fore.YELLOW}📦 Generating portable package...{Style.RESET_ALL}")
            
            # Generate overview page
            overview_html = self.html_generator.generate_overview_page(dashboard_data)
            overview_file = os.path.join(self.export_directory, "overview.html")
            with open(overview_file, 'w', encoding='utf-8') as f:
                f.write(overview_html)
            
            # Generate compliance page
            compliance_html = self.html_generator.generate_compliance_page(dashboard_data)
            compliance_file = os.path.join(self.export_directory, "compliance.html")
            with open(compliance_file, 'w', encoding='utf-8') as f:
                f.write(compliance_html)
            
            # Generate index page with navigation
            index_html = self.html_generator.generate_index_page(dashboard_data)
            index_file = os.path.join(self.export_directory, "index.html")
            with open(index_file, 'w', encoding='utf-8') as f:
                f.write(index_html)
            
            # Create launcher script
            self._create_launcher_script()
            
            # Create README
            self._create_readme()
            
            print(f"{Fore.GREEN}📦 Portable package generated with multiple pages{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate portable export: {str(e)}")
            return False
    
    def _generate_report_export(self, dashboard_data: Dict) -> bool:
        """Generate PDF report (placeholder for now)"""
        # PDF generation not yet implemented, falling back to static HTML
        print(f"{Fore.YELLOW}⚠️  PDF report generation not yet implemented{Style.RESET_ALL}")
        print(f"{Fore.CYAN}💡 Falling back to static HTML export{Style.RESET_ALL}")
        return self._generate_static_export(dashboard_data)
    
    def _create_launcher_script(self):
        """Create a simple launcher script for portable packages"""
        launcher_content = """#!/bin/bash
echo "Starting Prowler Dashboard Server..."
echo "Dashboard will be available at: http://localhost:8000"
echo "Press Ctrl+C to stop"
echo ""
python3 -m http.server 8000 2>/dev/null || python -m http.server 8000
"""
        launcher_file = os.path.join(self.export_directory, "serve.sh")
        with open(launcher_file, 'w') as f:
            f.write(launcher_content)
        os.chmod(launcher_file, 0o755)
        
        # Windows version
        launcher_content_win = """@echo off
echo Starting Prowler Dashboard Server...
echo Dashboard will be available at: http://localhost:8000
echo Press Ctrl+C to stop
echo.
python -m http.server 8000
pause
"""
        launcher_file_win = os.path.join(self.export_directory, "serve.bat")
        with open(launcher_file_win, 'w') as f:
            f.write(launcher_content_win)
    
    def _create_readme(self):
        """Create README file for portable packages"""
        readme_content = f"""# Prowler Dashboard Export

This package contains a self-contained Prowler security assessment dashboard.

## Files Included

- `index.html` - Main dashboard with navigation
- `overview.html` - Overview page with findings summary
- `compliance.html` - Compliance framework results
- `serve.sh` / `serve.bat` - Local server launcher scripts

## How to View

### Option 1: Direct File Access
Simply open `index.html` in your web browser.

### Option 2: Local Server (Recommended)
For full functionality, serve the files via HTTP:

**Linux/Mac:**
```bash
./serve.sh
```

**Windows:**
```cmd
serve.bat
```

Then open http://localhost:8000 in your browser.

## Export Details

- **Generated:** {dashboard_data.get('export_timestamp', 'Unknown')}
- **Format:** Portable Package
- **Data Source:** {self.output_directory}
- **Total Findings:** {dashboard_data.get('total_findings', 0)}

## Requirements

- Modern web browser (Chrome, Firefox, Safari, Edge)
- No internet connection required (fully offline)
- Optional: Python 3 for local server (recommended)

## Note

This dashboard is self-contained and includes all data inline. 
No external dependencies or internet connection required.
"""
        readme_file = os.path.join(self.export_directory, "README.md")
        with open(readme_file, 'w') as f:
            f.write(readme_content)
    
    def _print_usage_instructions(self):
        """Print instructions for using the exported dashboard"""
        print(f"\n{Fore.CYAN}📖 Usage Instructions:{Style.RESET_ALL}")
        
        if self.export_format == "static":
            html_file = os.path.join(self.export_directory, "prowler-dashboard.html")
            print(f"   Open in browser: {html_file}")
            print(f"   Or double-click the HTML file to view")
            
        elif self.export_format == "portable":
            print(f"   1. Open index.html in your browser, or")
            print(f"   2. Run the launcher script:")
            print(f"      • Linux/Mac: ./serve.sh")
            print(f"      • Windows: serve.bat")
            print(f"      Then visit: http://localhost:8000")


def export_dashboard(output_directory: str = None,
                    export_format: str = "static", 
                    export_directory: str = None) -> bool:
    """
    Export Prowler dashboard as self-contained HTML
    
    Args:
        output_directory: Path to Prowler CSV output files
        export_format: Export format (static, portable, report)  
        export_directory: Directory to save exported dashboard
        
    Returns:
        bool: True if export successful, False otherwise
    """
    try:
        exporter = DashboardExporter(
            output_directory=output_directory,
            export_format=export_format,
            export_directory=export_directory
        )
        return exporter.export_dashboard()
    except Exception as e:
        logger.error(f"Dashboard export failed: {str(e)}")
        return False