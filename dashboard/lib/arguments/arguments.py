def init_dashboard_parser(self):
    """Init the Dashboard CLI parser"""
    # If we don't set `help="Dashboard"` this won't be rendered
    # We don't want the dashboard to inherit from the common providers parser since it's a different component
    self.subparsers.add_parser("dashboard")
    
    # Dashboard Export Parser
    dashboard_export_parser = self.subparsers.add_parser(
        "dashboard-export",
        help="Export Prowler dashboard as self-contained HTML"
    )
    
    dashboard_export_parser.add_argument(
        "--output-dir",
        "-o",
        dest="output_directory",
        help="Directory containing Prowler CSV output files (default: ./output)",
        default=None
    )
    
    dashboard_export_parser.add_argument(
        "--export-dir",
        "-e",
        dest="export_directory", 
        help="Directory to save exported dashboard (default: ./dashboard-export)",
        default=None
    )
    
    dashboard_export_parser.add_argument(
        "--format",
        "-f",
        dest="export_format",
        choices=["static", "portable", "report"],
        default="static",
        help="Export format: static (single HTML), portable (multi-file), report (PDF)"
    )
    
    dashboard_export_parser.add_argument(
        "--title",
        "-t",
        dest="dashboard_title",
        help="Custom title for the exported dashboard",
        default="Prowler Security Dashboard"
    )
