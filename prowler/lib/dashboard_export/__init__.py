"""
Prowler Dashboard Export Module

This module provides functionality to export Prowler dashboard data as self-contained 
HTML deliverables that can be shared and viewed offline.

Features:
- Static HTML export with embedded data
- Portable dashboard packages
- PDF report generation
- Interactive charts preserved offline
"""

from .dashboard_export import export_dashboard

__all__ = ['export_dashboard']