#!/usr/bin/env python3
"""
ForensicAutomator - Entry Point
Run with: python forensic.py or python -m forensic_tool
"""

import sys

def main():
    """Main entry point - check for arguments or launch interactive mode."""
    if len(sys.argv) > 1:
        # CLI mode with arguments
        from forensic_tool.main import app
        app()
    else:
        # Interactive menu mode
        from forensic_tool.menu import interactive_mode
        interactive_mode()


if __name__ == "__main__":
    main()
