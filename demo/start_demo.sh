#!/bin/bash
# Easy Start Script for Honeypot Demo

echo "╔═══════════════════════════════════════════════════════╗"
echo "║                                                       ║"
echo "║   🍯  HONEYPOT DEMO - EASY START  🍯                 ║"
echo "║                                                       ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "Starting your honeypot demonstration..."
echo ""
echo "✅ Step 1: Checking Python..."

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is not installed. Please install Python first!"
    exit 1
fi

echo "✅ Python3 found!"
echo ""
echo "✅ Step 2: Starting honeypot server..."
echo ""

# Make the Python script executable
chmod +x honeypot_server.py

# Start the server
python3 honeypot_server.py
