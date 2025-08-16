#!/usr/bin/env bash
# Create venv, install deps, and run uvicorn (for Git Bash / WSL)
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
uvicorn src.app.main:app --reload --host 0.0.0.0 --port 8000
