"""Compatibility entrypoint for the authenticated unified GhostNet service."""
from pathlib import Path
import os
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from legacy_entrypoint import load_app
app=load_app()

if __name__=='__main__':
    app.run(host=os.getenv('ML_APP_HOST','127.0.0.1'),port=int(os.getenv('ML_APP_PORT','5000')),debug=False)
