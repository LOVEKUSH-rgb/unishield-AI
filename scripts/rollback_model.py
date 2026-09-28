#!/usr/bin/env python3
"""
UniShield AI -- Model Rollback Script
=====================================
Rolls back a model to a previously active version in the registry.
"""

import sys
import os
import argparse
import logging
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.config import settings

logging.basicConfig(level=logging.INFO, format="%(levelname)-8s [%(name)s] %(message)s")
logger = logging.getLogger("rollback_model")

def main():
    parser = argparse.ArgumentParser(description="Rollback a model version.")
    parser.add_argument("--model", type=str, required=True, help="Model name (e.g., dga_random_forest)")
    parser.add_argument("--version", type=str, required=True, help="Version to rollback to (e.g., v1.0.0)")
    args = parser.parse_args()

    models_dir = settings.model_registry_path
    target_dir = os.path.join(models_dir, args.model, args.version)
    manifest_path = os.path.join(target_dir, "manifest.json")
    
    if not os.path.exists(manifest_path):
        logger.error(f"Cannot rollback. Target manifest not found: {manifest_path}")
        sys.exit(1)
        
    registry_state_path = os.path.join(models_dir, "registry_state.json")
    state = {}
    if os.path.exists(registry_state_path):
        with open(registry_state_path, "r") as f:
            state = json.load(f)
            
    if args.model not in state:
        logger.error(f"Model {args.model} not found in registry state.")
        sys.exit(1)
        
    current = state[args.model].get("active_version")
    logger.info(f"Rolling back {args.model} from {current} to {args.version}")
        
    state[args.model]["active_version"] = args.version
    state[args.model]["status"] = "LOADED"
    state[args.model]["integrity"] = "VALID"
    
    with open(registry_state_path, "w") as f:
        json.dump(state, f, indent=4)
        
    logger.info(f"Successfully rolled back {args.model} to version {args.version}.")
    logger.info("Restart the API for changes to take effect.")

if __name__ == "__main__":
    main()
