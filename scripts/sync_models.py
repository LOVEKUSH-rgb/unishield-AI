#!/usr/bin/env python3
"""
UniShield AI -- Model Sync Script
=================================
Synchronizes ML models from the remote artifact store to the local runtime cache.
"""

import sys
import os
import argparse
import logging

# Ensure project root is in PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.config import settings
from src.models.storage import LocalArtifactStore
from src.models.sync import ModelSynchronizer

logging.basicConfig(level=logging.INFO, format="%(levelname)-8s [%(name)s] %(message)s")
logger = logging.getLogger("sync_models")

def main():
    parser = argparse.ArgumentParser(description="Synchronize ML models.")
    parser.add_argument("--model", type=str, help="Specific model name to sync")
    parser.add_argument("--version", type=str, help="Specific version to sync")
    args = parser.parse_args()

    if not settings.model_sync_enabled:
        logger.warning("MODEL_SYNC_ENABLED is false. Exiting.")
        sys.exit(0)
        
    logger.info(f"Artifact Store: {settings.model_artifact_store}")
    logger.info(f"Local Cache Path: {settings.model_registry_path}")

    # Initialize correct store
    if settings.model_artifact_store == "local":
        # In a real environment, the 'local' store source might be another mounted volume.
        # For simplicity in this local implementation, if sync is called, we assume
        # the user wants to sync from a 'remote_models' directory or similar.
        # Since we just generated the local models in `models/trained`, and the local cache
        # IS `models/trained`, syncing local to local is a no-op functionally,
        # but let's point the "remote" to a fictional 'data/model_store' for the sake of the abstraction.
        store_path = os.getenv("REMOTE_MODEL_STORE_PATH", "data/model_store")
        logger.info(f"Using LocalArtifactStore with source: {store_path}")
        store = LocalArtifactStore(base_path=store_path)
    else:
        logger.error(f"Unsupported artifact store: {settings.model_artifact_store}")
        sys.exit(1)

    synchronizer = ModelSynchronizer(store=store, local_cache_dir=settings.model_registry_path)

    models_to_sync = [args.model] if args.model else store.list_models()
    if not models_to_sync:
        logger.info("No models found in the store to synchronize.")
        sys.exit(0)

    success_count = 0
    failure_count = 0

    for model_name in models_to_sync:
        versions = [args.version] if args.version else store.list_versions(model_name)
        if not versions:
            logger.info(f"No versions found for model {model_name}")
            continue
            
        for version in versions:
            success = synchronizer.sync_model(model_name, version)
            if success:
                success_count += 1
            else:
                failure_count += 1

    logger.info(f"Sync complete. Success: {success_count}, Failed: {failure_count}")
    if failure_count > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
