# Phase 25 Audit — ML Artifact Lifecycle

## 1. Current Model Discovery & Loading
The system uses a `ModelRegistry` class inside `src/models/registry.py`. Models are discovered through a hardcoded default path `models/trained/`. 
The method `discover_and_validate(expected_name, preferred_type)` attempts to find:
- `{expected_name}_{preferred_type}.json` or `.pkl`
- `{expected_name}_{preferred_type}_meta.json` or `.json`

There are no versioned directories. The system relies on exactly matching the naming convention in the flat directory `models/trained/`.

## 2. Metadata Validation
`ModelRegistry._validate_metadata()` verifies that the JSON metadata file exists, can be parsed, contains a `model_name` and `features` key, and crucially checks that `feature_schema_version` equals the hardcoded `CURRENT_SCHEMA_VERSION = "v1"`.

## 3. Schema Compatibility
Compatibility is enforced via `feature_schema_version = "v1"`. If it does not match, the model is rejected.

## 4. Model Loading
When a detector starts (e.g. `src/detectors/dga_detector.py`), it calls `registry.discover_and_validate()`. If validation passes, it loads the model artifact into memory using `joblib.load()` or `xgb.Booster()`.

## 5. Statistical Fallback
If `discover_and_validate()` returns `None, None`, the detector gracefully initializes its internal state without throwing an exception and falls back to manually defined threshold-based detection rules (e.g. counting unique domains or looking for high-entropy domains in the DGA detector).

## 6. Supported Formats
- `xgboost` (JSON artifacts)
- `random_forest` (PKL artifacts)

## 7. Model Path Configuration
Currently, `models_dir` defaults to `"models/trained/"`. The API and dashboard don't provide a way to override this elegantly via Pydantic settings.

## 8. Model Versioning
The metadata contains `"model_version": "v1.0.0"`, but there is no structural versioning in the filesystem. A new model would overwrite the old one destructively.

## 9. Integrity Validation (SHA-256)
**Missing.** There is no cryptographic hashing applied. If `dga_random_forest.pkl` is partially downloaded or maliciously altered, `joblib.load()` will attempt to deserialize it, potentially leading to arbitrary code execution (ACE).

## 10. Rollback Capability
**Missing.** Since artifacts are overwritten destructively in the flat directory, rollback is impossible unless the operator manually finds and replaces the old files.
