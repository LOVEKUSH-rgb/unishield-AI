# Phase 32 Security Review

## 1. Benchmark Script Input Safety
All benchmark inputs come exclusively from:
- `data/samples/demo_flows_expanded.jsonl` (JSONL, no embedded code)
- `data/samples/phase32_edge_cases.jsonl` (generated locally by `generate_edge_cases.py`)

**Assessment**: The `benchmark_detectors.py` script reads JSONL lines and passes them to `FeatureVector(**data)` via Pydantic model validation. Pydantic provides strong type coercion and will raise `ValidationError` for unexpected types. There is no `eval()`, `exec()`, `subprocess` invocation, or `pickle.loads()` of dataset content. **No code execution risk from dataset content.**

## 2. Path Validation
- The `--output` path in `benchmark_detectors.py` is controlled at runtime.
- The script does not enforce that the output path stays inside `reports/`. This is a minor risk for local misuse, but the scripts are not exposed over the network.
- The API's `/evaluation/status` endpoint reads from a static committed path (`reports/phase32/phase31_vs_phase32.json`), which is hardcoded, not user-supplied.
- The existing `validate_safe_path()` function in `src/api/app.py` prevents path traversal for replay/ingest endpoints.

**Recommendation**: For production deployments, add a configurable `BASE_OUTPUT_DIR` guard in benchmark scripts.

## 3. JSON Deserialization Safety
All deserialization uses `json.loads()` from Python's standard library, which is safe from arbitrary code execution. No `pickle.loads()` is invoked during benchmarking. Existing ML model loading uses pickle under the registry's integrity hash check (SHA-256 manifest), which is preserved.

**Assessment**: No unsafe deserialization is introduced.

## 4. Secrets and Credentials
- Benchmark reports (`reports/phase32/*.json`) contain only metric values, flow statistics, and evidence strings. No JWT keys, database URLs, or environment secrets are logged.
- The `error_analysis.json` contains flow-level feature values (IP addresses, port numbers, durations, packet counts) derived from synthetic data. This presents no real-world PII exposure.
- The CI workflow sets `JWT_SECRET_KEY` via environment variable (not hardcoded in source). The value `ci-test-secret-key-do-not-use` is clearly labeled as non-production.

**Assessment**: No secrets are exposed in reports or logs.

## 5. Memory Safety (Unbounded Allocation)
- The benchmark reads `demo_flows_expanded.jsonl` (10,000 flows) and loads all into memory. At roughly 1KB per flow record, this is approximately 10MB — well within normal bounds.
- `detection_explanations.json` stores one entry per FP/FN across all detectors. In the worst case this would be 6 detectors × 10,000 flows = 60,000 entries. Each entry is small (< 2KB). This is bounded at ~120MB maximum, which is acceptable for a benchmark script.

**Recommendation**: For very large datasets (>1M flows), add streaming output to avoid memory issues.

## 6. API Malformed Input Safety
- All API endpoints that process user input use Pydantic schema validation.
- The `/evaluation/status` endpoint performs only a file read of a known path. No user input is processed.
- Malformed JSON from external clients cannot crash the API — FastAPI/Pydantic return `422 Unprocessable Entity` responses.

## 7. Active Network Behavior
None introduced. All benchmark scripts are strictly offline, processing local files only.

## 8. Verdict
No critical security issues were introduced in Phase 32. The minor path-validation concern for `--output` in benchmark scripts is noted as a future hardening recommendation.

| Category | Status |
|---|---|
| Arbitrary code execution via dataset | ✅ Not possible |
| Path traversal in API endpoints | ✅ Protected (existing guard) |
| Path traversal in benchmark scripts | ⚠️ Minor: No restriction on `--output` path |
| Unsafe deserialization (JSON) | ✅ Safe (`json.loads()` only) |
| Unsafe deserialization (Pickle ML) | ✅ Protected (SHA-256 integrity check) |
| Secrets in reports | ✅ None found |
| Active network scanning | ✅ Not introduced |
| Unbounded memory allocation | ✅ Bounded for current dataset sizes |
