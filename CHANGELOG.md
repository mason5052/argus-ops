# Changelog

All notable changes to Argus-Ops are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.3.0] - 2026-02-23

### Added
- `store.py`: SQLite-backed `IncidentStore` with WAL journal mode; incident history
  and trend data persist across process restarts
- `web/watch_service.py`: `DiagnoseStatus` enum (`IDLE` / `RUNNING` / `ERROR`)
  exposes AI diagnosis state to API consumers
- `WatchService.get_incidents()`: reads incident history from SQLite instead of the
  previous in-memory deque (unlimited history, paginated)
- `WatchService(db_path=":memory:")` parameter for hermetic unit tests
- `engine/pipeline.py`: `CollectorCircuitBreaker` with CLOSED / OPEN / HALF_OPEN
  state machine (failure_threshold=3, reset_timeout=60s)
- `engine/pipeline.py`: tenacity exponential backoff retry per collector
  (3 attempts, 2s -> 4s -> 8s wait, via `@retry`)
- `logging_config.py`: JSON-structured log formatter (`_JsonFormatter`);
  `RotatingFileHandler` support (10 MB per file, 5 backups)
- `ai/cost.py`: `decimal.Decimal` arithmetic for all monetary operations
  (eliminates floating-point rounding drift on per-token charges)
- `web/api.py`: `/api/status` now returns `diagnose_status` and `diagnose_error` fields
- `web/api.py`: `/api/diagnoses` now reads from SQLite via `watch.get_incidents()`
  instead of the in-memory state snapshot
- 58 new tests: `test_store.py` (16), `test_cli.py` (19), `test_api.py` (23) --
  total test count: 109

### Changed
- `WatchService.diagnose_now()`: concurrent callers now raise `RuntimeError`
  ("AI diagnosis is already in progress") instead of silently returning `[]`
- `WatchService._trend`: replaced `deque(maxlen=120)` with plain list; trend is
  also persisted via `IncidentStore.save_trend_point()`

### Fixed
- Circuit breaker prevents repeated K8s API calls when a collector is continuously
  failing (e.g. cluster unreachable), reducing log noise and CPU usage

---

## [0.2.0] - 2026-02-23

### Added
- `collectors/k8s.py`: `_API_TIMEOUT = 30` applied to all six K8s API calls
  (`list_node`, `list_namespace`, `list_namespaced_pod`, `list_namespaced_event`,
  `list_namespaced_deployment`, `list_namespaced_cron_job`)
- `collectors/k8s.py`: kubeconfig file permission check -- warns if mode is not 600
- `collectors/k8s.py`: `_redact_event_message()` strips Bearer tokens, private
  registry credentials, and RFC-1918 IP addresses from K8s event messages before
  sending to AI providers; truncates messages at 512 characters
- `ai/provider.py`: `_DiagnosisResponse` Pydantic model validates LLM JSON response
  (type coercion for lists, confidence clamped 0.0-1.0)
- `ai/provider.py`: LLM response size limit of 32 KB (`_MAX_CONTENT_BYTES`)
- `ai/provider.py`: `timeout=60` (`_LLM_TIMEOUT`) on all LiteLLM completion calls
- `ai/provider.py`: markdown code-fence stripping via regex before JSON parse
- Web dashboard at `argus-ops serve` (requires `pip install argus-ops[web]`)
- Docker image and K8s deployment manifests under `deploy/k8s/`

### Fixed
- `ai/provider.py`: removed `litellm.api_base = base_url` global state mutation;
  `api_base` is now passed per-call via `completion_kwargs["api_base"]`, preventing
  race conditions in multi-provider `serve` deployments

---

## [0.1.0] - 2026-02-22

### Added
- Initial release
- K8s collector (pods, nodes, events, deployments, CronJobs)
- Resource analyzer (CPU/memory limits enforcement)
- Pod health analyzer (CrashLoopBackOff, OOMKilled, Pending, ImagePullBackOff)
- Node health analyzer (NotReady, DiskPressure, MemoryPressure, PIDPressure, cordoned)
- AI-powered diagnosis via LiteLLM (OpenAI, Anthropic, Ollama, 100+ providers)
- Jinja2 prompt template for structured diagnosis
- Rich console reporter with severity-coloured output
- JSON reporter
- YAML + environment variable configuration system
- CLI commands: `scan`, `diagnose`, `config init`, `config show`, `config test`
- 51 tests, all passing
- GitHub Actions CI (Python 3.10 / 3.11 / 3.12, ubuntu-latest)
- README with architecture diagram and quick start guide

[Unreleased]: https://github.com/mason5052/argus-ops/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/mason5052/argus-ops/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mason5052/argus-ops/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mason5052/argus-ops/releases/tag/v0.1.0
