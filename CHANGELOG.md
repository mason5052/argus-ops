# Changelog

## [0.1.0] - 2026-02-22

### Added
- Initial release
- K8s collector (pods, nodes, events, deployments)
- Resource analyzer (CPU, memory, disk thresholds)
- Pod health analyzer (CrashLoopBackOff, OOMKilled, Pending)
- Node health analyzer (NotReady, DiskPressure, MemoryPressure)
- AI-powered diagnosis via LiteLLM (supports OpenAI, Anthropic, Ollama, 100+ providers)
- Rich console output with severity-colored findings
- JSON output mode
- YAML + environment variable configuration
- CLI commands: scan, diagnose, config init/show/test
