# Omium Python SDK

Python SDK and CLI for the Omium platform: tracing, checkpoints, and workflow management. Use the **HTTP/remote API** with [api.omium.ai](https://api.omium.ai) for the hosted platform, or the CLI for local runs and project push.

**Documentation:** [docs.omium.ai](https://docs.omium.ai) — install, configure, CLI reference, configuration.

## Installation

### From PyPI (recommended)

```bash
python -m pip install --upgrade pip
python -m pip install omium
```

The package is published via PyPI Trusted Publisher. Verify with `omium --version`.

### From source (development)

```bash
cd omium-platform/sdk/python
pip install -e ".[dev]"
```

## Quick start (platform)

1. Get an API key from [app.omium.ai](https://app.omium.ai) and configure the CLI:

   ```bash
   omium init --api-key omium_xxx --api-url https://api.omium.ai
   ```

2. Initialize the SDK in your code (or run with `omium run` so the CLI injects config):

   ```python
   import omium
   omium.init(api_key="omium_xxx", project="my-agent")
   ```

3. Use decorators for tracing and checkpoints:

   ```python
   from omium import trace, checkpoint

   @trace("my_step")
   def my_step(data):
       return process(data)

   @checkpoint("important_step")
   async def important_step(data):
       return await do_work(data)
   ```

4. Run with the CLI to send traces to the platform:

   ```bash
   omium run your_script.py --project my-agent
   ```

5. Push a project to see it on the [Automations dashboard](https://app.omium.ai/automations):

   ```bash
   omium project init --name my-agent
   omium project push
   ```

## Checkpoint API (advanced / local)

For direct checkpoint-manager access (e.g. local gRPC), use `OmiumClient` and the `@checkpoint` decorator or `Checkpoint` context manager:

```python
from omium import OmiumClient, checkpoint, Checkpoint

client = OmiumClient(checkpoint_manager_url="localhost:7001")
await client.connect()
client.set_execution_context(execution_id="exec_123", agent_id="agent_1")

@checkpoint("validate_data", preconditions=["data is not None"])
async def validate_data(data: dict) -> dict:
    return {"validated": True, "data": data}

async with Checkpoint("important_state", client=client) as cp:
    result = await do_critical_thing()
    cp.update_state(step="complete")
```

See the package docstrings and [docs.omium.ai](https://docs.omium.ai) for full API details.

## Configuration

- **API URL:** Use `https://api.omium.ai` for the hosted platform. Override with `OMIUM_API_URL` or `omium configure --api-url <url>`. Do not add `/api/v1` to the base URL.
- **API key:** Set via `omium init` (stored in `~/.omium/config.json`) or `OMIUM_API_KEY`.
- **Project config:** Use `omium.toml` in your project root; see [docs.omium.ai](https://docs.omium.ai/configuration/omium-toml).

## Requirements

- Python >= 3.9 (3.11+ recommended)
- grpcio >= 1.69.0, < 2.0
- protobuf >= 5.26.1, < 6.0

## Testing

```bash
pip install -e ".[dev]"
pytest tests/
pytest tests/ --cov=omium --cov-report=html
```

## Publishing (maintainers)

Before deploying via GitHub Actions:

1. **Bump version in both places** (must match or the workflow will fail):
   - `pyproject.toml` → `version = "X.Y.Z"`
   - `omium/__init__.py` → `__version__ = "X.Y.Z"`
2. Commit and push, then run **Actions → Publish Omium Python SDK → Run workflow**.
3. The workflow runs tests, builds, and publishes to PyPI (skips if version already exists).

## License

Proprietary - Omium Platform
