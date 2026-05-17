import sys
import importlib.util

packages = ['fastapi', 'uvicorn', 'pydantic', 'redis', 'openai', 'github', 'httpx', 'omium', 'sse_starlette']
missing = []

for pkg in packages:
    spec = importlib.util.find_spec(pkg)
    status = 'OK' if spec else 'MISSING'
    print(f'{status}: {pkg}')
    if not spec:
        missing.append(pkg)

if missing:
    print(f'\nMissing packages: {", ".join(missing)}')
    print('Run: pip install -r requirements.txt')
    sys.exit(1)
else:
    print('\nAll dependencies installed!')
    sys.exit(0)

# Made with Bob
