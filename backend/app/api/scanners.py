"""Scanner binary diagnostics: which external tools the backend can see."""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter

from app.config import settings
from app.scanners.common import resolve_binary, run_cmd

router = APIRouter()

_VERSION_ARGS = {
    "subfinder": ["-version"],
    "httpx": ["-version"],
    "katana": ["-version"],
    "nuclei": ["-version"],
}


@router.get("/api/scanners/status")
def scanners_status() -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    for name, args in _VERSION_ARGS.items():
        path = resolve_binary(name, settings)
        version = None
        if path:
            result = run_cmd([path, *args], timeout=15)
            output = f"{result.stdout or ''}\n{result.stderr or ''}"
            version = next((line.strip() for line in output.splitlines() if line.strip()), None)
            if version:
                version = version[:300]
        items.append(
            {
                "name": name,
                "path": path,
                "found": bool(path),
                "version": version,
            }
        )
    return {"items": items, "demo_mode": settings.demo_mode}
