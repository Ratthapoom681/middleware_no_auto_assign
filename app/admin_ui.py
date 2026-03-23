from pathlib import Path
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from .config import AppConfig, save_config
from .log_stream import get_log_entries


router = APIRouter()
ADMIN_ASSETS_PATH = Path(__file__).with_name("admin_assets")
ADMIN_HTML_PATH = ADMIN_ASSETS_PATH / "admin.html"
ADMIN_DESTINATION_HTML_PATH = ADMIN_ASSETS_PATH / "admin_destination.html"
ADMIN_ROUTING_HTML_PATH = ADMIN_ASSETS_PATH / "admin_routing.html"
ADMIN_TEAMS_HTML_PATH = ADMIN_ASSETS_PATH / "admin_teams.html"
ADMIN_FINDINGS_HTML_PATH = ADMIN_ASSETS_PATH / "admin_findings.html"
ADMIN_CREATE_HTML_PATH = ADMIN_ASSETS_PATH / "admin_create.html"
ADMIN_USERS_HTML_PATH = ADMIN_ASSETS_PATH / "admin_users.html"

_get_config: Callable[[], AppConfig] | None = None
_reload_runtime_config: Callable[[AppConfig], None] | None = None
_get_dojo_options: Callable[[], dict[str, list[dict[str, Any]]]] | None = None
_create_dojo_object: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None


def configure_admin(
    get_config: Callable[[], AppConfig],
    reload_runtime_config: Callable[[AppConfig], None],
    get_dojo_options: Callable[[], dict[str, list[dict[str, Any]]]],
    create_dojo_object: Callable[[str, dict[str, Any]], dict[str, Any]],
) -> None:
    global _get_config, _reload_runtime_config, _get_dojo_options, _create_dojo_object
    _get_config = get_config
    _reload_runtime_config = reload_runtime_config
    _get_dojo_options = get_dojo_options
    _create_dojo_object = create_dojo_object


def _require_runtime() -> tuple[
    Callable[[], AppConfig],
    Callable[[AppConfig], None],
    Callable[[], dict[str, list[dict[str, Any]]]],
    Callable[[str, dict[str, Any]], dict[str, Any]],
]:
    if _get_config is None or _reload_runtime_config is None or _get_dojo_options is None or _create_dojo_object is None:
        raise RuntimeError("Admin UI runtime is not configured.")
    return _get_config, _reload_runtime_config, _get_dojo_options, _create_dojo_object


@router.get("/admin", response_class=HTMLResponse)
async def admin_page():
    return ADMIN_HTML_PATH.read_text(encoding="utf-8")


@router.get("/admin/destination", response_class=HTMLResponse)
async def admin_destination_page():
    return ADMIN_DESTINATION_HTML_PATH.read_text(encoding="utf-8")


@router.get("/admin/routing", response_class=HTMLResponse)
async def admin_routing_page():
    return ADMIN_ROUTING_HTML_PATH.read_text(encoding="utf-8")


@router.get("/admin/teams", response_class=HTMLResponse)
async def admin_teams_page():
    return ADMIN_TEAMS_HTML_PATH.read_text(encoding="utf-8")


@router.get("/admin/findings", response_class=HTMLResponse)
async def admin_findings_page():
    return ADMIN_FINDINGS_HTML_PATH.read_text(encoding="utf-8")


@router.get("/admin/create", response_class=HTMLResponse)
async def admin_create_page():
    return ADMIN_CREATE_HTML_PATH.read_text(encoding="utf-8")


@router.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page():
    return ADMIN_USERS_HTML_PATH.read_text(encoding="utf-8")


@router.get("/admin/assets/{asset_name}")
async def admin_asset(asset_name: str):
    asset_path = ADMIN_ASSETS_PATH / asset_name
    if not asset_path.exists():
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    return FileResponse(asset_path)


@router.get("/admin/api/config")
async def admin_get_config():
    get_config, _, _, _ = _require_runtime()
    return JSONResponse(get_config().model_dump(mode="json"))


@router.post("/admin/api/config")
async def admin_save_config(request: Request):
    _, reload_runtime_config, _, _ = _require_runtime()
    payload = await request.json()
    try:
        new_config = AppConfig(**payload)
        save_config(new_config)
        reload_runtime_config(new_config)
        return JSONResponse({"status": "saved"})
    except Exception as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)


@router.get("/admin/api/dojo-options")
async def admin_dojo_options():
    _, _, get_dojo_options, _ = _require_runtime()
    try:
        return JSONResponse(get_dojo_options())
    except Exception as exc:
        return JSONResponse({"detail": str(exc)}, status_code=502)


@router.post("/admin/api/dojo/{object_type}")
async def admin_create_dojo_object(object_type: str, request: Request):
    _, _, _, create_dojo_object = _require_runtime()
    payload = await request.json()
    try:
        return JSONResponse(create_dojo_object(object_type, payload))
    except Exception as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)


@router.get("/admin/api/logs")
async def admin_logs():
    return JSONResponse({"entries": get_log_entries()})
