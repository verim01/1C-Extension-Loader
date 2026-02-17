import json
import os
import re
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse


@dataclass
class ExtensionEntry:
    name: str
    cfe_path: str


@dataclass
class Profile:
    name: str
    infobase_dir: str
    infobase_file_path: str
    ib_username: str
    ib_password: str
    ibcmd_exe_path: str
    onec_exe_path: str
    log_dir: str
    timeout_sec: int
    lock_file_path: str
    extensions: List[ExtensionEntry]


@dataclass
class HostConfig:
    host: str
    port: int
    mount_path: str
    powershell_exe: str
    runner_script_path: str
    runner_timeout_sec: int
    profiles_dir: str
    default_profile: str


LAST_RUN: Dict[str, Any] = {}

# Форма веб-интерфейса: профиль и загрузка расширения (localhost)
UI_HTML = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>1C: профиль и загрузка расширения</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 640px; margin: 1rem auto; padding: 0 1rem; }
    h1 { font-size: 1.25rem; }
    .field { margin-bottom: 0.75rem; }
    .field label { display: block; font-weight: 500; margin-bottom: 0.25rem; }
    .field input { width: 100%; box-sizing: border-box; }
    .hint { font-size: 0.85rem; color: #666; margin-top: 0.2rem; }
    section { margin-bottom: 1.5rem; }
    .buttons { display: flex; gap: 0.5rem; margin-top: 1rem; }
    button { padding: 0.5rem 1rem; cursor: pointer; }
    #message { margin-top: 1rem; padding: 0.5rem; border-radius: 4px; }
    #message.success { background: #e8f5e9; }
    #message.error { background: #ffebee; }
  </style>
</head>
<body>
  <h1>Профиль 1С и загрузка расширения</h1>
  <p class="hint">Страница для localhost. Можно выбрать сохранённый профиль или заполнить форму и сохранить.</p>

  <section>
    <h2>Сохранённые профили</h2>
    <div class="field">
      <label for="savedProfiles">Выберите профиль</label>
      <select id="savedProfiles">
        <option value="">— выберите или заполните форму ниже —</option>
      </select>
    </div>
    <div class="buttons" style="margin-top: 0.5rem;">
      <button type="button" id="btnLoadProfile">Загрузить в форму</button>
    </div>
  </section>

  <form id="profileForm">
    <section>
      <h2>Профиль</h2>
      <div class="field">
        <label for="name">Имя профиля</label>
        <input type="text" id="name" name="name" required placeholder="например my-base">
      </div>
    </section>

    <section>
      <h2>База 1С</h2>
      <div class="field">
        <label for="infobase_dir">Директория базы (infobase_dir)</label>
        <input type="text" id="infobase_dir" name="infobase_dir" placeholder="H:\\YourBaseFolder">
      </div>
      <div class="field">
        <label for="infobase_file_path">Файл базы (infobase_file_path)</label>
        <input type="text" id="infobase_file_path" name="infobase_file_path" placeholder="H:\\YourBaseFolder\\1Cv8.1CD">
      </div>
    </section>

    <section>
      <h2>Доступ</h2>
      <div class="field">
        <label for="ib_username">Пользователь ИБ (ib_username)</label>
        <input type="text" id="ib_username" name="ib_username" placeholder="USER">
      </div>
      <div class="field">
        <label for="ib_password">Пароль (ib_password)</label>
        <input type="password" id="ib_password" name="ib_password" placeholder="пароль">
      </div>
      <div class="field">
        <label for="ib_password_env">Переменная окружения для пароля (опционально)</label>
        <input type="text" id="ib_password_env" name="ib_password_env" placeholder="OPTIONAL_ENV_VAR">
      </div>
    </section>

    <section>
      <h2>Исполняемые файлы</h2>
      <div class="field">
        <label for="onec_exe_path">Путь к 1cv8.exe (onec_exe_path)</label>
        <input type="text" id="onec_exe_path" name="onec_exe_path" placeholder="C:\\Program Files\\1cv8\\8.3.xx\\bin\\1cv8.exe">
      </div>
      <div class="field">
        <label for="ibcmd_exe_path">Путь к ibcmd.exe (ibcmd_exe_path)</label>
        <input type="text" id="ibcmd_exe_path" name="ibcmd_exe_path" placeholder="C:\\Program Files\\1cv8\\8.3.xx\\bin\\ibcmd.exe">
      </div>
    </section>

    <section>
      <h2>Логи и прочее</h2>
      <div class="field">
        <label for="log_dir">Папка логов (log_dir)</label>
        <input type="text" id="log_dir" name="log_dir" placeholder="D:\\projects\\proj4\\docs\\automation\\logs">
      </div>
      <div class="field">
        <label for="timeout_sec">Таймаут, сек (timeout_sec)</label>
        <input type="number" id="timeout_sec" name="timeout_sec" value="1200">
      </div>
      <div class="field">
        <label for="lock_file_path">Файл блокировки (lock_file_path, опционально)</label>
        <input type="text" id="lock_file_path" name="lock_file_path" placeholder="D:\\projects\\proj4\\docs\\automation\\.run.lock">
      </div>
    </section>

    <section>
      <h2>Расширение (минимум одно)</h2>
      <div class="field">
        <label for="extension_name">Имя расширения</label>
        <input type="text" id="extension_name" name="extension_name" placeholder="ExtensionName">
      </div>
      <div class="field">
        <label for="extension_cfe_path">Путь к .cfe</label>
        <input type="text" id="extension_cfe_path" name="extension_cfe_path" placeholder="D:\\path\\to\\extension.cfe">
      </div>
    </section>

    <div class="buttons">
      <button type="button" id="btnSave">Сохранить</button>
      <button type="button" id="btnRun">Запустить</button>
    </div>
  </form>

  <div id="message" role="status" aria-live="polite"></div>

  <script>
    const form = document.getElementById('profileForm');
    const message = document.getElementById('message');
    const savedProfiles = document.getElementById('savedProfiles');
    function showMsg(text, isError) {
      message.textContent = text;
      message.className = isError ? 'error' : 'success';
    }
    function getPayload() {
      const d = new FormData(form);
      const extName = d.get('extension_name') || '';
      const extPath = d.get('extension_cfe_path') || '';
      return {
        name: (d.get('name') || '').trim(),
        infobase_dir: (d.get('infobase_dir') || '').trim(),
        infobase_file_path: (d.get('infobase_file_path') || '').trim(),
        ib_username: (d.get('ib_username') || '').trim(),
        ib_password: (d.get('ib_password') || '').trim(),
        ib_password_env: (d.get('ib_password_env') || '').trim(),
        onec_exe_path: (d.get('onec_exe_path') || '').trim(),
        ibcmd_exe_path: (d.get('ibcmd_exe_path') || '').trim(),
        log_dir: (d.get('log_dir') || '').trim(),
        timeout_sec: parseInt(d.get('timeout_sec') || '1200', 10) || 1200,
        lock_file_path: (d.get('lock_file_path') || '').trim(),
        extensions: extName || extPath ? [{ name: extName, cfe_path: extPath }] : []
      };
    }
    async function loadProfilesList() {
      try {
        const r = await fetch('/api/profiles');
        const data = await r.json();
        if (!data.ok || !data.profiles) return;
        const sel = savedProfiles;
        sel.innerHTML = '<option value="">— выберите или заполните форму ниже —</option>';
        data.profiles.forEach(function(name) {
          const opt = document.createElement('option');
          opt.value = name;
          opt.textContent = name;
          sel.appendChild(opt);
        });
      } catch (e) {}
    }
    function fillFormFromProfile(p) {
      if (!p) return;
      const set = function(id, val) { const el = document.getElementById(id); if (el) el.value = val || ''; };
      set('name', p.name);
      set('infobase_dir', p.infobase_dir);
      set('infobase_file_path', p.infobase_file_path || '');
      set('ib_username', p.ib_username);
      set('ib_password', p.ib_password || '');
      set('ib_password_env', p.ib_password_env || '');
      set('onec_exe_path', p.onec_exe_path || '');
      set('ibcmd_exe_path', p.ibcmd_exe_path || '');
      set('log_dir', p.log_dir || '');
      set('timeout_sec', p.timeout_sec != null ? p.timeout_sec : 1200);
      set('lock_file_path', p.lock_file_path || '');
      const ext = (p.extensions && p.extensions[0]) || {};
      set('extension_name', ext.name || '');
      set('extension_cfe_path', ext.cfe_path || '');
    }
    loadProfilesList();
    document.getElementById('btnLoadProfile').onclick = async () => {
      const name = (savedProfiles.value || '').trim();
      if (!name) { showMsg('Выберите профиль в списке.', true); return; }
      try {
        const r = await fetch('/api/profiles/by-name?name=' + encodeURIComponent(name));
        const data = await r.json();
        if (data.ok && data.profile) { fillFormFromProfile(data.profile); showMsg('Профиль загружен в форму: ' + name); }
        else showMsg(data.message || 'Ошибка загрузки', true);
      } catch (e) { showMsg('Ошибка запроса: ' + e.message, true); }
    };
    document.getElementById('btnSave').onclick = async () => {
      const payload = getPayload();
      try {
        const r = await fetch('/api/profile', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        const data = await r.json();
        if (data.ok) { showMsg('Профиль сохранён: ' + (data.profile || data.path || '')); loadProfilesList(); }
        else showMsg(data.message || (data.errors && data.errors.join('; ')) || 'Ошибка', true);
      } catch (e) { showMsg('Ошибка запроса: ' + e.message, true); }
    };
    document.getElementById('btnRun').onclick = async () => {
      const profileName = (savedProfiles.value || '').trim() || getPayload().name;
      const payload = getPayload();
      const extensionName = (payload.extensions && payload.extensions[0] ? payload.extensions[0].name : null) || null;
      if (!profileName) { showMsg('Выберите сохранённый профиль в списке или заполните форму и укажите имя профиля.', true); return; }
      try {
        const r = await fetch('/api/load-extension', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ profile_name: profileName, extension_name: extensionName || undefined }) });
        const data = await r.json();
        if (data.ok) showMsg('Готово. ' + (data.log_file ? 'Лог: ' + data.log_file : data.message || ''));
        else showMsg(data.message || (data.errors && data.errors.join('; ')) || 'Ошибка', true);
      } catch (e) { showMsg('Ошибка запроса: ' + e.message, true); }
    };
  </script>
</body>
</html>
"""


def _default_config_path() -> Path:
    env_path = os.environ.get("MCP_AUTOMATION_CONFIG", "").strip()
    if env_path:
        return Path(env_path)
    return Path(__file__).resolve().parent / "host.config.json"


def _full_path(path_value: str, base: Path) -> str:
    p = Path(path_value)
    if p.is_absolute():
        return str(p)
    return str((base / p).resolve())


def _load_host_config(config_path: Path) -> HostConfig:
    base_dir = config_path.parent
    raw = json.loads(config_path.read_text(encoding="utf-8"))
    return HostConfig(
        host=raw.get("host", "127.0.0.1"),
        port=int(raw.get("port", 9010)),
        mount_path=raw.get("mount_path", "/mcp"),
        powershell_exe=raw.get("powershell_exe", "powershell"),
        runner_script_path=_full_path(raw["runner_script_path"], base_dir),
        runner_timeout_sec=int(raw.get("runner_timeout_sec", 1200)),
        profiles_dir=_full_path(raw.get("profiles_dir", "./profiles"), base_dir),
        default_profile=raw.get("default_profile", "default"),
    )


def _extract_json_payload(text: str) -> Dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        raise ValueError("Runner output is empty")
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError("Runner output does not contain JSON payload")
    return json.loads(stripped[start : end + 1])


def _load_profiles(config: HostConfig) -> Dict[str, Profile]:
    profiles_dir = Path(config.profiles_dir)
    if not profiles_dir.exists():
        return {}

    profiles: Dict[str, Profile] = {}
    for file_path in profiles_dir.glob("*.json"):
        raw = json.loads(file_path.read_text(encoding="utf-8"))
        profile_name = str(raw.get("name") or file_path.stem)
        password = str(raw.get("ib_password") or "")
        password_env = str(raw.get("ib_password_env") or "")
        if password_env:
            password = os.environ.get(password_env, password)

        raw_extensions = raw.get("extensions", [])
        extensions: List[ExtensionEntry] = []
        for item in raw_extensions:
            extensions.append(
                ExtensionEntry(name=str(item["name"]), cfe_path=str(item["cfe_path"]))
            )

        profiles[profile_name] = Profile(
            name=profile_name,
            infobase_dir=str(raw["infobase_dir"]),
            infobase_file_path=str(raw.get("infobase_file_path") or ""),
            ib_username=str(raw["ib_username"]),
            ib_password=password,
            ibcmd_exe_path=str(raw.get("ibcmd_exe_path") or ""),
            onec_exe_path=str(raw.get("onec_exe_path") or ""),
            log_dir=str(raw.get("log_dir") or ""),
            timeout_sec=int(raw.get("timeout_sec", 1200)),
            lock_file_path=str(raw.get("lock_file_path") or ""),
            extensions=extensions,
        )
    return profiles


def _resolve_profile(profiles: Dict[str, Profile], profile_name: Optional[str], default_profile: str) -> Profile:
    chosen = profile_name or default_profile
    if chosen not in profiles:
        raise ValueError(f"Profile not found: {chosen}")
    return profiles[chosen]


def _resolve_extension(profile: Profile, extension_name: Optional[str]) -> ExtensionEntry:
    if not profile.extensions:
        raise ValueError(f"Profile {profile.name} has no extensions configured")
    if not extension_name:
        return profile.extensions[0]

    for ext in profile.extensions:
        if ext.name == extension_name:
            return ext
    raise ValueError(f"Extension '{extension_name}' is not allowed in profile '{profile.name}'")


def _validate_profile(profile: Profile, extension: Optional[ExtensionEntry] = None) -> List[str]:
    errors: List[str] = []
    if not Path(profile.infobase_dir).exists():
        errors.append(f"infobase_dir not found: {profile.infobase_dir}")
    if profile.infobase_file_path and not Path(profile.infobase_file_path).exists():
        errors.append(f"infobase_file_path not found: {profile.infobase_file_path}")

    ibcmd_candidate = profile.ibcmd_exe_path
    if not ibcmd_candidate and profile.onec_exe_path:
        ibcmd_candidate = str(Path(profile.onec_exe_path).parent / "ibcmd.exe")
    if not ibcmd_candidate:
        errors.append("ibcmd path is not configured")
    elif not Path(ibcmd_candidate).exists():
        errors.append(f"ibcmd.exe not found: {ibcmd_candidate}")

    if not profile.ib_username:
        errors.append("ib_username is empty")
    if not profile.ib_password:
        errors.append("ib_password is empty (or ib_password_env is not set)")
    if profile.log_dir and not Path(profile.log_dir).exists():
        try:
            Path(profile.log_dir).mkdir(parents=True, exist_ok=True)
        except Exception:
            errors.append(f"log_dir is not writable: {profile.log_dir}")

    if extension:
        if not Path(extension.cfe_path).exists():
            errors.append(f"Extension file not found: {extension.cfe_path}")

    return errors


def _build_runner_config(profile: Profile, extension: ExtensionEntry) -> Dict[str, Any]:
    ibcmd_candidate = profile.ibcmd_exe_path
    if not ibcmd_candidate and profile.onec_exe_path:
        ibcmd_candidate = str(Path(profile.onec_exe_path).parent / "ibcmd.exe")

    return {
        "onec_exe_path": profile.onec_exe_path,
        "ibcmd_exe_path": ibcmd_candidate,
        "infobase_dir": profile.infobase_dir,
        "infobase_file_path": profile.infobase_file_path,
        "extension_cfe_path": extension.cfe_path,
        "extension_name": extension.name,
        "ib_username": profile.ib_username,
        "ib_password": profile.ib_password,
        "timeout_sec": profile.timeout_sec,
        "log_dir": profile.log_dir,
        "lock_file_path": profile.lock_file_path,
        "disable_startup_dialogs": True,
        "extra_designer_args": [],
    }


def _run_runner(config: HostConfig, runner_config: Dict[str, Any]) -> Dict[str, Any]:
    run_id = uuid.uuid4().hex
    if not Path(config.runner_script_path).exists():
        return {
            "ok": False,
            "status": "error",
            "message": f"Скрипт раннера не найден: {config.runner_script_path}. Укажите верный путь в host.config.json (runner_script_path) или восстановите файл load-extension-ibcmd.ps1.",
            "run_id": run_id,
        }
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            suffix=".json",
            delete=False,
        ) as temp_file:
            json.dump(runner_config, temp_file, ensure_ascii=False, indent=2)
            temp_path = temp_file.name

        cmd = [
            config.powershell_exe,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            config.runner_script_path,
            "-ConfigPath",
            temp_path,
        ]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=config.runner_timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": "timeout",
            "exit_code": 30,
            "message": "Runner process timeout exceeded",
            "run_id": run_id,
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": "error",
            "message": f"Runner launch failed: {exc}",
            "run_id": run_id,
        }
    finally:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass

    payload: Dict[str, Any] = {}
    parse_error = ""
    try:
        payload = _extract_json_payload(proc.stdout or "")
    except Exception as exc:
        parse_error = str(exc)

    exit_code = int(payload.get("exit_code", proc.returncode))
    message = payload.get("message", "Runner finished")
    ok_from_payload_or_exit = bool(payload.get("ok", proc.returncode == 0))
    # Runner script may exit 0 and print "Runner finished" but omit "ok": true, or use exit_code in payload
    if payload and exit_code == 0 and message == "Runner finished":
        ok_from_payload_or_exit = True

    # When runner stdout had no valid JSON, show parse error in message so UI shows real cause
    if parse_error:
        message = parse_error
        if proc.returncode != 0:
            message = f"{parse_error} (exit code: {proc.returncode})"
        if proc.stderr:
            stderr_preview = (proc.stderr or "").strip()[-500:]
            if stderr_preview:
                message = f"{message}. stderr: {stderr_preview}"

    response: Dict[str, Any] = {
        "ok": ok_from_payload_or_exit,
        "status": payload.get("status", "success" if proc.returncode == 0 else "error"),
        "exit_code": exit_code,
        "duration_ms": payload.get("duration_ms"),
        "log_file": payload.get("log_file"),
        "message": message,
        "run_id": run_id,
    }
    if parse_error:
        response["parser_warning"] = f"JSON parse failed: {parse_error}"
        response["stdout_tail"] = (proc.stdout or "")[-1000:]
    if proc.stderr:
        response["stderr_tail"] = proc.stderr[-1000:]

    return response


CONFIG_PATH = _default_config_path()
CONFIG = _load_host_config(CONFIG_PATH)

mcp = FastMCP(
    name="proj4-1c-automation-host",
    instructions=(
        "Loads 1C extensions into configured infobases via PowerShell runner and "
        "profile-based whitelist. Does not execute arbitrary shell commands."
    ),
    host=CONFIG.host,
    port=CONFIG.port,
    streamable_http_path=CONFIG.mount_path,
)


def _sanitize_profile_name(name: str) -> str:
    """Допустимы только буквы, цифры, дефис, подчёркивание; без '..' и разделителей пути."""
    if not name or ".." in name or "/" in name or "\\" in name:
        raise ValueError("Недопустимое имя профиля")
    if not re.match(r"^[a-zA-Z0-9_\-\u0400-\u04FF]+$", name):
        raise ValueError("Имя профиля содержит недопустимые символы")
    return name.strip()


def _profile_from_request_body(body: Dict[str, Any]) -> Dict[str, Any]:
    """Собирает и нормализует JSON профиля из тела запроса; проверяет обязательные поля."""
    name = (body.get("name") or "").strip()
    if not name:
        raise ValueError("name обязательно")
    _sanitize_profile_name(name)

    infobase_dir = (body.get("infobase_dir") or "").strip()
    if not infobase_dir:
        raise ValueError("infobase_dir обязательно")

    ib_username = (body.get("ib_username") or "").strip()
    if not ib_username:
        raise ValueError("ib_username обязательно")

    ib_password = (body.get("ib_password") or "").strip()
    ib_password_env = (body.get("ib_password_env") or "").strip()
    if not ib_password and not ib_password_env:
        raise ValueError("Укажите ib_password или ib_password_env")

    ibcmd_exe_path = (body.get("ibcmd_exe_path") or "").strip()
    onec_exe_path = (body.get("onec_exe_path") or "").strip()
    if not ibcmd_exe_path and not onec_exe_path:
        raise ValueError("Укажите ibcmd_exe_path или onec_exe_path")

    log_dir = (body.get("log_dir") or "").strip()
    if not log_dir:
        raise ValueError("log_dir обязательно")

    extensions = body.get("extensions") or []
    if not isinstance(extensions, list) or len(extensions) == 0:
        raise ValueError("Нужно минимум одно расширение (name и cfe_path)")
    out_extensions: List[Dict[str, str]] = []
    for i, ext in enumerate(extensions):
        if not isinstance(ext, dict):
            raise ValueError(f"extensions[{i}] должен быть объектом с name и cfe_path")
        en = (ext.get("name") or "").strip()
        cp = (ext.get("cfe_path") or "").strip()
        if not en or not cp:
            raise ValueError(f"extensions[{i}]: name и cfe_path обязательны")
        out_extensions.append({"name": en, "cfe_path": cp})

    return {
        "name": name,
        "infobase_dir": infobase_dir,
        "infobase_file_path": (body.get("infobase_file_path") or "").strip(),
        "ib_username": ib_username,
        "ib_password": ib_password,
        "ib_password_env": ib_password_env or None,
        "ibcmd_exe_path": ibcmd_exe_path or None,
        "onec_exe_path": onec_exe_path or None,
        "log_dir": log_dir,
        "timeout_sec": int(body.get("timeout_sec") or 1200) or 1200,
        "lock_file_path": (body.get("lock_file_path") or "").strip() or None,
        "extensions": out_extensions,
    }


@mcp.custom_route("/", methods=["GET"])
async def serve_root(request: Request) -> HTMLResponse:
    return HTMLResponse(UI_HTML)


@mcp.custom_route("/ui", methods=["GET"])
async def serve_ui(request: Request) -> HTMLResponse:
    return HTMLResponse(UI_HTML)


@mcp.custom_route("/api/profiles", methods=["GET"])
async def api_list_profiles(request: Request) -> JSONResponse:
    """Список имён сохранённых профилей для выбора в форме."""
    result = list_profiles()
    return JSONResponse(result)


@mcp.custom_route("/api/profiles/by-name", methods=["GET"])
async def api_get_profile(request: Request) -> JSONResponse:
    """Получить один профиль по имени (для загрузки в форму)."""
    name = (request.query_params.get("name") or "").strip()
    if not name:
        return JSONResponse(
            {"ok": False, "message": "Укажите параметр name"},
            status_code=400,
        )
    try:
        _sanitize_profile_name(name)
    except ValueError as e:
        return JSONResponse(
            {"ok": False, "message": str(e)},
            status_code=400,
        )
    profiles_dir = Path(CONFIG.profiles_dir)
    profile_path = profiles_dir / f"{name}.json"
    if not profile_path.is_file():
        return JSONResponse(
            {"ok": False, "message": f"Профиль не найден: {name}"},
            status_code=404,
        )
    try:
        data = json.loads(profile_path.read_text(encoding="utf-8"))
    except Exception as e:
        return JSONResponse(
            {"ok": False, "message": f"Ошибка чтения профиля: {e}"},
            status_code=500,
        )
    return JSONResponse({"ok": True, "profile": data})


@mcp.custom_route("/api/profile", methods=["POST"])
async def api_save_profile(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse(
            {"ok": False, "message": f"Неверное тело запроса: {e}"},
            status_code=400,
        )
    try:
        profile_data = _profile_from_request_body(body)
    except ValueError as e:
        return JSONResponse(
            {"ok": False, "message": str(e)},
            status_code=400,
        )
    name = profile_data["name"]
    profiles_dir = Path(CONFIG.profiles_dir)
    profiles_dir.mkdir(parents=True, exist_ok=True)
    profile_path = profiles_dir / f"{name}.json"
    out = {k: v for k, v in profile_data.items() if v is not None}
    if out.get("ib_password_env") is None:
        out.pop("ib_password_env", None)
    profile_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    return JSONResponse({"ok": True, "profile": name, "path": str(profile_path)})


@mcp.custom_route("/api/load-extension", methods=["POST"])
async def api_load_extension(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception as e:
        return JSONResponse(
            {"ok": False, "message": f"Неверное тело запроса: {e}"},
            status_code=400,
        )
    profile_name = (body.get("profile_name") or "").strip()
    if not profile_name:
        return JSONResponse(
            {"ok": False, "message": "profile_name обязателен"},
            status_code=400,
        )
    extension_name = (body.get("extension_name") or "").strip() or None
    try:
        result = load_extension(profile_name=profile_name, extension_name=extension_name)
    except Exception as exc:
        return JSONResponse(
            {"ok": False, "message": str(exc)},
            status_code=500,
        )
    status_code = 200 if result.get("ok") else 400
    return JSONResponse(result, status_code=status_code)


@mcp.tool(name="list_profiles", description="List available automation profiles.")
def list_profiles() -> Dict[str, Any]:
    profiles = _load_profiles(CONFIG)
    return {
        "ok": True,
        "default_profile": CONFIG.default_profile,
        "profiles": sorted(list(profiles.keys())),
    }


@mcp.tool(
    name="list_available_extensions",
    description="Return whitelist of available extension(s) for selected profile.",
)
def list_available_extensions(profile_name: Optional[str] = None) -> Dict[str, Any]:
    try:
        profiles = _load_profiles(CONFIG)
        profile = _resolve_profile(profiles, profile_name, CONFIG.default_profile)
        return {
            "ok": True,
            "profile": profile.name,
            "extensions": [
                {"name": ext.name, "path": ext.cfe_path, "mode": "profile-whitelist"}
                for ext in profile.extensions
            ],
        }
    except Exception as exc:
        return {"ok": False, "status": "error", "message": str(exc)}


@mcp.tool(
    name="validate_environment",
    description="Validate profile paths, credentials, and extension file availability.",
)
def validate_environment(
    profile_name: Optional[str] = None,
    extension_name: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        profiles = _load_profiles(CONFIG)
        profile = _resolve_profile(profiles, profile_name, CONFIG.default_profile)
        extension = _resolve_extension(profile, extension_name) if extension_name else None
        errors = _validate_profile(profile, extension)
        return {
            "ok": len(errors) == 0,
            "profile": profile.name,
            "extension": extension.name if extension else None,
            "errors": errors,
        }
    except Exception as exc:
        return {"ok": False, "status": "error", "message": str(exc)}


@mcp.tool(
    name="load_extension",
    description="Load extension from selected profile into selected infobase.",
)
def load_extension(
    profile_name: Optional[str] = None,
    extension_name: Optional[str] = None,
) -> Dict[str, Any]:
    global LAST_RUN
    try:
        profiles = _load_profiles(CONFIG)
        profile = _resolve_profile(profiles, profile_name, CONFIG.default_profile)
        extension = _resolve_extension(profile, extension_name)
        errors = _validate_profile(profile, extension)
        if errors:
            return {
                "ok": False,
                "status": "error",
                "profile": profile.name,
                "extension": extension.name,
                "message": "Environment validation failed",
                "errors": errors,
            }

        runner_cfg = _build_runner_config(profile, extension)
        result = _run_runner(CONFIG, runner_cfg)
        result["profile"] = profile.name
        result["extension"] = extension.name
        LAST_RUN = result
        return result
    except Exception as exc:
        return {"ok": False, "status": "error", "message": str(exc)}


@mcp.tool(
    name="load_extension_prototype",
    description="Backward-compatible alias: load extension in default profile.",
)
def load_extension_prototype(extension_name: Optional[str] = None) -> Dict[str, Any]:
    return load_extension(profile_name=CONFIG.default_profile, extension_name=extension_name)


@mcp.tool(
    name="get_last_run",
    description="Return the most recent load run result.",
)
def get_last_run() -> Dict[str, Any]:
    if not LAST_RUN:
        return {"ok": True, "message": "No runs yet", "last_run": None}
    return {"ok": True, "last_run": LAST_RUN}


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
