"""
API de integrações pro ecossistema UFBA (gradline + sync-faculdade skill).

Duas funções, sem nada em comum além de "evitar reimplementar em outra
linguagem o que já validamos em Python":

1. Classroom OAuth broker — o client_secret do Google Cloud fica só aqui.
   Quem consome (skill, app) nunca vê o secret, só recebe/usa um
   refresh_token próprio.
2. Calendar OAuth broker — mesmo modelo do Classroom (mesmo client OAuth,
   escopo diferente): cada pessoa loga com a própria conta Google e recebe
   o próprio refresh_token. Todo evento criado/lido/apagado é no calendário
   de quem está chamando, nunca num calendário fixo — não existe conceito de
   "dono" da API aqui, só de quem tá autenticado em cada chamada.
3. Moodle proxy genérico — repassa qualquer wsfunction pro
   webservice/rest/server.php de um Moodle (site_url + wstoken vêm de quem
   chama; este serviço não guarda token de ninguém). Existe só pra
   centralizar a lógica de request/erro num lugar só, reusável por qualquer
   cliente (Python, TypeScript, o que for) sem duplicar parsing.

O que NÃO faz, de propósito: não captura o wstoken do Moodle (isso exige
login institucional interativo — CAFe/SAML — que só pode rodar do lado de
quem está logando, nunca em servidor). Ver `moodle_auth.py` na skill
sync-faculdade pra essa parte.
"""
import os

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, Response
from pydantic import BaseModel

app = FastAPI(title="ufba-integrations-api")

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
CLASSROOM_SCOPES = " ".join([
    "https://www.googleapis.com/auth/classroom.courses.readonly",
    "https://www.googleapis.com/auth/classroom.coursework.me.readonly",
    "https://www.googleapis.com/auth/classroom.coursework.students.readonly",
    "https://www.googleapis.com/auth/classroom.courseworkmaterials.readonly",
    "https://www.googleapis.com/auth/classroom.announcements.readonly",
    "https://www.googleapis.com/auth/classroom.topics.readonly",
    "https://www.googleapis.com/auth/drive.readonly",
])
CALENDAR_SCOPES = "https://www.googleapis.com/auth/calendar"
CALENDAR_API_BASE = "https://www.googleapis.com/calendar/v3"

# Mesmo client OAuth reusado pros dois (GOOGLE_CLASSROOM_CLIENT_ID/SECRET,
# nome histórico do Classroom, mas é o client Google geral — só troca o
# escopo pedido em cada fluxo).


def _env(name):
    value = os.environ.get(name)
    if not value:
        raise HTTPException(500, f"Falta variável de ambiente {name} no serviço")
    return value


def _oauth_start(scope, redirect_path, state=None):
    client_id = _env("GOOGLE_CLASSROOM_CLIENT_ID")
    redirect_uri = _env("PUBLIC_BASE_URL") + redirect_path
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "access_type": "offline",
        "prompt": "consent",
    }
    if state:
        params["state"] = state
    return RedirectResponse(str(httpx.URL(GOOGLE_AUTH_URL, params=params)))


def _oauth_callback(code, error, redirect_path, env_var_name, state=None):
    if error or not code:
        return HTMLResponse(f"<h2>Erro na autorização: {error or 'sem code'}</h2>", status_code=400)

    client_id = _env("GOOGLE_CLASSROOM_CLIENT_ID")
    client_secret = _env("GOOGLE_CLASSROOM_CLIENT_SECRET")
    redirect_uri = _env("PUBLIC_BASE_URL") + redirect_path

    resp = httpx.post(GOOGLE_TOKEN_URL, data={
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    })
    if resp.status_code != 200:
        return HTMLResponse(f"<h2>Erro trocando code por token: {resp.text}</h2>", status_code=502)

    tokens = resp.json()
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        return HTMLResponse(
            "<h2>Google não devolveu refresh_token. Revogue o acesso do app em "
            "myaccount.google.com/permissions e tente de novo.</h2>",
            status_code=502,
        )

    # Se veio um state "local:<porta>", quem chamou /oauth/start está rodando
    # localmente e subiu um listener nessa porta pra receber o token sozinho
    # (ver skill renovar-token-calendar) — nesse caso a página faz o POST
    # automático via JS em vez de exigir copiar e colar. O client_secret nunca
    # passa por aqui, só o refresh_token final.
    local_port = None
    if state and state.startswith("local:"):
        candidate = state[len("local:"):]
        if candidate.isdigit():
            local_port = int(candidate)

    if local_port and 1 <= local_port <= 65535:
        return HTMLResponse(f"""
            <h2 id="status">Autorizado. Enviando o token pro seu Claude Code local...</h2>
            <pre style="font-size:14px;background:#eee;padding:12px;user-select:all">
{env_var_name}={refresh_token}
            </pre>
            <script>
              fetch("http://localhost:{local_port}/token", {{
                method: "POST",
                headers: {{"Content-Type": "application/json"}},
                body: JSON.stringify({{env_var_name: "{env_var_name}", refresh_token: "{refresh_token}"}}),
              }}).then(() => {{
                document.getElementById("status").textContent = "Token entregue. Pode fechar esta aba.";
              }}).catch(() => {{
                document.getElementById("status").textContent =
                  "Não consegui entregar automaticamente (listener local não respondeu) — copie o valor acima à mão.";
              }});
            </script>
        """)

    # Sem listener local (ex: sessão cloud) — mostra na tela pra copiar. Este
    # serviço não guarda o token em lugar nenhum, é passado direto pra quem
    # está logando.
    return HTMLResponse(f"""
        <h2>Autorizado. Copie este valor pro seu .env local:</h2>
        <pre style="font-size:14px;background:#eee;padding:12px;user-select:all">
{env_var_name}={refresh_token}
        </pre>
        <p>Pode fechar esta aba depois de copiar.</p>
    """)


def _oauth_refresh(refresh_token):
    client_id = _env("GOOGLE_CLASSROOM_CLIENT_ID")
    client_secret = _env("GOOGLE_CLASSROOM_CLIENT_SECRET")
    resp = httpx.post(GOOGLE_TOKEN_URL, data={
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    })
    if resp.status_code != 200:
        raise HTTPException(502, f"Falha ao renovar token: {resp.text}")
    return resp.json()["access_token"]


@app.get("/health")
def health():
    return {"ok": True}


# ---------------------------------------------------------------------------
# Classroom OAuth broker
# ---------------------------------------------------------------------------

@app.get("/classroom/oauth/start")
def classroom_oauth_start():
    """Redireciona pro consentimento do Google. redirect_uri é sempre este
    próprio serviço (/classroom/oauth/callback) — precisa estar cadastrado
    no Google Cloud Console como URI de redirecionamento autorizado."""
    return _oauth_start(CLASSROOM_SCOPES, "/classroom/oauth/callback")


@app.get("/classroom/oauth/callback")
def classroom_oauth_callback(code: str | None = None, error: str | None = None):
    return _oauth_callback(code, error, "/classroom/oauth/callback", "CLASSROOM_REFRESH_TOKEN")


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/classroom/token")
def classroom_token(body: RefreshRequest):
    """Troca um refresh_token (de qualquer aluno, obtido via /oauth/start)
    por um access_token de curta duração. O secret nunca sai do servidor."""
    return {"access_token": _oauth_refresh(body.refresh_token)}


# ---------------------------------------------------------------------------
# Calendar OAuth broker — mesmo modelo do Classroom acima. Cada evento
# criado/lido/apagado é sempre no calendário de quem está autenticado
# (o access_token passado em cada chamada), nunca num calendário fixo.
# ---------------------------------------------------------------------------

@app.get("/calendar/oauth/start")
def calendar_oauth_start(local_port: int | None = None):
    state = f"local:{local_port}" if local_port else None
    return _oauth_start(CALENDAR_SCOPES, "/calendar/oauth/callback", state=state)


@app.get("/calendar/oauth/callback")
def calendar_oauth_callback(code: str | None = None, error: str | None = None, state: str | None = None):
    return _oauth_callback(code, error, "/calendar/oauth/callback", "GOOGLE_REFRESH_TOKEN", state=state)


@app.post("/calendar/token")
def calendar_token(body: RefreshRequest):
    return {"access_token": _oauth_refresh(body.refresh_token)}


@app.get("/calendar/events")
def calendar_list_events(access_token: str, calendar_id: str = "primary", max_results: int = 20):
    resp = httpx.get(
        f"{CALENDAR_API_BASE}/calendars/{calendar_id}/events",
        params={"maxResults": max_results, "singleEvents": "true", "orderBy": "startTime"},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


class CreateEventRequest(BaseModel):
    access_token: str
    calendar_id: str = "primary"
    summary: str
    start: str  # RFC3339, ex: "2026-09-01T09:00:00-03:00"
    end: str
    description: str | None = None


@app.post("/calendar/events")
def calendar_create_event(body: CreateEventRequest):
    payload = {
        "summary": body.summary,
        "start": {"dateTime": body.start},
        "end": {"dateTime": body.end},
    }
    if body.description:
        payload["description"] = body.description

    resp = httpx.post(
        f"{CALENDAR_API_BASE}/calendars/{body.calendar_id}/events",
        json=payload,
        headers={"Authorization": f"Bearer {body.access_token}"},
    )
    if resp.status_code not in (200, 201):
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.delete("/calendar/events/{calendar_id}/{event_id}")
def calendar_delete_event(calendar_id: str, event_id: str, access_token: str):
    resp = httpx.delete(
        f"{CALENDAR_API_BASE}/calendars/{calendar_id}/events/{event_id}",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if resp.status_code not in (200, 204):
        raise HTTPException(resp.status_code, resp.text)
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Classroom API proxy genérico — mesmo espírito do /moodle/call, mas a
# Classroom API é REST (method + path), não um wsfunction único, então o
# formato do corpo é diferente. access_token vem de quem chama (via
# /classroom/token) — nunca guardado aqui.
# ---------------------------------------------------------------------------

CLASSROOM_API_BASE = "https://classroom.googleapis.com/v1"
DRIVE_API_BASE = "https://www.googleapis.com/drive/v3"


class ClassroomCallRequest(BaseModel):
    access_token: str
    method: str = "GET"
    path: str  # ex: "/courses/{id}/courseWork" — relativo a CLASSROOM_API_BASE
    params: dict = {}
    paginate_key: str | None = None  # ex: "courseWork" — junta todas as páginas nesse campo


@app.post("/classroom/call")
def classroom_call(body: ClassroomCallRequest):
    """Repassa uma chamada REST pra Classroom API. Se paginate_key for
    passado, segue nextPageToken automaticamente e junta tudo num array só
    (mesmo comportamento do paginate() que existia em classroom.py)."""
    headers = {"Authorization": f"Bearer {body.access_token}"}
    url = CLASSROOM_API_BASE + body.path

    if not body.paginate_key:
        resp = httpx.request(body.method, url, params=body.params, headers=headers, timeout=30)
        if resp.status_code != 200:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json() if resp.content else {}

    items = []
    params = dict(body.params)
    while True:
        resp = httpx.request(body.method, url, params=params, headers=headers, timeout=30)
        if resp.status_code != 200:
            raise HTTPException(resp.status_code, resp.text)
        page = resp.json()
        items.extend(page.get(body.paginate_key, []))
        next_token = page.get("nextPageToken")
        if not next_token:
            break
        params["pageToken"] = next_token
    return {body.paginate_key: items}


@app.get("/classroom/drive-file")
def classroom_drive_file_metadata(access_token: str, file_id: str):
    """Metadados de um arquivo do Drive anexado a um coursework (nome,
    mimeType, modifiedTime) — usado pra decidir se precisa rebaixar."""
    resp = httpx.get(
        f"{DRIVE_API_BASE}/files/{file_id}",
        params={"fields": "id,name,mimeType,modifiedTime"},
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=30,
    )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.get("/classroom/drive-download")
def classroom_drive_download(access_token: str, file_id: str, export_mime: str | None = None):
    """Baixa o binário de um anexo do Drive. Google Docs/Slides/Sheets
    nativos não têm bytes 'crus' — passe export_mime (ex: application/pdf)
    pra usar o endpoint de export em vez de alt=media."""
    headers = {"Authorization": f"Bearer {access_token}"}
    if export_mime:
        url = f"{DRIVE_API_BASE}/files/{file_id}/export"
        params = {"mimeType": export_mime}
    else:
        url = f"{DRIVE_API_BASE}/files/{file_id}"
        params = {"alt": "media"}

    resp = httpx.get(url, params=params, headers=headers, timeout=60)
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, f"Erro baixando do Drive: {resp.text}")
    return Response(
        content=resp.content,
        media_type=resp.headers.get("content-type", "application/octet-stream"),
    )


# ---------------------------------------------------------------------------
# Moodle proxy genérico
# ---------------------------------------------------------------------------

class MoodleCallRequest(BaseModel):
    site_url: str  # ex: "https://ava.ufba.br"
    wstoken: str
    wsfunction: str
    params: dict = {}


@app.post("/moodle/call")
def moodle_call(body: MoodleCallRequest):
    """Repassa uma chamada Web Services pro Moodle indicado. Genérico de
    propósito — não hardcoda wsfunction nenhuma, pra servir qualquer Moodle
    (não só ava.ufba.br) e qualquer função (core_course_get_contents,
    mod_assign_get_assignments, etc.) sem precisar de deploy novo."""
    payload = {
        "wstoken": body.wstoken,
        "wsfunction": body.wsfunction,
        "moodlewsrestformat": "json",
        **body.params,
    }
    url = body.site_url.rstrip("/") + "/webservice/rest/server.php"
    resp = httpx.post(url, data=payload, timeout=30)
    if resp.status_code != 200:
        raise HTTPException(502, f"Erro HTTP do Moodle ({resp.status_code}): {resp.text}")

    result = resp.json()
    if isinstance(result, dict) and "exception" in result:
        raise HTTPException(400, result)
    return result


@app.get("/moodle/download")
def moodle_download(fileurl: str, wstoken: str):
    """Repassa o binário de um arquivo do Moodle (fileurl vem de dentro do
    retorno de core_course_get_contents/mod_assign_get_assignments — não é
    um id arbitrário, é a URL completa do arquivo específico). Sem ganho de
    segurança em existir (o wstoken já é da própria pessoa, ela podia baixar
    direto) — só evita duplicar "concatena token=" em outro cliente/linguagem."""
    sep = "&" if "?" in fileurl else "?"
    url = f"{fileurl}{sep}token={wstoken}"
    resp = httpx.get(url, timeout=60, follow_redirects=True)
    if resp.status_code != 200:
        raise HTTPException(502, f"Erro HTTP do Moodle ({resp.status_code}) baixando arquivo")

    return Response(
        content=resp.content,
        media_type=resp.headers.get("content-type", "application/octet-stream"),
    )
