# ufba-integrations-api

API pequena que serve duas integrações do ecossistema UFBA (gradline +
skill `sync-faculdade` de `~/dev/me/rotina-pessoal`), pra não duplicar
lógica de acesso a Classroom/Moodle em mais de uma linguagem:

1. **Classroom OAuth broker** — o `client_secret` do Google Cloud fica só
   aqui. Quem consome (a skill, o app) nunca vê o secret, só um
   `refresh_token` próprio (obtido logando com a própria conta Google em
   `/classroom/oauth/start`).
2. **Moodle proxy genérico** — `POST /moodle/call` repassa qualquer
   `wsfunction` pro `webservice/rest/server.php` de qualquer Moodle
   (`site_url` + `wstoken` vêm de quem chama; este serviço não guarda
   token de ninguém).

## O que NÃO faz, de propósito

Não captura o `wstoken` do Moodle — isso exige login institucional
interativo (CAFe/SAML), que só pode rodar do lado de quem está logando,
nunca em servidor. Essa parte continua em
`~/dev/me/rotina-pessoal/.claude/skills/sync-faculdade/scripts/moodle_auth.py`
(Playwright, local, login manual na janela).

## Rodando local

```bash
uv run --with fastapi --with uvicorn --with httpx uvicorn main:app --reload
```

Precisa de `GOOGLE_CLASSROOM_CLIENT_ID`, `GOOGLE_CLASSROOM_CLIENT_SECRET` e
`PUBLIC_BASE_URL` no ambiente (ver `.env.example`).

## Deploy

Railway, projeto `ufba-app` (workspace Espectro Tech), serviço próprio
separado do `ufba-backend`. `Procfile` já configurado pro Nixpacks detectar
e rodar via `uvicorn`.
