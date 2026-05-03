from ..db import fetchrow, execute, fetch

async def insert_form(
    page_id: int,
    action_url: str,
    method: str = "GET",
    session_id: str | None = None,
    js_only: bool = False,
    phase: str = "guest"
) -> dict:
    await execute(
        """
        INSERT INTO forms (page_id, action_url, method, session_id, js_only, phase, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,NOW())
        """,
        page_id, action_url, method, session_id, js_only, phase,
    )
    row = await fetchrow(
        """
        SELECT * FROM forms
        WHERE page_id=$1 AND action_url=$2
        ORDER BY created_at DESC
        LIMIT 1
        """,
        page_id, action_url
    )
    return row or {}

async def insert_form_input(
    form_id: int,
    name: str | None,
    type: str | None,
    input_id: str | None,
    placeholder: str | None
) -> dict:
    await execute(
        """
        INSERT INTO form_inputs (form_id, name, type, input_id, placeholder, created_at)
        VALUES ($1,$2,$3,$4,$5,NOW())
        """,
        form_id, name, type, input_id, placeholder
    )
    row = await fetchrow(
        """
        SELECT * FROM form_inputs
        WHERE form_id=$1 AND name=$2
        ORDER BY created_at DESC
        LIMIT 1
        """,
        form_id, name
    )
    return row or {}


async def get_forms_by_session(session_id: str) -> list[dict]:
    return await fetch("SELECT * FROM forms WHERE session_id=$1", session_id)

async def get_forms_by_page(page_id):
    query = "SELECT id, action_url, method FROM forms WHERE page_id = $1"
    rows = await fetch(query, page_id)
    return [{'id': r['id'], 'action_url': r['action_url'], 'method': r['method']} for r in rows]

async def get_form_inputs(form_id):
    query = "SELECT name FROM form_inputs WHERE form_id = $1"
    rows = await fetch(query, form_id)
    return [r['name'] for r in rows]