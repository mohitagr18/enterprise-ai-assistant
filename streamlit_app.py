"""
Sentinel AI — Secure Enterprise AI Assistant Portal.

A premium, interactive Streamlit client demonstrating the 12-layer security pipeline,
knowledge base RAG management, and administrative operations.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

import httpx
import redis.asyncio as aioredis
import streamlit as st

# Setup page configurations
st.set_page_config(
    page_title="Sentinel AI — Security Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Dark theme custom styling
st.markdown(
    """
    <style>
    /* Dark glassmorphic styling */
    .stApp {
        background-color: #0f111a;
        color: #e2e8f0;
    }
    .main-header {
        font-family: 'Outfit', 'Inter', sans-serif;
        background: linear-gradient(90deg, #6366f1 0%, #a855f7 50%, #ec4899 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: 800;
        font-size: 3rem;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-family: 'Inter', sans-serif;
        color: #94a3b8;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 0.75rem;
        padding: 1rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    .security-badge {
        display: inline-block;
        padding: 0.25rem 0.5rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-right: 0.5rem;
        margin-bottom: 0.5rem;
    }
    .badge-pass { background-color: #065f46; color: #34d399; border: 1px solid #059669; }
    .badge-block { background-color: #7f1d1d; color: #f87171; border: 1px solid #dc2626; }
    .badge-neutral { background-color: #1e293b; color: #94a3b8; border: 1px solid #475569; }
    
    /* Custom indicator dot */
    .indicator {
        height: 10px;
        width: 10px;
        background-color: #10b981;
        border-radius: 50%;
        display: inline-block;
        margin-right: 8px;
        box-shadow: 0 0 8px #10b981;
    }
    .indicator-offline {
        background-color: #ef4444;
        box-shadow: 0 0 8px #ef4444;
    }
    </style>
    """,
    unsafe_allowed_html=True,
)

# Backend URL configuration
BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000")

# Initialize session state variables
if "token" not in st.session_state:
    st.session_state.token = None
if "role" not in st.session_state:
    st.session_state.role = None
if "username" not in st.session_state:
    st.session_state.username = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "session_id" not in st.session_state:
    st.session_state.session_id = f"session_{int(time.time())}"
if "backend_online" not in st.session_state:
    st.session_state.backend_online = False
if "tokens_consumed" not in st.session_state:
    st.session_state.tokens_consumed = 0


# Helper to run async tasks inside Streamlit
def run_async(coro):
    return asyncio.run(coro)


# Check backend health
def check_health() -> dict[str, Any] | None:
    try:
        r = httpx.get(f"{BACKEND_URL}/health", timeout=2.0)
        if r.status_code == 200:
            st.session_state.backend_online = True
            return r.json()
    except Exception:
        st.session_state.backend_online = False
    return None


health_info = check_health()

# =====================================================================
# SIDEBAR
# =====================================================================
with st.sidebar:
    st.markdown("### 🛡️ Sentinel Status")
    
    # 1. Health indicator
    if st.session_state.backend_online and health_info:
        uptime = health_info.get("uptime_seconds", 0)
        uptime_str = (
            f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m"
            if uptime > 60
            else f"{uptime}s"
        )
        st.markdown(
            f'<div style="display: flex; align-items: center;"><span class="indicator"></span>'
            f'<span style="color:#10b981; font-weight:600;">FastAPI Online</span></div>'
            f'<div style="font-size:0.8rem; color:#94a3b8; margin-left:18px;">Uptime: {uptime_str} | v{health_info.get("version", "1.0.0")}</div>',
            unsafe_allowed_html=True,
        )
    else:
        st.markdown(
            '<div style="display: flex; align-items: center;"><span class="indicator indicator-offline"></span>'
            '<span style="color:#ef4444; font-weight:600;">FastAPI Offline</span></div>'
            '<div style="font-size:0.8rem; color:#94a3b8; margin-left:18px;">Start server: <code>uvicorn sentinel.main:app</code></div>',
            unsafe_allowed_html=True,
        )

    st.markdown("---")

    # 2. Authentication State
    if st.session_state.token:
        st.markdown(f"**Current User:** `{st.session_state.username}`")
        role_colors = {"admin": "#a855f7", "power_user": "#10b981", "standard": "#3b82f6"}
        role_color = role_colors.get(st.session_state.role, "#94a3b8")
        st.markdown(
            f'**Clearance Role:** <span style="color:{role_color}; font-weight:bold; '
            f'text-transform: uppercase; font-size:0.9rem;">{st.session_state.role}</span>',
            unsafe_allowed_html=True,
        )
        st.markdown(f"**Session ID:** `{st.session_state.session_id}`")
        st.markdown(f"**Tokens Consumed:** `{st.session_state.tokens_consumed:,}`")
        
        if st.sidebar.button("Logout Session", use_container_width=True):
            # Logout
            try:
                headers = {"Authorization": f"Bearer {st.session_state.token}"}
                httpx.post(f"{BACKEND_URL}/auth/logout", headers=headers, timeout=2.0)
            except Exception:
                pass
            st.session_state.token = None
            st.session_state.role = None
            st.session_state.username = None
            st.session_state.chat_history = []
            st.session_state.tokens_consumed = 0
            st.rerun()
    else:
        st.markdown("🔐 *Session not authenticated. Log in to continue.*")


# =====================================================================
# LOGIN PAGE
# =====================================================================
if not st.session_state.token:
    st.markdown('<h1 class="main-header">Sentinel AI</h1>', unsafe_allowed_html=True)
    st.markdown('<p class="sub-header">Secure Enterprise AI Assistant & Security Gate</p>', unsafe_allowed_html=True)

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("### 🔑 Identity Provider Login")
        st.write("Sentinel AI uses JWT authentication and Role-Based Access Control (RBAC).")

        login_mode = st.radio("Authentication Method", ["Mock Roles (Quick Access)", "Custom Credentials"])

        username = ""
        password = ""

        if login_mode == "Mock Roles (Quick Access)":
            mock_role = st.selectbox(
                "Select Mock Identity Role",
                ["Standard Employee (standarduser)", "Power User / Editor (poweruser)", "System Administrator (admin)"],
            )
            if "standarduser" in mock_role:
                username = "standarduser"
                password = "userpass123"
            elif "poweruser" in mock_role:
                username = "poweruser"
                password = "powerpass123"
            else:
                username = "admin"
                password = "adminpass123"
        else:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

        if st.button("Authenticate Session", type="primary", use_container_width=True):
            if not st.session_state.backend_online:
                st.error("Failed to authenticate: FastAPI backend is offline.")
            else:
                try:
                    payload = {"username": username, "password": password}
                    r = httpx.post(f"{BACKEND_URL}/auth/login", json=payload, timeout=5.0)
                    if r.status_code == 200:
                        data = r.json()
                        st.session_state.token = data["access_token"]
                        st.session_state.username = username
                        # Decode role from token payload
                        import jose.jwt
                        decoded = jose.jwt.get_unverified_claims(data["access_token"])
                        st.session_state.role = decoded.get("role", "standard")
                        st.success("Session authenticated successfully!")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error(f"Login failed: {r.json().get('detail', 'Unknown error')}")
                except Exception as e:
                    st.error(f"Authentication Request Error: {str(e)}")

    with col2:
        st.markdown("### 🔬 Enterprise Security Layers")
        st.write(
            "This application validates every input and output through a defense-in-depth security framework "
            "comprising 12 specialized layers. Each request goes through the following checklist:"
        )
        layers = [
            ("1. Input Validator", "Checks size, formats, null bytes, regex-injection patterns."),
            ("2. Semantic Guard", "Uses ML toxicity and prompt-injection detection (llm-guard)."),
            ("3. System Prompt Hardener", "Wraps documents in system tags; enforces assistant boundaries."),
            ("4. Input Restructurer", "Counts tokens, truncates content, checks against token quotas."),
            ("5. Token Budget", "Limits daily expenditures according to user roles."),
            ("6. Content Moderator", "Evaluates content for violent, hateful, or harmful speech."),
            ("7. Context Isolator", "Filters files by clearance; wraps RAG text in secure tags."),
            ("8. Output Validator", "Validates output format, intercepts traceback leakages."),
            ("9. Audit Logger", "Always fires; writes tamper-evident audit trails to audit.jsonl."),
            ("10. Agent Identity", "Enforces privilege ceilings and allowed agent capabilities."),
            ("11. Human Gate", "Intercepts high-stakes actions, requiring admin approval."),
            ("12. Threat Monitor", "Maintains behavioral anomaly counters; locks out abusive sessions.")
        ]
        for name, desc in layers:
            st.markdown(f"**{name}** — *{desc}*")

    st.stop()


# =====================================================================
# MAIN PORTAL INTERFACE (AUTHENTICATED)
# =====================================================================

# Build tabs based on permissions
tabs_list = ["💬 Chat Console", "📚 Knowledge Base"]
if st.session_state.role == "admin":
    tabs_list.append("🛡️ Admin Center")

tabs = st.tabs(tabs_list)

# ---------------------------------------------------------------------
# TAB 1: CHAT CONSOLE
# ---------------------------------------------------------------------
with tabs[0]:
    st.markdown("### 💬 Secure Chat Console")
    
    # Session configurations
    with st.expander("🛠️ Chat Parameters & Safety Overrides", expanded=False):
        c1, c2 = st.columns(2)
        with c1:
            include_context = st.checkbox("Include Context (RAG Search)", value=True)
        with c2:
            custom_session = st.text_input("Active Session ID", value=st.session_state.session_id)
            if custom_session != st.session_state.session_id:
                st.session_state.session_id = custom_session
                st.session_state.chat_history = []
                st.rerun()

    # Display chat room history
    for chat_item in st.session_state.chat_history:
        role = chat_item["role"]
        avatar = "👤" if role == "user" else "🛡️"
        
        with st.chat_message(role, avatar=avatar):
            st.markdown(chat_item["content"])
            
            # Show metadata if available (for assistant replies or blocks)
            if "metadata" in chat_item:
                meta = chat_item["metadata"]
                
                # Render layers metadata
                if "layers_fired" in meta:
                    st.markdown('<div style="margin-top: 8px;">', unsafe_allowed_html=True)
                    for layer in meta["layers_fired"]:
                        st.markdown(
                            f'<span class="security-badge badge-pass">✓ {layer}</span>',
                            unsafe_allowed_html=True,
                        )
                    st.markdown("</div>", unsafe_allowed_html=True)
                
                if "blocked_layer" in meta:
                    st.markdown(
                        f'<div style="margin-top:8px;">'
                        f'<span class="security-badge badge-block">🚫 {meta["blocked_layer"]}</span>'
                        f'<span class="security-badge badge-neutral">Code: {meta["error_code"]}</span>'
                        f'</div>',
                        unsafe_allowed_html=True,
                    )
                
                # Render token/time stats
                if "tokens_used" in meta or "processing_time_ms" in meta:
                    tok = meta.get("tokens_used", {})
                    in_t = tok.get("input", 0)
                    out_t = tok.get("output", 0)
                    time_ms = meta.get("processing_time_ms", 0)
                    st.caption(f"⚡ {time_ms} ms | 🪙 Tokens: In={in_t}, Out={out_t}")

    # Chat user input
    user_input = st.chat_input("Type message (Try injection attacks to test safety)...")

    if user_input:
        # Append user message
        st.session_state.chat_history.append({"role": "user", "content": user_input})
        st.chat_message("user", avatar="👤").markdown(user_input)

        # Prepare payload and headers
        headers = {"Authorization": f"Bearer {st.session_state.token}"}
        payload = {
            "message": user_input,
            "session_id": st.session_state.session_id,
            "include_context": include_context,
        }

        # Make API call
        with st.chat_message("assistant", avatar="🛡️"):
            message_placeholder = st.empty()
            message_placeholder.markdown("🔍 *Evaluating request through security pipeline...*")
            
            try:
                response = httpx.post(f"{BACKEND_URL}/chat", json=payload, headers=headers, timeout=45.0)
                
                if response.status_code == 200:
                    # Successful completion
                    data = response.json()
                    assistant_text = data["response"]
                    
                    # Store consumption stats
                    tokens = data.get("tokens_used", {})
                    st.session_state.tokens_consumed += tokens.get("input", 0) + tokens.get("output", 0)
                    
                    metadata = {
                        "layers_fired": data.get("layers_fired", []),
                        "tokens_used": tokens,
                        "processing_time_ms": data.get("processing_time_ms", 0),
                    }
                    
                    # Update placeholder and state
                    message_placeholder.markdown(assistant_text)
                    st.session_state.chat_history.append({
                        "role": "assistant",
                        "content": assistant_text,
                        "metadata": metadata,
                    })
                    st.rerun()

                elif response.status_code in (202, 400, 403, 500):
                    # Blocked request or exception
                    data = response.json()
                    err_msg = data.get("detail", "Request failed.")
                    err_code = data.get("error_code", "UNKNOWN_ERROR")
                    
                    # Determine which layer blocked based on error_code
                    blocked_layer = "unknown"
                    if "INPUT_VALIDATION" in err_code: blocked_layer = "input_validator"
                    elif "SEMANTIC" in err_code: blocked_layer = "semantic_guard"
                    elif "CONTENT" in err_code: blocked_layer = "content_moderator"
                    elif "TOKEN" in err_code: blocked_layer = "token_budget"
                    elif "AGENT_IDENTITY" in err_code: blocked_layer = "agent_identity"
                    elif "THREAT" in err_code: blocked_layer = "threat_monitor"
                    elif "HUMAN" in err_code: blocked_layer = "human_gate"
                    elif "CONTEXT" in err_code: blocked_layer = "context_isolator"
                    elif "OUTPUT" in err_code: blocked_layer = "output_validator"

                    # Custom styling for different blocks
                    if response.status_code == 202:
                        # Human gate pending
                        pending_card = (
                            f"### ⏳ High-Stakes Action Intercepted\n"
                            f"The model requested a gated operation: **{data.get('details', {}).get('action_category', 'unknown')}**.\n\n"
                            f"This requires human-in-the-loop validation.\n\n"
                            f"**Approval Token:** `{data.get('details', {}).get('approval_token', '')}`  \n"
                            f"*(Log in as an Administrator to approve this token)*"
                        )
                        message_placeholder.markdown(pending_card)
                        st.session_state.chat_history.append({
                            "role": "assistant",
                            "content": pending_card,
                            "metadata": {
                                "blocked_layer": blocked_layer,
                                "error_code": err_code,
                            },
                        })
                    else:
                        block_card = (
                            f"### 🚫 Security Policy Blocked Request\n"
                            f"**Violation Type:** `{err_code}`  \n"
                            f"**Security Reason:** {err_msg}"
                        )
                        message_placeholder.markdown(block_card)
                        st.session_state.chat_history.append({
                            "role": "assistant",
                            "content": block_card,
                            "metadata": {
                                "blocked_layer": blocked_layer,
                                "error_code": err_code,
                            },
                        })
                    st.rerun()
                else:
                    message_placeholder.error(f"HTTP Connection Error: Received status code {response.status_code}")
                    
            except Exception as e:
                message_placeholder.error(f"Failed to query backend assistant API: {str(e)}")


# ---------------------------------------------------------------------
# TAB 2: KNOWLEDGE BASE
# ---------------------------------------------------------------------
with tabs[1]:
    st.markdown("### 📚 RAG Knowledge Base Manager")
    st.write("Indexed documents are embedded and retrieved securely according to classification levels.")

    headers = {"Authorization": f"Bearer {st.session_state.token}"}

    # Upload section for Power Users and Admins
    if st.session_state.role in ("admin", "power_user"):
        st.markdown("#### 📤 Index New Document")
        
        with st.form("document_upload_form"):
            uploaded_file = st.file_uploader("Select file (txt, md, json, csv)", type=["txt", "md", "json", "csv"])
            classification_level = st.selectbox(
                "Document Security Classification",
                ["public", "internal", "confidential", "restricted"]
            )
            source = st.text_input("Source Identifier (e.g. hr_policies, company_wiki)", value="internal_docs")
            
            submit_doc = st.form_submit_button("Index Document")
            
            if submit_doc:
                if not uploaded_file:
                    st.warning("Please upload a file first.")
                elif not source.strip():
                    st.warning("Source identifier is required.")
                else:
                    try:
                        # Construct multipart form request
                        files = {"file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
                        data = {"classification_level": classification_level, "source": source}
                        
                        r = httpx.post(f"{BACKEND_URL}/documents", files=files, data=data, headers=headers, timeout=20.0)
                        
                        if r.status_code == 201:
                            res = r.json()
                            st.success(
                                f"Success: Document indexed! ID: `{res['document_id'][:12]}...` "
                                f"({res['filename']})"
                            )
                        else:
                            st.error(f"Ingestion Blocked: {r.json().get('detail', 'Rejected by safety bounds.')}")
                    except Exception as e:
                        st.error(f"Ingestion Request Error: {str(e)}")
    else:
        st.info("🔒 *Note: Only users with Editor (power_user) or Admin roles can index new documents.*")

    st.markdown("---")
    st.markdown("#### 🗄️ Currently Indexed Documents")

    # Fetch document list
    try:
        r = httpx.get(f"{BACKEND_URL}/documents?page=1&limit=100", headers=headers, timeout=5.0)
        if r.status_code == 200:
            docs_data = r.json()
            docs_list = docs_data.get("documents", [])
            total_docs = docs_data.get("total", 0)

            if not docs_list:
                st.write("No documents indexed in ChromaDB yet.")
            else:
                st.caption(f"Showing {len(docs_list)} of {total_docs} total documents")
                
                # Render document tables
                for doc in docs_list:
                    c_id, c_src, c_level, c_time, c_act = st.columns([2, 2, 2, 2, 1])
                    with c_id:
                        st.write(f"`{doc['id']}`")
                    with c_src:
                        st.write(doc["source"])
                    with c_level:
                        # Color coding clearance levels
                        color_map = {
                            "public": "gray", "internal": "blue",
                            "confidential": "orange", "restricted": "red"
                        }
                        color = color_map.get(doc["classification_level"], "gray")
                        st.markdown(
                            f'<span style="color:{color}; font-weight:bold;">{doc["classification_level"].upper()}</span>',
                            unsafe_allowed_html=True,
                        )
                    with c_time:
                        st.write(doc.get("created_at") or "N/A")
                    with c_act:
                        if st.session_state.role == "admin":
                            if st.button("Delete", key=f"del_{doc['id']}", type="secondary"):
                                try:
                                    del_r = httpx.delete(f"{BACKEND_URL}/documents/{doc['id']}", headers=headers, timeout=5.0)
                                    if del_r.status_code == 200:
                                        st.success("Deleted document!")
                                        time.sleep(0.5)
                                        st.rerun()
                                    else:
                                        st.error(f"Failed: {del_r.json().get('detail')}")
                                except Exception as err:
                                    st.error(str(err))
                        else:
                            st.write("🔒 *Admin only*")
        else:
            st.error("Failed to query documents: Unauthorized.")
    except Exception as e:
        st.error(f"Database query exception: {str(e)}")


# ---------------------------------------------------------------------
# TAB 3: ADMIN CENTER (ADMIN ROLE ONLY)
# ---------------------------------------------------------------------
if st.session_state.role == "admin":
    with tabs[2]:
        st.markdown("### 🛡️ Security Operations & Audit Control Center")
        
        headers = {"Authorization": f"Bearer {st.session_state.token}"}

        admin_tabs = st.tabs(["⏳ Pending Approvals", "📊 Daily Usage & Limits", "📜 Audit Log Viewer"])

        # -----------------------------------------------------------------
        # SUB-TAB 1: GATED ACTIONS APPROVALS
        # -----------------------------------------------------------------
        with admin_tabs[0]:
            st.markdown("#### ⏳ Pending Human Gates Actions")
            st.write(
                "When Layer 11 intercepts high-stakes operations (like data_deletion or financial_approval), "
                "it stores a pending token in Redis. Administrators must explicitly approve it here."
            )

            # Discover and query pending tokens from Redis directly
            pending_tokens = []
            try:
                # Import settings and client
                from sentinel.config import Settings
                from sentinel.dependencies import get_settings
                settings = get_settings()

                if settings.REDIS_URL:
                    redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
                else:
                    import fakeredis.aioredis as fakeredis_aio
                    redis_client = fakeredis_aio.FakeRedis(decode_responses=True)

                # Scan keys
                keys = run_async(redis_client.keys("human_gate:token:*"))
                for key in keys:
                    val = run_async(redis_client.get(key))
                    if val:
                        payload = json.loads(val)
                        token_id = key.split(":")[-1]
                        payload["token"] = token_id
                        # Check TTL
                        ttl = run_async(redis_client.ttl(key))
                        payload["ttl"] = ttl
                        pending_tokens.append(payload)
            except Exception as e:
                st.warning(f"Unable to read pending tokens from Redis client directly: {str(e)}")

            # Manual input fallback
            manual_token = st.text_input("Manually Approve Token ID")
            if manual_token.strip():
                col_app, col_rej = st.columns(2)
                with col_app:
                    if st.button("Approve Gated Token", type="primary", use_container_width=True):
                        try:
                            payload_approve = {"decision": "approve"}
                            r = httpx.post(f"{BACKEND_URL}/admin/approve/{manual_token}", json=payload_approve, headers=headers, timeout=5.0)
                            if r.status_code == 200:
                                st.success("Token action successfully APPROVED!")
                                time.sleep(0.5)
                                st.rerun()
                            else:
                                st.error(f"Approval failed: {r.json().get('detail')}")
                        except Exception as err:
                            st.error(str(err))
                with col_rej:
                    if st.button("Reject Gated Token", use_container_width=True):
                        try:
                            payload_reject = {"decision": "reject", "reason": "Administrative rejection"}
                            r = httpx.post(f"{BACKEND_URL}/admin/approve/{manual_token}", json=payload_reject, headers=headers, timeout=5.0)
                            if r.status_code == 200:
                                st.warning("Token action successfully REJECTED and deleted!")
                                time.sleep(0.5)
                                st.rerun()
                            else:
                                st.error(f"Rejection failed: {r.json().get('detail')}")
                        except Exception as err:
                            st.error(str(err))

            st.write("---")
            if not pending_tokens:
                st.info("No pending gated approvals in Redis.")
            else:
                for pt in pending_tokens:
                    c_tok, c_user, c_act, c_ttl, c_ops = st.columns([3, 2, 2, 1, 2])
                    with c_tok:
                        st.write(f"`{pt['token']}`")
                    with c_user:
                        st.write(f"User: `{pt['user_id']}`")
                    with c_act:
                        st.write(f"Action: **{pt['action_category']}**")
                    with c_ttl:
                        st.write(f"{pt['ttl']}s")
                    with c_ops:
                        st_app_key = f"app_btn_{pt['token']}"
                        st_rej_key = f"rej_btn_{pt['token']}"
                        
                        col_inner_app, col_inner_rej = st.columns(2)
                        with col_inner_app:
                            if st.button("Approve", key=st_app_key, type="primary"):
                                try:
                                    r = httpx.post(f"{BACKEND_URL}/admin/approve/{pt['token']}", json={"decision": "approve"}, headers=headers, timeout=5.0)
                                    if r.status_code == 200:
                                        st.success("Approved!")
                                        time.sleep(0.5)
                                        st.rerun()
                                    else:
                                        st.error(r.json().get('detail'))
                                except Exception as err:
                                    st.error(str(err))
                        with col_inner_rej:
                            if st.button("Reject", key=st_rej_key):
                                try:
                                    r = httpx.post(f"{BACKEND_URL}/admin/approve/{pt['token']}", json={"decision": "reject"}, headers=headers, timeout=5.0)
                                    if r.status_code == 200:
                                        st.warning("Rejected!")
                                        time.sleep(0.5)
                                        st.rerun()
                                    else:
                                        st.error(r.json().get('detail'))
                                except Exception as err:
                                    st.error(str(err))

        # -----------------------------------------------------------------
        # SUB-TAB 2: DAILY USAGE & BUDGETS
        # -----------------------------------------------------------------
        with admin_tabs[1]:
            st.markdown("#### 📊 Real-Time Daily Budgets Usage")
            
            try:
                r = httpx.get(f"{BACKEND_URL}/admin/usage", headers=headers, timeout=5.0)
                if r.status_code == 200:
                    usages = r.json()
                    
                    for usage in usages:
                        st.markdown(f"##### User: `{usage['user_id']}`")
                        used = usage["tokens_used"]
                        limit = usage["limit"]
                        rem = usage["tokens_remaining"]
                        reqs = usage["requests"]
                        
                        col_u1, col_u2, col_u3 = st.columns(3)
                        with col_u1:
                            st.write(f"🪙 **Used / Limit:** `{used:,}` / `{limit:,}` tokens")
                        with col_u2:
                            st.write(f"⏳ **Remaining:** `{rem:,}` tokens")
                        with col_u3:
                            st.write(f"📨 **Today's Requests:** `{reqs}` calls")
                        
                        progress = min(1.0, used / limit) if limit > 0 else 0.0
                        st.progress(progress)
                        st.write("---")
                else:
                    st.error("Failed to query usage stats.")
            except Exception as e:
                st.error(f"Error fetching usage details: {str(e)}")

        # -----------------------------------------------------------------
        # SUB-TAB 3: AUDIT LOG VIEWER
        # -----------------------------------------------------------------
        with admin_tabs[2]:
            st.markdown("#### 📜 Security Audit Event Logs")
            st.write("Read-only security log records generated unconditionally at Layer 9 audit_logger.")

            # Filter controls
            c_f1, c_f2, c_f3 = st.columns(3)
            with c_f1:
                filter_user = st.text_input("Filter by Username")
            with c_f2:
                limit_logs = st.number_input("Max Events", min_value=10, max_value=1000, value=50, step=10)
            with c_f3:
                st.caption("")
                if st.button("Refresh Logs", type="secondary", use_container_width=True):
                    st.rerun()

            try:
                # Query audit endpoint
                params = {"limit": limit_logs}
                if filter_user.strip():
                    params["user_id"] = filter_user.strip()
                
                r = httpx.get(f"{BACKEND_URL}/admin/audit", params=params, headers=headers, timeout=10.0)
                
                if r.status_code == 200:
                    log_data = r.json()
                    events = log_data.get("events", [])
                    total_events = log_data.get("total", 0)

                    st.caption(f"Showing {len(events)} of {total_events} matching audit log records")
                    
                    if not events:
                        st.info("No audit logs match current filters.")
                    else:
                        for idx, ev in enumerate(events):
                            # Header summaries
                            timestamp = ev.get("timestamp", "").split(".")[0].replace("T", " ")
                            user = ev.get("user_id", "unknown")
                            session = ev.get("session_id", "")[:12]
                            blocked = ev.get("layers_blocked", {})
                            time_ms = ev.get("response_time_ms", 0)
                            
                            bg_color = "#341a1a" if blocked else "#1a1f36"
                            border_color = "#e53e3e" if blocked else "#4a5568"
                            text_color = "#fc8181" if blocked else "#90cdf4"
                            status_text = "BLOCKED" if blocked else "PASSED"

                            expander_label = f"[{timestamp}]  👤 User: {user}  |  STATUS: {status_text}  |  ⚡ {time_ms}ms"
                            
                            with st.expander(expander_label):
                                st.markdown(
                                    f'<div style="background-color: {bg_color}; border: 1px solid {border_color}; '
                                    f'border-radius: 6px; padding: 12px; margin-bottom: 10px;">'
                                    f'<strong style="color: {text_color}">Security Event Details:</strong><br>'
                                    f'Session ID: <code>{ev.get("session_id")}</code><br>'
                                    f'Input SHA-256 Hash: <code>{ev.get("request_hash")}</code><br>'
                                    f'Layers Blocked: <code>{json.dumps(blocked)}</code>'
                                    f'</div>',
                                    unsafe_allowed_html=True,
                                )
                                # Raw JSON
                                st.json(ev)
                else:
                    st.error("Failed to query audit logs.")
            except Exception as e:
                st.error(f"Error querying audit log files: {str(e)}")
