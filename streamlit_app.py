import base64
import json

import msal
import streamlit as st

st.set_page_config(
    page_title="Authentication Context Demo",
    page_icon="🔐",
)

# ============================================================
# CONFIG
# ============================================================

TENANT_ID = st.secrets["TENANT_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
CLIENT_SECRET = st.secrets["CLIENT_SECRET"]
REDIRECT_URI = st.secrets["REDIRECT_URI"]

AUTH_CONTEXT_ID = st.secrets.get("STEPUP_ACR_VALUE", "c3")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

SCOPES = [
    "User.Read"
]

# ============================================================
# MSAL
# ============================================================


@st.cache_resource
def get_app():
    return msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY,
    )


app = get_app()

# ============================================================
# SESSION
# ============================================================

defaults = {
    "account": None,
    "access_claims": None,
    "login_claims": None,
    "stepup_claims": None,
    "want_sensitive": False,
}

for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ============================================================
# JWT DECODER
# ============================================================

def decode_jwt(token):
    parts = token.split(".")

    if len(parts) < 2:
        return {}

    payload = parts[1]

    payload += "=" * ((4 - len(payload) % 4) % 4)

    decoded = base64.urlsafe_b64decode(payload)

    return json.loads(decoded)


# ============================================================
# HELPERS
# ============================================================

def build_auth_url(state, claims=None):

    return app.get_authorization_request_url(
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        state=state,
        claims_challenge=json.dumps(claims)
        if claims
        else None,
    )


def get_acrs(claims):

    if not claims:
        return []

    acrs = claims.get("acrs", [])

    if isinstance(acrs, str):
        acrs = [acrs]

    return acrs


def has_auth_context(context_id):

    claims = st.session_state.access_claims

    if not claims:
        return False

    acrs = get_acrs(claims)

    return context_id in acrs


def show_claims(title, claims):

    st.subheader(title)

    if not claims:
        st.info("Pas de claims")
        return

    st.write("#### acrs")
    st.code(json.dumps(claims.get("acrs"), indent=2))

    st.write("#### amr")
    st.code(json.dumps(claims.get("amr"), indent=2))

    st.write("#### xms_cc")
    st.code(json.dumps(claims.get("xms_cc"), indent=2))

    with st.expander("Claims complets"):
        st.json(claims)


# ============================================================
# CALLBACK
# ============================================================

params = st.query_params

if "code" in params:

    code = params["code"]
    state = params.get("state", "unknown")

    try:

        token_result = app.acquire_token_by_authorization_code(
            code=code,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
        )

        if "access_token" not in token_result:

            st.error(token_result)
            st.stop()

        access_token = token_result["access_token"]

        access_claims = decode_jwt(access_token)

        st.session_state.access_claims = access_claims

        username = (
            access_claims.get("preferred_username")
            or access_claims.get("upn")
            or "user"
        )

        st.session_state.account = username

        if state == "login":
            st.session_state.login_claims = access_claims

        if state == "stepup":
            st.session_state.stepup_claims = access_claims

    except Exception as e:
        st.error(str(e))

    finally:
        st.query_params.clear()
        st.rerun()

# ============================================================
# UI
# ============================================================

st.title("🔐 Authentication Context Test")

st.write(f"Context cible : **{AUTH_CONTEXT_ID}**")

# ------------------------------------------------------------
# LOGIN
# ------------------------------------------------------------

if not st.session_state.account:

    login_url = build_auth_url(
        state="login"
    )

    st.link_button(
        "➡️ Se connecter",
        login_url,
    )

    st.stop()

# ------------------------------------------------------------
# CONNECTED
# ------------------------------------------------------------

st.success(
    f"Connecté : {st.session_state.account}"
)

if has_auth_context(AUTH_CONTEXT_ID):

    st.success(
        f"Authentication Context {AUTH_CONTEXT_ID} présent"
    )

else:

    st.warning(
        f"Authentication Context {AUTH_CONTEXT_ID} absent"
    )

# ------------------------------------------------------------
# DEBUG
# ------------------------------------------------------------

show_claims(
    "Claims login",
    st.session_state.login_claims,
)

show_claims(
    "Claims step-up",
    st.session_state.stepup_claims,
)

# ------------------------------------------------------------
# ACTION SENSIBLE
# ------------------------------------------------------------

st.divider()

if st.button("Tester action sensible"):
    st.session_state.want_sensitive = True

if st.session_state.want_sensitive:

    if has_auth_context(AUTH_CONTEXT_ID):

        st.success(
            "✅ Accès autorisé"
        )

    else:

        st.error(
            "🔒 Authentication Context requis"
        )

        claims = {
            "access_token": {
                "acrs": {
                    "essential": True,
                    "value": AUTH_CONTEXT_ID,
                }
            }
        }

        stepup_url = build_auth_url(
            state="stepup",
            claims=claims,
        )

        st.link_button(
            "➡️ Effectuer le step-up",
            stepup_url,
        )

# ------------------------------------------------------------
# LOGOUT
# ------------------------------------------------------------

st.divider()

if st.button("Reset session"):

    for k in defaults.keys():
        st.session_state[k] = defaults[k]

    st.rerun()
