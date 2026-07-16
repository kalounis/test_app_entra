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

SCOPES = ["User.Read"]

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
    "id_token_claims": None,       # source de verite pour "acrs" (ID token, propre a votre app)
    "access_token_claims": None,   # garde uniquement a titre de comparaison/diagnostic
    "login_claims": None,
    "stepup_claims": None,
    "want_sensitive": False,
}

for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ============================================================
# JWT DECODER (utilise uniquement pour l'access token, a titre de diagnostic)
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
        claims_challenge=json.dumps(claims) if claims else None,
    )


def get_acrs(claims):
    if not claims:
        return []
    acrs = claims.get("acrs", [])
    if isinstance(acrs, str):
        acrs = [acrs]
    return acrs


def has_auth_context(context_id):
    # On verifie sur l'ID token, pas sur l'access token Graph :
    # c'est le jeton emis pour VOTRE app, entierement sous votre controle.
    claims = st.session_state.id_token_claims
    if not claims:
        return False
    return context_id in get_acrs(claims)


# Codes amr généralement considérés comme phishing-resistant par Entra ID
PHISHING_RESISTANT_AMR_HINTS = {
    "wia": "Windows Integrated Auth / Windows Hello for Business",
    "face": "Windows Hello (visage)",
    "fpt": "Windows Hello / biométrie (empreinte)",
    "hwk": "Clé matérielle (FIDO2 / clé de sécurité)",
    "swk": "Clé logicielle",
    "csig": "Authentification par certificat",
}


def show_claims(title, claims):
    st.subheader(title)

    if not claims:
        st.info("Pas de claims")
        return

    st.write("#### acrs")
    st.code(json.dumps(claims.get("acrs"), indent=2))

    amr = claims.get("amr") or []
    st.write("#### amr (méthode(s) d'authentification réellement utilisée(s))")
    st.code(json.dumps(amr, indent=2))

    matched = [PHISHING_RESISTANT_AMR_HINTS[m] for m in amr if m in PHISHING_RESISTANT_AMR_HINTS]
    if matched:
        st.warning(
            "⚠️ Cette connexion utilise déjà une méthode potentiellement "
            f"phishing-resistant : {', '.join(matched)}. C'est probablement "
            "ce qui explique la présence de l'acrs correspondant, "
            "indépendamment de toute demande explicite de step-up."
        )

    if claims.get("auth_time"):
        st.write("#### auth_time (horodatage de la dernière authentification)")
        st.code(str(claims.get("auth_time")))

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

        if "id_token_claims" not in token_result:
            st.error(token_result)
            st.stop()

        id_claims = token_result["id_token_claims"]
        st.session_state.id_token_claims = id_claims

        # Access token garde uniquement pour comparaison / diagnostic
        if "access_token" in token_result:
            st.session_state.access_token_claims = decode_jwt(token_result["access_token"])

        username = (
            id_claims.get("preferred_username")
            or id_claims.get("upn")
            or "user"
        )
        st.session_state.account = username

        if state == "login":
            st.session_state.login_claims = id_claims
        if state == "stepup":
            st.session_state.stepup_claims = id_claims

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
    login_url = build_auth_url(state="login")
    st.link_button("➡️ Se connecter", login_url)
    st.stop()

# ------------------------------------------------------------
# CONNECTED
# ------------------------------------------------------------

st.success(f"Connecté : {st.session_state.account}")

if has_auth_context(AUTH_CONTEXT_ID):
    st.success(f"Authentication Context {AUTH_CONTEXT_ID} présent (ID token)")
else:
    st.warning(f"Authentication Context {AUTH_CONTEXT_ID} absent (ID token)")

# Diagnostic : compare ID token vs access token, pour visualiser
# une eventuelle evaluation opportuniste differente entre les deux jetons.
if st.session_state.access_token_claims:
    access_acrs = get_acrs(st.session_state.access_token_claims)
    id_acrs = get_acrs(st.session_state.id_token_claims)
    if set(access_acrs) != set(id_acrs):
        st.info(
            "ℹ️ Les valeurs `acrs` diffèrent entre l'ID token "
            f"({id_acrs}) et l'access token Graph ({access_acrs}). "
            "C'est normal : chaque type de jeton est évalué "
            "individuellement par l'évaluation opportuniste."
        )

# ------------------------------------------------------------
# DEBUG
# ------------------------------------------------------------

show_claims("Claims ID token — login", st.session_state.login_claims)
show_claims("Claims ID token — step-up", st.session_state.stepup_claims)

if st.session_state.access_token_claims:
    with st.expander("Access token Graph (diagnostic uniquement)"):
        st.json(st.session_state.access_token_claims)

# ------------------------------------------------------------
# ACTION SENSIBLE
# ------------------------------------------------------------

st.divider()

if st.button("Tester action sensible"):
    st.session_state.want_sensitive = True

if st.session_state.want_sensitive:
    if has_auth_context(AUTH_CONTEXT_ID):
        st.success("✅ Accès autorisé")
    else:
        st.error("🔒 Authentication Context requis")

        claims = {
            "id_token": {
                "acrs": {
                    "essential": True,
                    "value": AUTH_CONTEXT_ID,
                }
            }
        }

        stepup_url = build_auth_url(state="stepup", claims=claims)
        st.link_button("➡️ Effectuer le step-up", stepup_url)

# ------------------------------------------------------------
# RESET
# ------------------------------------------------------------

st.divider()

if st.button("Reset session"):
    for k in defaults.keys():
        st.session_state[k] = defaults[k]
    st.rerun()
