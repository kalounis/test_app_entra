"""
Demo Step-up MFA - Test de plusieurs Authentication Contexts (c3 OU c4)
"""

import json

import msal
import streamlit as st

st.set_page_config(page_title="Step-up MFA - c3 OU c4", page_icon="🛡️")

# ============================================================
# CONFIG
# ============================================================

TENANT_ID = st.secrets["TENANT_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
CLIENT_SECRET = st.secrets["CLIENT_SECRET"]
REDIRECT_URI = st.secrets["REDIRECT_URI"]

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["User.Read"]

# ============================================================
# AUTH CONTEXTS
# ============================================================

AUTH_CONTEXT_MAPPING = {
    "view_profile": None,
    "view_salary_data": ["c3", "c4"],
}

PHISHING_RESISTANT_LABEL = "Authentication Context c3 OU c4"

# ============================================================
# MSAL
# ============================================================

@st.cache_resource
def get_msal_app():
    return msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY,
    )

msal_app = get_msal_app()

# ============================================================
# SESSION
# ============================================================

defaults = {
    "account": None,
    "id_token_claims": None,
    "pending_action": None,
}

for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ============================================================
# HELPERS
# ============================================================

def get_acrs(claims):
    if not claims:
        return []

    acrs = claims.get("acrs", [])

    if isinstance(acrs, str):
        acrs = [acrs]

    return acrs


def check_for_required_auth_context(operation):

    required_acrs = AUTH_CONTEXT_MAPPING.get(operation)

    if not required_acrs:
        return None

    if isinstance(required_acrs, str):
        required_acrs = [required_acrs]

    current_acrs = get_acrs(st.session_state.id_token_claims)

    # Test OR : l'utilisateur satisfait déjà au moins un contexte
    if any(acr in current_acrs for acr in required_acrs):
        return None

    # Demande explicite c3 OU c4
    return {
        "id_token": {
            "acrs": {
                "essential": True,
                "values": required_acrs
            }
        }
    }


def build_challenge_url(claims_challenge, pending_action):
    st.session_state.pending_action = pending_action

    return msal_app.get_authorization_request_url(
        SCOPES,
        redirect_uri=REDIRECT_URI,
        claims_challenge=json.dumps(claims_challenge),
    )


def build_login_url():
    return msal_app.get_authorization_request_url(
        SCOPES,
        redirect_uri=REDIRECT_URI,
    )

# ============================================================
# CALLBACK
# ============================================================

params = st.query_params

if "code" in params:
    code = params["code"]

    try:
        result = msal_app.acquire_token_by_authorization_code(
            code,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
        )

        if "id_token_claims" in result:

            claims = result["id_token_claims"]

            st.session_state.id_token_claims = claims

            st.session_state.account = (
                claims.get("preferred_username")
                or claims.get("upn")
                or "utilisateur"
            )

        else:
            st.error(
                f"Échec : {result.get('error_description', result)}"
            )

    except Exception as e:
        st.error(str(e))

    finally:
        st.query_params.clear()
        st.rerun()

# ============================================================
# UI
# ============================================================

st.title("🛡️ Test Authentication Contexts c3 OU c4")

if not st.session_state.account:
    st.write("Vous n'êtes pas connecté.")
    st.link_button("➡️ Se connecter", build_login_url())
    st.stop()

st.success(f"Connecté : {st.session_state.account}")

with st.expander("Claims du token"):

    claims = st.session_state.id_token_claims or {}

    st.write("### Valeurs de debug")

    st.write("acrs :", get_acrs(claims))
    st.write("amr :", claims.get("amr"))
    st.write("auth_time :", claims.get("auth_time"))

    st.json(claims)

st.divider()

st.subheader("Opération standard")

if st.button("Voir mon profil"):
    st.success("✅ Accès accordé")

st.divider()

st.subheader(
    "Opération sensible nécessitant c3 OU c4"
)

if st.button("Consulter les données de salaire"):

    claims_challenge = check_for_required_auth_context(
        "view_salary_data"
    )

    if claims_challenge is None:

        st.success(
            "✅ Contexte déjà satisfait "
            "(au moins un de c3 ou c4)"
        )

    else:

        st.warning(
            "🔒 Step-up requis : demande de c3 OU c4"
        )

        st.json(claims_challenge)

        url = build_challenge_url(
            claims_challenge,
            pending_action="view_salary_data",
        )

        st.link_button(
            "➡️ Effectuer le step-up",
            url,
        )

# ============================================================
# RETOUR STEP-UP
# ============================================================

if (
    st.session_state.pending_action == "view_salary_data"
    and st.session_state.id_token_claims
):

    returned_acrs = get_acrs(
        st.session_state.id_token_claims
    )

    required_acrs = AUTH_CONTEXT_MAPPING[
        "view_salary_data"
    ]

    if any(acr in returned_acrs for acr in required_acrs):

        st.success(
            "✅ Step-up validé. "
            f"acrs retournés : {returned_acrs}"
        )

        st.session_state.pending_action = None

st.divider()

if st.button("Se déconnecter"):

    for k in defaults:
        st.session_state[k] = defaults[k]

    st.rerun()
