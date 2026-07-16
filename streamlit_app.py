import json

import msal
import streamlit as st

st.set_page_config(page_title="Demo Step-up MFA - Entra ID", page_icon="🔐")

TENANT_ID = st.secrets["TENANT_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
CLIENT_SECRET = st.secrets["CLIENT_SECRET"]
REDIRECT_URI = st.secrets["REDIRECT_URI"]
STEPUP_ACR_VALUE = st.secrets.get("STEPUP_ACR_VALUE", "c3")
SCOPES = ["User.Read"]

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"


@st.cache_resource
def get_msal_app():
    return msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY,
    )


cca = get_msal_app()

if "account" not in st.session_state:
    st.session_state.account = None
if "id_token_claims" not in st.session_state:
    st.session_state.id_token_claims = None
if "want_protected" not in st.session_state:
    st.session_state.want_protected = False


def build_auth_url(claims_challenge=None, state=None):
    return cca.get_authorization_request_url(
        SCOPES,
        redirect_uri=REDIRECT_URI,
        state=state,
        claims_challenge=json.dumps(claims_challenge) if claims_challenge else None,
    )


def has_stepup_context():
    claims = st.session_state.id_token_claims
    if not claims or "acrs" not in claims:
        return False
    acrs = claims["acrs"]
    if isinstance(acrs, str):
        acrs = [acrs]
    return STEPUP_ACR_VALUE in acrs


# --- Traitement du retour Entra ID (code d'autorisation présent dans l'URL) ---
params = st.query_params
if "code" in params:
    code = params["code"]
    try:
        result = cca.acquire_token_by_authorization_code(
            code, scopes=SCOPES, redirect_uri=REDIRECT_URI
        )
        if "id_token_claims" in result:
            st.session_state.account = result["id_token_claims"].get(
                "preferred_username", "utilisateur"
            )
            st.session_state.id_token_claims = result["id_token_claims"]
        else:
            st.error(
                f"Échec de l'authentification : {result.get('error_description', result)}"
            )
    except Exception as e:
        st.error(f"Erreur lors de l'échange du code : {e}")
    finally:
        st.query_params.clear()
        st.rerun()

# --- Interface ---
st.title("🔐 Demo Step-up MFA — Entra ID")

if not st.session_state.account:
    st.write("Vous n'êtes pas connecté.")
    login_url = build_auth_url(state="login")
    st.markdown(
        f'<a href="{login_url}" target="_self">➡️ Se connecter</a>',
        unsafe_allow_html=True,
    )
else:
    st.success(f"Connecté en tant que **{st.session_state.account}**")

    if has_stepup_context():
        st.info(f"Contexte d'authentification step-up (`{STEPUP_ACR_VALUE}`) : ✅ présent")
    else:
        st.warning(f"Contexte d'authentification step-up (`{STEPUP_ACR_VALUE}`) : ❌ absent")

    st.divider()
    st.subheader("Action sensible")

    if st.button("Tester l'action sensible"):
        st.session_state.want_protected = True

    if st.session_state.want_protected:
        if has_stepup_context():
            st.success("✅ Accès accordé à l'action sensible")
            with st.expander("Claims de l'id_token"):
                st.json(st.session_state.id_token_claims)
        else:
            st.error("🔒 Authentification renforcée requise pour cette action")
            stepup_url = build_auth_url(
                claims_challenge={
                    "id_token": {"acrs": {"essential": True, "value": STEPUP_ACR_VALUE}}
                },
                state="stepup",
            )
            st.markdown(
                f'<a href="{stepup_url}" target="_self">➡️ Effectuer le step-up MFA</a>',
                unsafe_allow_html=True,
            )

    st.divider()
    if st.button("Se déconnecter (local)"):
        st.session_state.account = None
        st.session_state.id_token_claims = None
        st.session_state.want_protected = False
        st.rerun()
