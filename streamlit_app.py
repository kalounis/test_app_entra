import json

import msal
import streamlit as st

st.set_page_config(
    page_title="Demo Step-up MFA - Entra ID",
    page_icon="🔐",
)

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

TENANT_ID = st.secrets["TENANT_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
CLIENT_SECRET = st.secrets["CLIENT_SECRET"]
REDIRECT_URI = st.secrets["REDIRECT_URI"]

STEPUP_ACR_VALUE = st.secrets.get("STEPUP_ACR_VALUE", "c3")

SCOPES = ["User.Read"]

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"


# ------------------------------------------------------------------
# MSAL
# ------------------------------------------------------------------

@st.cache_resource
def get_msal_app():
    return msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY,
    )


cca = get_msal_app()

# ------------------------------------------------------------------
# Session State
# ------------------------------------------------------------------

if "account" not in st.session_state:
    st.session_state.account = None

if "id_token_claims" not in st.session_state:
    st.session_state.id_token_claims = None

if "login_claims" not in st.session_state:
    st.session_state.login_claims = None

if "stepup_claims" not in st.session_state:
    st.session_state.stepup_claims = None

if "last_state" not in st.session_state:
    st.session_state.last_state = None

if "want_protected" not in st.session_state:
    st.session_state.want_protected = False


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def build_auth_url(state, claims_challenge=None):

    return cca.get_authorization_request_url(
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        state=state,
        claims_challenge=(
            json.dumps(claims_challenge)
            if claims_challenge
            else None
        ),
    )


def get_acrs(claims):

    if not claims:
        return []

    acrs = claims.get("acrs", [])

    if isinstance(acrs, str):
        acrs = [acrs]

    return acrs


def has_stepup_context():

    if not st.session_state.id_token_claims:
        return False

    return STEPUP_ACR_VALUE in get_acrs(
        st.session_state.id_token_claims
    )


def show_claims(title, claims):

    st.subheader(title)

    if not claims:
        st.info("Aucune donnée")
        return

    st.write("### ACRS")
    st.code(json.dumps(claims.get("acrs", []), indent=2))

    st.write("### AMR")
    st.code(json.dumps(claims.get("amr", []), indent=2))

    st.write("### AUTH_TIME")
    st.code(str(claims.get("auth_time")))

    with st.expander("Claims complets"):
        st.json(claims)


# ------------------------------------------------------------------
# Callback Entra ID
# ------------------------------------------------------------------

params = st.query_params

if "code" in params:

    code = params["code"]
    state = params.get("state", "")

    try:

        result = cca.acquire_token_by_authorization_code(
            code=code,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
        )

        if "id_token_claims" in result:

            claims = result["id_token_claims"]

            st.session_state.account = claims.get(
                "preferred_username",
                "user",
            )

            st.session_state.id_token_claims = claims
            st.session_state.last_state = state

            if state == "login":
                st.session_state.login_claims = claims

            elif state == "stepup":
                st.session_state.stepup_claims = claims

        else:

            st.error(
                result.get(
                    "error_description",
                    str(result),
                )
            )

    except Exception as ex:

        st.error(str(ex))

    finally:

        st.query_params.clear()
        st.rerun()

# ------------------------------------------------------------------
# UI
# ------------------------------------------------------------------

st.title("🔐 Diagnostic Authentication Context")

if not st.session_state.account:

    st.warning("Utilisateur non connecté")

    login_url = build_auth_url("login")

    st.link_button(
        "➡️ Se connecter",
        login_url,
    )

else:

    st.success(
        f"Connecté en tant que {st.session_state.account}"
    )

    st.write("---")

    st.write(
        f"Dernier flow exécuté : **{st.session_state.last_state}**"
    )

    st.write(
        f"Authentication Context recherché : **{STEPUP_ACR_VALUE}**"
    )

    if has_stepup_context():
        st.success(
            f"Context {STEPUP_ACR_VALUE} détecté"
        )
    else:
        st.warning(
            f"Context {STEPUP_ACR_VALUE} absent"
        )

    st.write("---")

    show_claims(
        "Claims du login initial",
        st.session_state.login_claims,
    )

    st.write("---")

    show_claims(
        "Claims du step-up",
        st.session_state.stepup_claims,
    )

    st.write("---")

    if st.button("Tester action sensible"):
        st.session_state.want_protected = True

    if st.session_state.want_protected:

        if has_stepup_context():

            st.success(
                "✅ Accès accordé"
            )

        else:

            st.error(
                "🔒 Step-up requis"
            )

            claims_challenge = {
                "id_token": {
                    "acrs": {
                        "essential": True,
                        "value": STEPUP_ACR_VALUE,
                    }
                }
            }

            stepup_url = build_auth_url(
                state="stepup",
                claims_challenge=claims_challenge,
            )

            st.link_button(
                "➡️ Lancer le step-up",
                stepup_url,
            )

    st.write("---")

    if st.button("Réinitialiser la session"):

        st.session_state.account = None
        st.session_state.id_token_claims = None
        st.session_state.login_claims = None
        st.session_state.stepup_claims = None
        st.session_state.last_state = None
        st.session_state.want_protected = False

        st.rerun()
