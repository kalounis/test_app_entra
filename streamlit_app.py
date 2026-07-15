import base64
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


def decode_jwt(token):
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


if "account" not in st.session_state:
    st.session_state.account = None

if "id_token_claims" not in st.session_state:
    st.session_state.id_token_claims = None

if "access_token_claims" not in st.session_state:
    st.session_state.access_token_claims = None

if "want_protected" not in st.session_state:
    st.session_state.want_protected = False


def build_auth_url(claims_challenge=None, state=None):
    return cca.get_authorization_request_url(
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        state=state,
        prompt="login",
        claims_challenge=json.dumps(claims_challenge)
        if claims_challenge
        else None,
    )


def has_stepup_context():
    claims = st.session_state.access_token_claims

    if claims is None:
        claims = st.session_state.id_token_claims

    if claims is None:
        return False

    acrs = claims.get("acrs")

    if not acrs:
        return False

    if isinstance(acrs, str):
        acrs = [acrs]

    return STEPUP_ACR_VALUE in acrs


params = st.query_params

if "code" in params:
    code = params["code"]

    result = cca.acquire_token_by_authorization_code(
        code,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )

    if "id_token_claims" in result:

        st.session_state.account = result["id_token_claims"].get(
            "preferred_username", "utilisateur"
        )

        st.session_state.id_token_claims = result["id_token_claims"]

        if "access_token" in result:
            st.session_state.access_token_claims = decode_jwt(
                result["access_token"]
            )

    else:
        st.error(result)

    st.query_params.clear()
    st.rerun()


st.title("🔐 Demo Step-up MFA")

if not st.session_state.account:

    login_url = build_auth_url(state="login")

    st.markdown(
        f'<a href="{login_url}" target="_self">➡️ Se connecter</a>',
        unsafe_allow_html=True,
    )

else:

    st.success(f"Connecté : {st.session_state.account}")

    if has_stepup_context():
        st.success(f"Step-up {STEPUP_ACR_VALUE} présent")
    else:
        st.error(f"Step-up {STEPUP_ACR_VALUE} absent")

    with st.expander("ID Token"):
        st.json(st.session_state.id_token_claims)

    with st.expander("Access Token"):
        st.json(st.session_state.access_token_claims)

    if st.button("Tester l'action sensible"):
        st.session_state.want_protected = True

    if st.session_state.want_protected:

        if has_stepup_context():

            st.success("Accès autorisé")

        else:

            st.error("Step-up requis")

            stepup_url = build_auth_url(
                claims_challenge={
                    "access_token": {
                        "acrs": {
                            "essential": True,
                            "value": STEPUP_ACR_VALUE,
                        }
                    }
                },
                state="stepup",
            )

            st.markdown(
                f'<a href="{stepup_url}" target="_self">➡️ Effectuer le Step-up</a>',
                unsafe_allow_html=True,
            )

    if st.button("Déconnexion"):

        st.session_state.account = None
        st.session_state.id_token_claims = None
        st.session_state.access_token_claims = None
        st.session_state.want_protected = False

        st.rerun()