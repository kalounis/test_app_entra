import json

import msal
import streamlit as st

st.set_page_config(page_title="Demo Step-up MFA - Entra ID", page_icon="🔐")

TENANT_ID = st.secrets["TENANT_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
CLIENT_SECRET = st.secrets["CLIENT_SECRET"]
REDIRECT_URI = st.secrets["REDIRECT_URI"]

STEPUP_ACR_VALUE = st.secrets.get("STEPUP_ACR_VALUE", "c3")

SCOPES = ["openid", "profile", "email", "User.Read"]

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"


@st.cache_resource
def get_msal_app():
    return msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        client_credential=CLIENT_SECRET,
        authority=AUTHORITY,
    )


cca = get_msal_app()

# --------------------------------------------------------------------
# Session state
# --------------------------------------------------------------------

defaults = {
    "account": None,
    "id_token_claims": None,
    "login_claims": None,
    "stepup_claims": None,
    "want_protected": False,
    "last_state": None,
}

for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------


def build_auth_url(state, claims_challenge=None, force_login=False):
    kwargs = {
        "scopes": SCOPES,
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }

    if claims_challenge:
        kwargs["claims_challenge"] = json.dumps(claims_challenge)

    url = cca.get_authorization_request_url(**kwargs)

    if force_login:
        separator = "&" if "?" in url else "?"
        url += f"{separator}prompt=login"

    return url


def get_acrs(claims):
    if not claims:
        return []

    acrs = claims.get("acrs", [])

    if isinstance(acrs, str):
        acrs = [acrs]

    return acrs


def has_stepup_context():
    claims = st.session_state.id_token_claims

    if not claims:
        return False

    acrs = get_acrs(claims)

    return STEPUP_ACR_VALUE in acrs


def show_claim_summary(claims, title):
    st.subheader(title)

    if not claims:
        st.info("Aucun claim")
        return

    st.write("**acrs**")
    st.code(json.dumps(claims.get("acrs", []), indent=2))

    st.write("**amr**")
    st.code(json.dumps(claims.get("amr", []), indent=2))

    st.write("**auth_time**")
    st.code(str(claims.get("auth_time")))

    with st.expander("Claims complets"):
        st.json(claims)


# --------------------------------------------------------------------
# Callback Entra ID
# --------------------------------------------------------------------

params = st.query_params

if "code" in params:

    code = params["code"]
    state = params.get("state")

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
                claims.get("upn", "User"),
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
                    json.dumps(result, indent=2),
                )
            )

    except Exception as ex:
        st.error(str(ex))

    finally:
        st.query_params.clear()
        st.rerun()

# --------------------------------------------------------------------
# UI
# --------------------------------------------------------------------

st.title("🔐 Demo Step-up MFA - Diagnostic")

if not st.session_state.account:

    st.warning("Non connecté")

    login_url = build_auth_url(
        state="login",
        force_login=True,
    )

    st.markdown(
        f'{login_url}➡️ Connexion</a>',
        unsafe_allow_html=True,
    )

else:

    st.success(f"Connecté : {st.session_state.account}")

    st.write("### Diagnostic")

    st.write(
        f"**Dernier flow exécuté :** {st.session_state.last_state}"
    )

    st.write(
        f"**Step-up détecté :** {'✅ OUI' if has_stepup_context() else '❌ NON'}"
    )

    st.write(
        f"**ACR recherché :** {STEPUP_ACR_VALUE}"
    )

    st.divider()

    show_claim_summary(
        st.session_state.login_claims,
        "Claims du login initial",
    )

    st.divider()

    show_claim_summary(
        st.session_state.stepup_claims,
        "Claims du flow step-up",
    )

    st.divider()

    if st.button("Tester l'action sensible"):
        st.session_state.want_protected = True

    if st.session_state.want_protected:

        if has_stepup_context():

            st.success(
                f"✅ Contexte {STEPUP_ACR_VALUE} présent"
            )

        else:

            st.error(
                f"🔒 Contexte {STEPUP_ACR_VALUE} absent"
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
                force_login=True,
            )

            st.markdown(
                f'{stepup_url}➡️ Lancer le step-up</a>',
                unsafe_allow_html=True,
            )

    st.divider()

    if st.button("Reset session"):

        for k in list(defaults.keys()):
            st.session_state[k] = defaults[k]

        st.rerun()
