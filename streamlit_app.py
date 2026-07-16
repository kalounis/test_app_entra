"""
Demo Step-up MFA (Phishing Resistant) - Entra ID Authentication Context
========================================================================

Reproduit fidèlement la logique de l'exemple officiel Microsoft
"Use the Conditional Access auth context to perform step-up authentication
for high-privilege operations in a Web app"
https://github.com/Azure-Samples/ms-identity-dotnetcore-ca-auth-context-app

Correspondance avec le sample C# (commentée à chaque étape) :
  - AuthContext table (mapping Operation -> AuthContextId)  -> AUTH_CONTEXT_MAPPING
  - CheckForRequiredAuthContext(method)                     -> check_for_required_auth_context()
  - _consentHandler.ChallengeUser(scopes, claimsChallenge)   -> build_challenge_url()
  - Session state (pour survivre à la redirection)           -> st.session_state.pending_action
"""

import json

import msal
import streamlit as st

st.set_page_config(page_title="Step-up Phishing Resistant - Entra ID", page_icon="🛡️")

# ============================================================
# CONFIG
# ============================================================

TENANT_ID = st.secrets["TENANT_ID"]
CLIENT_ID = st.secrets["CLIENT_ID"]
CLIENT_SECRET = st.secrets["CLIENT_SECRET"]
REDIRECT_URI = st.secrets["REDIRECT_URI"]

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["User.Read"]

# ------------------------------------------------------------
# Équivalent de la table "AuthContext" du sample C#
# (Operation -> AuthContextId). Dans le sample officiel, cette table
# est alimentée par un admin via Microsoft Graph
# (authenticationContextClassReferences). Ici, on la code en dur pour
# la démo, mais la structure (dictionnaire operation -> acr) est la
# même que celle interrogée par CheckForRequiredAuthContext().
# ------------------------------------------------------------
AUTH_CONTEXT_MAPPING = {
    "view_profile": None,  # aucune exigence particulière
    "view_salary_data": st.secrets.get("STEPUP_ACR_VALUE", "c3"),  # phishing resistant
}
PHISHING_RESISTANT_LABEL = "Phishing Resistant (c3)"

# ============================================================
# MSAL — équivalent de AddMicrosoftIdentityWebApp(...).EnableTokenAcquisitionToCallDownstreamApi()
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
# SESSION STATE
# ------------------------------------------------------------
# Le sample C# utilise le Session state ASP.NET pour restaurer l'action
# demandée par l'utilisateur une fois revenu de la redirection Entra ID
# (voir section "Take a look into the example of using session state"
# du README du sample). st.session_state joue exactement ce rôle ici.
# ============================================================

defaults = {
    "account": None,
    "id_token_claims": None,
    "pending_action": None,   # <-- équivalent du Session state du sample C#
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ============================================================
# HELPERS
# ============================================================

def get_acrs(claims):
    """Équivalent de context.User.FindAll('acrs') côté C#."""
    if not claims:
        return []
    acrs = claims.get("acrs", [])
    if isinstance(acrs, str):
        acrs = [acrs]
    return acrs


def check_for_required_auth_context(operation):
    """
    Équivalent direct de CheckForRequiredAuthContext(string method) dans
    TodoListController.cs :
      1. récupère l'AuthContextId requis pour cette opération
      2. si aucun n'est requis -> None (pas de step-up nécessaire)
      3. si un acrs correspondant est déjà présent dans l'ID token -> None
      4. sinon -> retourne le claims challenge à envoyer à Entra ID
    """
    required_acr = AUTH_CONTEXT_MAPPING.get(operation)

    if not required_acr:
        return None

    current_acrs = get_acrs(st.session_state.id_token_claims)
    if required_acr in current_acrs:
        return None  # déjà satisfait, pas de step-up nécessaire

    # Construit le claims challenge, comme le fait le sample C# avec
    # authenticationContextClassReferencesClaim côté Web API, mais ici
    # on cible directement l'ID token puisqu'il s'agit d'une Web App
    # (pas d'une Web API séparée).
    return {
        "id_token": {
            "acrs": {"essential": True, "value": required_acr}
        }
    }


def build_challenge_url(claims_challenge, pending_action):
    """
    Équivalent de _consentHandler.ChallengeUser(scopes, claimsChallenge) :
    prépare la redirection vers Entra ID avec le claims challenge, et
    mémorise l'action en attente (comme le Session state du sample) pour
    la restaurer après le retour de redirection.
    """
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
# CALLBACK — retour d'Entra ID après authentification/step-up
# ============================================================

params = st.query_params

if "code" in params:
    code = params["code"]
    try:
        result = msal_app.acquire_token_by_authorization_code(
            code, scopes=SCOPES, redirect_uri=REDIRECT_URI
        )
        if "id_token_claims" in result:
            claims = result["id_token_claims"]
            st.session_state.id_token_claims = claims
            st.session_state.account = (
                claims.get("preferred_username") or claims.get("upn") or "utilisateur"
            )
        else:
            st.error(f"Échec de l'authentification : {result.get('error_description', result)}")
    except Exception as e:
        st.error(f"Erreur lors de l'échange du code : {e}")
    finally:
        st.query_params.clear()
        st.rerun()

# ============================================================
# UI
# ============================================================

st.title("🛡️ Step-up Phishing Resistant — Entra ID")

if not st.session_state.account:
    st.write("Vous n'êtes pas connecté.")
    st.link_button("➡️ Se connecter", build_login_url())
    st.stop()

st.success(f"Connecté : **{st.session_state.account}**")

with st.expander("Claims de l'ID token courant"):
    claims = st.session_state.id_token_claims or {}
    st.write("**acrs**:", get_acrs(claims))
    st.write("**amr** (méthode(s) utilisée(s)) :", claims.get("amr"))
    st.write("**auth_time**:", claims.get("auth_time"))
    st.json(claims)

st.divider()

# ------------------------------------------------------------
# Opération non sensible — aucune exigence
# ------------------------------------------------------------
st.subheader("Opération standard")
if st.button("Voir mon profil (aucune exigence)"):
    st.info("✅ Accès accordé — cette opération ne requiert aucun step-up.")

st.divider()

# ------------------------------------------------------------
# Opération sensible — nécessite le contexte Phishing Resistant (c3)
# Reproduit l'appel CheckForRequiredAuthContext("Delete") du sample,
# suivi du ChallengeUser() si un claims challenge est retourné.
# ------------------------------------------------------------
st.subheader(f"Opération sensible — requiert {PHISHING_RESISTANT_LABEL}")

if st.button("Consulter les données de salaire (sensible)"):
    claims_challenge = check_for_required_auth_context("view_salary_data")

    if claims_challenge is None:
        st.success("✅ Accès accordé — le contexte Phishing Resistant est déjà satisfait.")
    else:
        st.error("🔒 Authentification renforcée requise (Phishing Resistant)")
        url = build_challenge_url(claims_challenge, pending_action="view_salary_data")
        st.link_button("➡️ Effectuer le step-up Phishing Resistant", url)

# Si on revient d'une redirection et qu'une action était en attente,
# on la ré-affiche automatiquement (équivalent du restore de Session
# state évoqué dans le README du sample officiel).
if st.session_state.pending_action == "view_salary_data" and get_acrs(
    st.session_state.id_token_claims
):
    required_acr = AUTH_CONTEXT_MAPPING["view_salary_data"]
    if required_acr in get_acrs(st.session_state.id_token_claims):
        st.success("✅ Step-up validé — accès aux données de salaire accordé.")
        st.session_state.pending_action = None

st.divider()
if st.button("Se déconnecter (local)"):
    for k in defaults:
        st.session_state[k] = defaults[k]
    st.rerun()
