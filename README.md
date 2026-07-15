# Demo Step-up MFA avec Microsoft Entra ID — version Streamlit

Application Python/Streamlit testant le **step-up MFA** via le mécanisme
**Authentication Context** (`acrs`) de Microsoft Entra ID.

## Principe

Contrairement à une app Express/Flask classique, Streamlit n'a qu'une seule
URL (pas de route `/auth/redirect` dédiée). Le retour d'Entra ID après
authentification arrive donc en query params (`?code=...`) sur l'URL
racine de l'app, lus via `st.query_params` au chargement de la page.

## 1. Configuration côté Entra ID

Identique à la version Node (voir plus haut dans la conversation), à
adapter uniquement sur le **Redirect URI**, qui doit être l'URL racine de
l'app (pas un sous-chemin) :

1. **App registrations > New registration**
   - Redirect URI type **Web** = `http://localhost:8501` en local, puis
     l'URL Streamlit Cloud une fois déployée (voir étape 3)
2. **Certificates & secrets** → créer un client secret
3. **Protection > Conditional Access > Authentication contexts** → créer
   `c1` ("Step-up MFA required"), cocher **Publish to apps**
4. **Protection > Conditional Access > Policies** → nouvelle policy :
   - Target resources > **Authentication context** = `c1`
   - Grant : **Require multifactor authentication**
   - Statut : `On`

## 2. Test en local

```bash
pip install -r requirements.txt
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# remplir secrets.toml avec vos valeurs (REDIRECT_URI = http://localhost:8501)
streamlit run streamlit_app.py
```

## 3. Déploiement gratuit sur Streamlit Community Cloud

1. Poussez ce dossier dans un repo GitHub (le `.gitignore` exclut déjà
   `secrets.toml` — ne le committez jamais)
2. Allez sur [share.streamlit.io](https://share.streamlit.io), connectez
   votre compte GitHub
3. **New app** → sélectionnez le repo, la branche, et
   `streamlit_app.py` comme fichier principal → **Deploy**
4. Notez l'URL publique attribuée (ex: `https://votre-app.streamlit.app`)
5. **Important** : retournez dans Entra ID > votre App registration >
   **Authentication**, et mettez à jour le Redirect URI avec cette URL
   exacte (sans slash final si l'app n'en ajoute pas)
6. Dans Streamlit Cloud : **App settings > Secrets**, collez le contenu de
   `secrets.toml.example` avec les vraies valeurs, en mettant
   `REDIRECT_URI` = l'URL publique de l'app
7. Rechargez l'app

## 4. Scénario de test

Identique à la version Node : connexion normale → badge "absent" → clic
sur "Tester l'action sensible" → écran de step-up → redirection Entra ID
avec exigence MFA → retour avec `acrs: ["c1"]` dans les claims → accès
accordé.

## Limites du tier gratuit à connaître

- L'app se met en veille après une période d'inactivité et redémarre
  (~30s) au prochain accès — sans impact pour du test manuel
- Pas de domaine personnalisé
- Un code d'autorisation est à usage unique : si vous rafraîchissez la
  page manuellement après un retour d'Entra ID, l'échange peut échouer
  (comportement normal OAuth, pas un bug) — relancez simplement le login
- Les secrets sont gérés via l'interface Streamlit Cloud, pas de fichier
  `.env` à uploader
