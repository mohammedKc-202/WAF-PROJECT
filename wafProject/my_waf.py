from flask import Flask, request, Response
import requests
import re
import datetime
from urllib.parse import unquote
app = Flask(__name__)

# L'adresse de l'application vulnérable (DVWA sur Docker)
TARGET_URL = "http://localhost:3000"

# ---------------------------------------------------------
# SÉCURITÉ : LOGS & DÉTECTION
# ---------------------------------------------------------

def ecrire_log(ip, payload, raison):
    """Écrit chaque blocage dans un fichier de log local."""
    date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("waf.log", "a", encoding="utf-8") as f:
        f.write(f"[{date}] IP: {ip} | Raison: {raison} | Payload: {payload}\n")


def est_malveillant(donnees):
    """Analyse les données pour détecter des patterns SQLi ou XSS."""
    if not donnees:
        return False
    
    # Décodage des caractères URL (ex: %3C -> <) et passage en minuscules
    data = unquote(donnees).lower()

    # 1. Détection par mots-clés simples
    mots_interdits = [
        "select", "union", "drop", "insert", "script", 
        "alert(", "onerror=", "1=1", "or 1=1"
    ]
    for mot in mots_interdits:
        if mot in data:
            print(f"[-] DEBUG: Mot interdit détecté -> {mot}")
            return True

    # 2. Détection avancée par Expressions Régulières (Regex)
    patterns = [
        r"<\s*script\s*>",                 # Balise <script> avec espaces
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # Caractères spéciaux SQL (', --, #)
        r"\b(or|and)\b.*\b\d+=\d+\b",      # Logiques d'injection type OR 1=1 ou AND 5=5
        r"union.*select",                  # Tentatives d'unions complexes
    ]

    for p in patterns:
        if re.search(p, data, re.IGNORECASE):
            print(f"[-] DEBUG: Regex match -> {p}")
            return True

    return False

# ---------------------------------------------------------
# INTERCEPTION & ROUTAGE
# ---------------------------------------------------------

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE"])
def proxy(path):
    # Force Flask à lire les données entrantes pour éviter les pertes du body
    request.get_data() 
    
    # 1. Récupération des données de la requête
    url_params = request.query_string.decode()
    body_data = request.form.to_dict()
    body_str = str(body_data) + request.get_data().decode()
    
    # Affichage de débogage dans le terminal
    print(f"[*] Analyse de l'URL : {unquote(url_params)}")

    # 2. Phase de vérification
    if est_malveillant(url_params) or est_malveillant(body_str):
        print("!!! VICTOIRE : ATTAQUE BLOQUÉE !!!")
        
        # Enregistrement de l'attaque dans le fichier log
        payload_complet = f"URL: {url_params} | BODY: {body_str}"
        ecrire_log(request.remote_addr, payload_complet, "Signature/Regex Match")
        
        # Envoi de la réponse 403 personnalisée au client
        page_blocage = """
        <html>
            <head>
                <meta charset="utf-8">
                <title>Accès Refusé</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; margin-top: 100px; background-color: #f8d7da; color: #721c24; }
                    .container { display: inline-block; padding: 30px; border: 2px solid #f5c6cb; background: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
                    h1 { margin-top: 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Accès Refusé</h1>
                    <p><strong>WAF de MohammedK :</strong> Une menace de sécurité a été détectée dans votre requête.</p>
                </div>
            </body>
        </html>
        """
        return Response(page_blocage, status=403, mimetype='text/html')

    # 3. Transmission de la requête propre à l'application cible (DVWA)
    url = f"{TARGET_URL}/{path}"
    
    resp = requests.request(
        method=request.method,
        url=url,
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False
    )

    # Reconstruction et nettoyage des en-têtes HTTP de réponse
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in resp.raw.headers.items()
               if name.lower() not in excluded_headers]

    return Response(resp.content, resp.status_code, headers)

if __name__ == '__main__':
    # Lance le WAF sur le port 5000 de toutes les interfaces de la machine
    app.run(host='0.0.0.0', port=5000)