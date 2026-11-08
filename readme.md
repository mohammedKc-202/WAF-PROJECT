Projet : Under the Hood – Building and Deploying a WAF
1. Présentation du Projet
Ce projet consiste en la mise en place d'une architecture de sécurité multicouche pour protéger une application web vulnérable. L'objectif est de comparer l'efficacité d'un WAF open-source industriel (ModSecurity) par rapport à un WAF personnalisé développé de toutes pièces en Python. Ce travail permet d'analyser l'interception du trafic HTTP, l'inspection des payloads et les mécanismes de détection par signatures et expressions régulières.

2. Architecture Réseau
L'environnement est déployé sur une machine Kali Linux utilisant la technologie Docker pour l'isolation des services :

Application Cible (Target) : DVWA (Damn Vulnerable Web App) fonctionnant sur le port 80.

WAF Open-Source : ModSecurity avec le Core Rule Set (CRS) de l'OWASP, agissant comme reverse proxy sur le port 8081.

Custom WAF : Script Python (Flask) agissant comme reverse proxy sur le port 5000.

3. Guide d'Installation et Déploiement
Déploiement de la cible (DVWA)
Bash
sudo docker run -d --net=host --name dvwa vulnerables/web-dvwa
Déploiement du WAF Open-Source (ModSecurity)
Bash
sudo docker run -d --net=host \
   --name mon-waf-pro \
   -e PROXY_LOCATION=http://127.0.0.1:80 \
   -e PORT=8081 \
   owasp/modsecurity-crs:nginx
Déploiement du Custom WAF
Installer les dépendances :

Bash
pip install flask requests
Lancer le script :

Bash
   python3 my_waf.py
4. Fonctionnalités du Custom WAF
Le script my_waf.py remplit les exigences suivantes :

Interception de trafic : Fonctionnement en mode Reverse Proxy.

Inspection Engine : Analyse complète de l'URI, des Headers et du Body (POST data).

Logique de détection : Détection de patterns SQL Injection (ex: UNION SELECT, OR 1=1) et XSS (ex: <script>) via des expressions régulières et du filtrage de chaînes.

Gestion des réponses : Blocage des requêtes malveillantes avec un code HTTP 403 Forbidden et une page HTML personnalisée.

Logging : Journalisation dans waf.log incluant l'horodatage, l'IP de l'attaquant, la règle déclenchée et le payload détecté.

5. Méthodologie de Test (Showdown)
L'efficacité des dispositifs a été évaluée selon trois axes :

Tests manuels : Exploitation de failles XSS et SQLi pour vérifier le blocage immédiat.

Tests automatisés : Utilisation de scanners de vulnérabilités (Nikto/OWASP ZAP) pour comparer les taux de blocage.

Analyse des faux positifs : Vérification de la navigation normale pour s'assurer que les règles ne sont pas trop restrictives.

6. Structure des Fichiers du Dépôt
my_waf.py : Code source du WAF personnalisé.

waf.log : Exemple de fichier de journalisation des attaques.

README.md : Instructions et documentation du projet.

rapport_final.pdf : Analyse comparative détaillée (FortiWeb vs Open-Source vs Custom).