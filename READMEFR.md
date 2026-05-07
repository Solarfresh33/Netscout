NetScout
Outil de reconnaissance et d'analyse de sécurité réseau. Scannez des ports, analysez SSL/TLS, énumérez le DNS et auditez les en-têtes de sécurité HTTP en une seule commande.

Utilisation autorisée uniquement. Ne scannez que les systèmes que vous possédez ou pour lesquels vous avez une autorisation explicite.


Fonctionnalités
ModuleDescriptionScanner de portsScan TCP concurrent avec détection de services et récupération de bannièresAnalyseur SSL/TLSInspection de certificats, détection de protocoles/chiffrements faibles, vérification d'expirationÉnumérateur DNSEnregistrements A/AAAA/MX/NS/TXT/SOA, tentative de transfert de zone AXFR, bruteforce de sous-domainesAnalyseur HTTPAudit des en-têtes de sécurité (HSTS, CSP, X-Frame-Options…), flags des cookies, divulgation du serveurGénérateur de rapportsExport JSON et rapport HTML au thème sombre

Installation
Prérequis : Python 3.9+
bash# Cloner le dépôt
git clone <repo-url>
cd Projet-Cyber

# Installer les dépendances
pip install -r requirements.txt

Démarrage rapide
bash# Scan complet d'un domaine
python -m netscout.cli scan example.com

# Sauvegarder les rapports (JSON + HTML) dans un répertoire
python -m netscout.cli scan example.com --output ./rapports

Commandes
scan : Lancer un scan de sécurité
python -m netscout.cli scan CIBLE [OPTIONS]
CIBLE peut être un nom de domaine (example.com), une adresse IP (192.168.1.1) ou une URL (https://example.com).
Options
OptionDéfautDescription-p, --ports33 ports principauxPorts à scanner : 80,443 ou une plage 1-1024--no-ports—Ignorer le scan de ports--no-ssl—Ignorer l'analyse SSL/TLS--no-dns—Ignorer l'énumération DNS--no-http—Ignorer l'analyse des en-têtes HTTP--no-bruteforce—Ignorer le bruteforce de sous-domaines--ssl-port443Port utilisé pour la connexion SSL/TLS-o, --output—Répertoire de sauvegarde des rapports-f, --formatbothFormat du rapport : json, html ou both--threads100Nombre de threads pour le scanner--allow-private—Autoriser le scan de cibles privées/internes (RFC 1918, loopback, etc.)-q, --quiet—Masquer la bannière et les indicateurs de progression
Exemples
bash# Scanner uniquement les ports principaux (sans DNS ni HTTP)
python -m netscout.cli scan 10.0.0.1 --no-dns --no-http

# Scanner une plage de ports personnalisée et sauvegarder un rapport JSON
python -m netscout.cli scan example.com --ports 1-1024 --output ./rapports --format json

# Scan HTTPS uniquement sur un port non standard
python -m netscout.cli scan example.com --no-ports --no-dns --ssl-port 8443

# Scan rapide — ignorer le bruteforce de sous-domaines, utiliser plus de threads
python -m netscout.cli scan example.com --no-bruteforce --threads 200

# Mode silencieux, sauvegarder un rapport HTML
python -m netscout.cli scan example.com -q --output ./rapports --format html

info : Afficher l'état des modules
bashpython -m netscout.cli info
Affiche les dépendances optionnelles disponibles (requests, dnspython, jinja2).

Rapports
Lorsque --output est défini, NetScout écrit les rapports dans le répertoire spécifié.
rapports/
├── example_com.json   # Résultat complet du scan (lisible par machine)
└── example_com.html   # Rapport lisible au thème sombre
Le rapport HTML contient :

Tableau des ports ouverts avec bannières
Score SSL/TLS (0–100) avec détails du certificat et problèmes détectés
Enregistrements DNS et sous-domaines découverts
Score des en-têtes de sécurité HTTP avec recommandations de correction


Scoring SSL/TLS
Le score SSL commence à 100 et est réduit pour chaque anomalie détectée :
AnomalieDéductionCertificat expiré−40Protocole faible (TLS < 1.2, SSLv3…)−30Chiffrement faible (RC4, DES, NULL…)−20Clé trop courte (< 2048 bits)−20Certificat expirant dans < 30 jours−15Certificat auto-signé−10

Scoring des en-têtes de sécurité HTTP
Le score HTTP commence à 100 et est réduit pour chaque en-tête absent ou mal configuré :
En-têteSévéritéDéductionStrict-Transport-SecurityÉLEVÉE−20Content-Security-PolicyÉLEVÉE−20X-Frame-OptionsMOYENNE−10X-Content-Type-OptionsMOYENNE−10Referrer-PolicyFAIBLE−5Permissions-PolicyFAIBLE−5X-XSS-ProtectionFAIBLE−5HSTS max-age < 6 moisMOYENNE−10Cookie sans flag Secure/HttpOnlyMOYENNE−10 par cookie

Lancer les tests
bashPYTHONPATH=. python -m pytest netscout/tests/ -v
53 tests unitaires couvrant tous les modules. Aucun appel réseau n'est effectué pendant les tests (les sockets et requêtes sont simulés).

Structure du projet
Projet-Cyber/
├── netscout/
│   ├── cli.py                  # Point d'entrée CLI (Click)
│   ├── core/
│   │   ├── models.py           # Classes de données (ScanResult, PortResult, …)
│   │   └── utils.py            # Validation de cible, correspondance des services
│   ├── modules/
│   │   ├── port_scanner.py     # Scanner de ports TCP
│   │   ├── ssl_analyzer.py     # Analyseur SSL/TLS
│   │   ├── dns_enum.py         # Énumérateur DNS
│   │   └── http_analyzer.py    # Analyseur d'en-têtes HTTP
│   ├── reports/
│   │   └── generator.py        # Générateur de rapports JSON + HTML
│   └── tests/                  # Tests unitaires
├── requirements.txt
└── pyproject.toml

By Solar