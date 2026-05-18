# Construire l'application CAMILLE (.exe Windows)

L'application est une **app de bureau native** : une fenêtre Windows
autonome (sans navigateur ni barre d'adresse) qui embarque le moteur de
scan. Le `.exe` final ne nécessite **aucune installation de Python** sur la
machine cible.

---

## Méthode rapide (recommandée)

Sur une machine **Windows 10 ou 11**, depuis le dossier du projet :

```
build_windows.bat
```

Double-clique simplement sur ce fichier. Il va :
1. créer un environnement virtuel propre,
2. installer les dépendances + PyInstaller,
3. compiler l'exécutable.

Résultat : **`dist\CAMILLE.exe`**. Un fichier unique, déplaçable et
distribuable tel quel. Double-clic pour lancer.

---

## Méthode manuelle

```bat
python -m venv .build-venv
.build-venv\Scripts\activate
pip install -r requirements.txt pyinstaller pywebview
pyinstaller CAMILLE.spec
```

L'exécutable apparaît dans `dist\CAMILLE.exe`.

---

## Tester sans compiler (mode développement)

Pas besoin de construire le `.exe` pour utiliser l'app. Elle fonctionne
directement comme fenêtre native :

```bash
pip install -r requirements.txt pywebview
python -m camille.desktop
```

> Si `pywebview` n'est pas installé, l'app bascule automatiquement sur le
> navigateur par défaut — elle reste utilisable dans tous les cas.

---

## Notes techniques

- **Pas de runtime à installer sur la cible.** Sur Windows 10/11,
  `pywebview` utilise le moteur **Edge WebView2** déjà présent dans le
  système. Aucun navigateur tiers n'est requis.
- **Pourquoi pas de `.exe` fourni directement ?** Un exécutable Windows
  doit être compilé *sur* Windows (PyInstaller ne fait pas de
  cross-compilation Linux→Windows fiable). Toute la configuration est
  prête : la génération se fait en une commande.
- **macOS / Linux :** la même commande `pyinstaller CAMILLE.spec` produit
  un binaire natif pour la plateforme courante (`.app` / ELF). Adapte
  juste l'icône si besoin.
- **Antivirus :** les exécutables PyInstaller non signés déclenchent
  parfois un faux positif. Pour une distribution large, envisage une
  signature de code (certificat Authenticode).

---

## Structure ajoutée

```
CAMILLE/
├── camille/
│   └── desktop.py            # Point d'entrée de l'app de bureau
├── CAMILLE.spec              # Configuration PyInstaller
├── build_windows.bat         # Script de build en 1 clic
└── camille/web/static/
    ├── app.ico               # Icône de l'application
    └── app.png
```
