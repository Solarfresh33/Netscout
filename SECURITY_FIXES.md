# Corrections de sécurité — CAMILLE

Résumé des modifications apportées suite à l'audit de sécurité.

## 🔴 Fix #1 — XSS stocké dans le rapport HTML (CRITIQUE)

**Fichier :** `camille/reports/generator.py`

### Avant
```python
env = Environment(loader=BaseLoader())
```
Toutes les données issues de la cible (bannières, en-têtes `Server`,
`commonName` du certificat, SAN, enregistrements DNS, sous-domaines AXFR,
URLs de redirection) étaient injectées brutes dans le HTML. Un attaquant
contrôlant un serveur scanné pouvait y placer du JavaScript qui s'exécutait
ensuite dans le navigateur de l'analyste.

### Après
```python
env = Environment(
    loader=BaseLoader(),
    autoescape=select_autoescape(["html", "xml"]),
)
```
+ ajout d'une **Content-Security-Policy** stricte dans le `<head>` du
template (défense en profondeur — bloque tout JS même si un autre bug
permettait de contourner l'échappement).

### Vérification
```python
banner = '<script>alert("PWNED")</script>'
# Avant : apparaissait tel quel → XSS
# Après : '&lt;script&gt;alert(&#34;PWNED&#34;)&lt;/script&gt;' → texte inerte
```

---

## 🟠 Fix #2 — Injection ANSI dans les bannières (ÉLEVÉ)

**Fichier :** `camille/modules/port_scanner.py`

### Avant
```python
return raw.decode(errors="replace").strip()[:200]
```
Une bannière contenant `\x1b[2J\x1b[H` effaçait l'écran du terminal de
l'analyste, masquant des résultats déjà imprimés.

### Après
```python
_CTRL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

def _sanitize_banner(text: str) -> str:
    cleaned = _CTRL_CHARS.sub("", text)
    return cleaned.strip()[:200]
```
On supprime tous les caractères de contrôle ASCII (sauf `\t`, `\n`, `\r`).
Le caractère `\x1b` (ESC) qui déclenche l'interprétation des séquences ANSI
est retiré, donc `[2J` apparaît en texte brut.

---

## 🟠 Fix #3 — TLS verify=False par défaut (ÉLEVÉ)

**Fichier :** `camille/modules/http_analyzer.py`

### Avant
```python
response = requests.get(url, verify=False, allow_redirects=True, ...)
```
Désactivait la validation du certificat dès la première tentative — un MITM
pouvait injecter n'importe quel contenu.

### Après
```python
def _fetch(url):
    try:
        return requests.get(url, verify=True, ...), True
    except SSLError:
        # Fallback verify=False, mais signalé dans le rapport
        return requests.get(url, verify=False, ...), False
```
- Tentative initiale **avec** vérification stricte
- Fallback uniquement si le certif est cassé (cas d'usage légitime pour
  un scanner), avec une `HeaderIssue` HIGH dans le rapport
- Suppression explicite du warning `urllib3.InsecureRequestWarning`
- Audit des redirections (`_audit_redirects`) qui signale tout changement
  de host (défense en profondeur SSRF)

---

## 🟡 Fix #4 — Exceptions trop larges (MOYEN)

**Fichier :** `camille/modules/dns_enum.py`

### Avant
```python
except (dns.exception.DNSException, Exception):
    continue
```
Avalait silencieusement `KeyError`, `AttributeError`, `MemoryError`...
masquant d'éventuels comportements anormaux (DNS forgé, cache poisoning).

### Après
```python
_DNS_EXPECTED_ERRORS = (
    dns.exception.DNSException,
    socket.error, ConnectionError, TimeoutError, ValueError,
)
...
except _DNS_EXPECTED_ERRORS:
    continue
```
On liste explicitement les exceptions attendues. Tout le reste remonte
naturellement et peut être diagnostiqué.

---

## 🟡 Fix #5 — Crash sur cipher() = None (MOYEN)

**Fichier :** `camille/modules/ssl_analyzer.py`

### Avant
```python
cipher_name, proto, bits = tls_sock.cipher()  # TypeError si None
```

### Après
```python
cipher_info = tls_sock.cipher()
if cipher_info is None:
    cipher_name, proto, bits = "unknown", "unknown", 0
else:
    cipher_name = cipher_info[0] or "unknown"
    ...
```
+ vérification également ajoutée pour `cert` qui peut être `{}` ou `None`
selon les conditions de la handshake.

---

## 🟡 Fix #6 — Détection des cibles privées (MOYEN)

**Fichiers :** `camille/core/utils.py`, `camille/cli.py`

### Nouveautés
- `is_private_target(target)` : détecte loopback, RFC 1918, link-local,
  multicast, etc.
- Flag CLI **`--allow-private`** : par défaut, CAMILLE refuse de scanner
  une cible interne (refuser un scan de `169.254.169.254` empêche
  l'extraction accidentelle de credentials de métadonnées cloud).
- `safe_filename(name)` : assainit les noms de fichiers de rapport via
  whitelist `[A-Za-z0-9._-]` — défense en profondeur contre un éventuel
  contournement futur de la regex de validation.

### Exemple
```bash
$ camille scan 192.168.1.1
Refusing to scan private/internal target: 192.168.1.1
Re-run with --allow-private if you really intend to scan internal
infrastructure (and have authorisation to do so).

$ camille scan 192.168.1.1 --allow-private
[scan proceeds]
```

---

## Tests

Les **53 tests unitaires existants passent toujours** sans modification —
les changements sont rétrocompatibles côté API.

```bash
PYTHONPATH=. python -m pytest camille/tests/ -v
# ============================== 53 passed in 0.33s ==============================
```

---

## Récapitulatif des fichiers modifiés

| Fichier | Changement |
|---------|-----------|
| `camille/reports/generator.py` | Autoescape Jinja2 + CSP |
| `camille/modules/port_scanner.py` | Sanitisation ANSI |
| `camille/modules/http_analyzer.py` | TLS strict-first + audit redirects |
| `camille/modules/dns_enum.py` | Exceptions explicites |
| `camille/modules/ssl_analyzer.py` | Gestion cipher()=None |
| `camille/core/utils.py` | `is_private_target` + `safe_filename` |
| `camille/cli.py` | Flag `--allow-private` + filename safe |

Aucun changement dans `camille/core/models.py` — les structures de données
sont conservées telles quelles.
