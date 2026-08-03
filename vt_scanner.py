# filepath: vt_scanner.py
# ============================================================================
# VirusTotal Scanner CLI - VERSION 1.2.0 (Python 3.10+ Secure Edition)
# ============================================================================
# Auteur: valorisa
# Description: Scan fichiers/dossiers/URLs via l'API VirusTotal v3 en CLI.
# Licence: Personal/Edu (alignée README du projet)
# ============================================================================
from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import locale
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

# cryptography and keyring are required in requirements.txt, but import them
# in a tolerant manner to avoid hard ImportError at module import time on
# partially provisioned environments (dev machines, CI edge cases).
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    Fernet = None
    InvalidToken = None

try:
    import keyring
    from keyring.errors import KeyringError
except ImportError:
    keyring = None

    class KeyringError(Exception):
        """Fallback KeyringError used when `keyring` is not installed."""

# Exceptions to catch for Fernet decrypt/load operations.
FERNET_DECRYPT_EXCEPTIONS = (OSError, ValueError, RuntimeError)  # pylint: disable=invalid-name
if InvalidToken is not None:
    FERNET_DECRYPT_EXCEPTIONS += (InvalidToken,)


# -----------------------------
# Constantes (alignées PS1)
# -----------------------------
BASE_URL: str = "https://www.virustotal.com/api/v3".strip()
DELAY_BETWEEN_REQUESTS: int = 16
HTTP_TIMEOUT_SEC: int = 30

MAX_FILE_SIZE_BYTES: int = 650 * 1024 * 1024  # ~650MB

API_KEYRING_SERVICE: str = "vt-scanner-cli"
API_KEYRING_USERNAME: str = "api_key"

CONFIG_DIR: Path = Path.home() / ".vt-scanner"
FERNET_KEY_PATH: Path = CONFIG_DIR / "fernet.key"
FERNET_APIKEY_PATH: Path = CONFIG_DIR / "api_key.enc"

USER_AGENT: str = "VT-Scanner-CLI/1.2-python"

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


# -----------------------------
# Couleurs (colorama + fallback)
# -----------------------------
try:
    from colorama import Fore as _Fore  # type: ignore
    from colorama import Style as _Style  # type: ignore
    from colorama import init as _colorama_init  # type: ignore

    _colorama_init(autoreset=True)

    class C:
        CYAN = _Fore.CYAN
        GREEN = _Fore.GREEN
        RED = _Fore.RED
        YELLOW = _Fore.YELLOW
        GRAY = getattr(_Fore, "LIGHTBLACK_EX", _Fore.WHITE)
        WHITE = _Fore.WHITE
        BRIGHT = _Style.BRIGHT
        RESET = _Style.RESET_ALL

except ImportError:  # pragma: no cover
    class C:  # type: ignore
        CYAN = GREEN = RED = YELLOW = GRAY = WHITE = BRIGHT = RESET = ""


# -----------------------------
# Exceptions métier
# -----------------------------
class QuotaExceededError(RuntimeError):
    pass


class InvalidApiKeyError(RuntimeError):
    pass


@dataclass(frozen=True)
class Verdict:
    text: str
    is_malicious: Optional[bool]  # None si indisponible


# -----------------------------
# Utilitaires
# -----------------------------
def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def cprint(text: str, color: str = "") -> None:
    """Print text with optional color reset."""
    print(f"{color}{text}{C.RESET}")


def prompt(text: str) -> str:
    """Prompt user and return stripped input (returns empty string on EOF)."""
    # input() peut lever EOFError; on normalise.
    try:
        return input(text).strip()
    except EOFError:
        return ""


def ensure_config_dir() -> None:
    """Ensure configuration directory exists with restrictive permissions."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(CONFIG_DIR, 0o700)
        except OSError:
            # best-effort, ne doit pas casser l'exécution
            pass


def get_csv_delimiter() -> str:
    """Return a CSV delimiter adapted to current locale (',' or ';')."""
    # Approche proche de PowerShell Export-Csv -UseCulture:
    # si décimale ',', le séparateur liste est souvent ';' en FR/Europe.
    try:
        locale.setlocale(locale.LC_ALL, "")
        dec = locale.localeconv().get("decimal_point", ".")
        return ";" if dec == "," else ","
    except locale.Error:
        return ","


def compute_sha256(file_path: Path) -> str:
    """Compute and return the SHA256 hex digest of a file (lowercase)."""
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def validate_sha256(s: str) -> bool:
    """Validate that a string is exactly a 64-hex-character SHA256."""
    return bool(SHA256_RE.fullmatch(s.strip()))


def normalize_and_validate_url(s: str) -> Optional[str]:
    """Normalize and validate an HTTP/HTTPS URL. Return canonical URL or None."""
    s = s.strip()
    if not s:
        return None
    if not s.startswith(("http://", "https://")):
        s = f"https://{s}"
    # urlparse does not raise on normal input; validate components explicitly.
    u = urlparse(s)
    if u.scheme not in ("http", "https"):
        return None
    if not u.netloc:
        return None
    return s


# -----------------------------
# Stockage sécurisé clé API
# -----------------------------
def _fernet_load_or_create_key() -> "Fernet":
    """Load or create a Fernet key file and return a Fernet instance.

    Raises:
        RuntimeError: if the `cryptography` package is not installed.
    """
    ensure_config_dir()
    if Fernet is None:
        raise RuntimeError("cryptography package is required for Fernet operations")

    if not FERNET_KEY_PATH.exists():
        key = Fernet.generate_key()
        FERNET_KEY_PATH.write_bytes(key)
        if os.name != "nt":
            try:
                os.chmod(FERNET_KEY_PATH, 0o600)
            except OSError:
                pass
    else:
        key = FERNET_KEY_PATH.read_bytes()

    return Fernet(key)


def _save_api_key_fernet(api_key: str) -> bool:
    try:
        f = _fernet_load_or_create_key()
        token = f.encrypt(api_key.encode("utf-8"))
        FERNET_APIKEY_PATH.write_bytes(token)
        if os.name != "nt":
            try:
                os.chmod(FERNET_APIKEY_PATH, 0o600)
            except OSError:
                pass
        return True
    except FERNET_DECRYPT_EXCEPTIONS as e:
        cprint(f"Impossible de sauvegarder la clé API (fallback Fernet) : {e}", C.YELLOW)
        return False


def _load_api_key_fernet() -> Optional[str]:
    try:
        if not FERNET_APIKEY_PATH.exists():
            return None
        f = _fernet_load_or_create_key()
        token = FERNET_APIKEY_PATH.read_bytes()
        # decrypt() raises InvalidToken when the encrypted payload is invalid.
        return f.decrypt(token).decode("utf-8")
    except FERNET_DECRYPT_EXCEPTIONS as e:
        cprint(f"Impossible de charger la clé API (fallback Fernet) : {e}", C.YELLOW)
        return None


def _delete_api_key_fernet() -> bool:
    try:
        if FERNET_APIKEY_PATH.exists():
            FERNET_APIKEY_PATH.unlink()
        return True
    except OSError as e:
        cprint(f"Impossible de supprimer la clé API locale (fallback Fernet) : {e}", C.YELLOW)
        return False


def save_api_key(api_key: str) -> bool:
    """Save API key using keyring primary backend, fallback to Fernet file storage."""
    api_key = api_key.strip()
    if not api_key:
        return False

    # If keyring is not available, directly use Fernet fallback (best-effort).
    if keyring is None:
        return _save_api_key_fernet(api_key)

    try:
        keyring.set_password(API_KEYRING_SERVICE, API_KEYRING_USERNAME, api_key)
        return True
    except (KeyringError, RuntimeError) as e:
        cprint(f"[INFO] keyring a échoué ({type(e).__name__}). Fallback Fernet activé.", C.GRAY)
        return _save_api_key_fernet(api_key)


def load_api_key() -> Optional[str]:
    """Load API key from keyring or fallback to Fernet storage."""
    # If keyring is not available, use Fernet fallback.
    if keyring is None:
        return _load_api_key_fernet()

    try:
        k = keyring.get_password(API_KEYRING_SERVICE, API_KEYRING_USERNAME)
        if k:
            return k.strip()
        return None
    except (KeyringError, RuntimeError):
        return _load_api_key_fernet()


def delete_api_key() -> bool:
    """Delete API key from keyring and local Fernet fallback (best-effort)."""
    ok = True
    if keyring is not None:
        try:
            keyring.delete_password(API_KEYRING_SERVICE, API_KEYRING_USERNAME)
        except (KeyringError, RuntimeError):
            ok = ok and True  # best-effort if keyring backend fails
    ok = ok and _delete_api_key_fernet()
    return ok


# -----------------------------
# HTTP / API VT
# -----------------------------
def build_session(api_key: str) -> requests.Session:
    s = requests.Session()
    update_headers(s, api_key)
    return s


def update_headers(session: requests.Session, api_key: str) -> None:
    clean = api_key.strip()
    session.headers.clear()
    session.headers.update(
        {
            "x-apikey": clean,
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
    )


def test_api_key(session: requests.Session) -> bool:
    try:
        r = session.get(f"{BASE_URL}/users/me", timeout=HTTP_TIMEOUT_SEC)
    except requests.exceptions.RequestException as e:
        cprint(f"Erreur de connexion : {e}", C.RED)
        return False

    if r.status_code == 200:
        return True
    if r.status_code == 401:
        cprint("Cle API invalide ou non autorisee.", C.RED)
        return False
    if r.status_code == 403:
        cprint("Quota depasse ou acces refuse.", C.RED)
        return False

    cprint(f"Erreur HTTP {r.status_code} : {r.text[:200]}", C.RED)
    return False


def _extract_last_analysis_stats(payload: Dict[str, Any]) -> Optional[Dict[str, int]]:
    try:
        stats = payload["data"]["attributes"]["last_analysis_stats"]
        # s'assurer que les clés attendues existent
        return {
            "harmless": int(stats.get("harmless", 0)),
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "timeout": int(stats.get("timeout", 0)),
            "undetected": int(stats.get("undetected", 0)),
        }
    except (KeyError, TypeError, ValueError):
        return None


def get_scan_report(session: requests.Session, resource_id: str, kind: str = "files") -> Optional[Dict[str, int]]:
    if kind not in ("files", "urls"):
        raise ValueError("kind must be 'files' or 'urls'")

    url = f"{BASE_URL}/{kind}/{resource_id}"
    try:
        r = session.get(url, timeout=HTTP_TIMEOUT_SEC)
    except requests.exceptions.RequestException:
        return None

    if r.status_code == 200:
        try:
            return _extract_last_analysis_stats(r.json())
        except ValueError:
            return None

    if r.status_code == 404:
        return None
    if r.status_code == 401:
        raise InvalidApiKeyError("API key invalid")
    if r.status_code == 403:
        raise QuotaExceededError("Quota exceeded or forbidden")

    # autres erreurs : on reste silencieux comme PS (Write-Verbose)
    return None


def wait_vt_analysis(
    session: requests.Session,
    resource_id: str,
    kind: str,
    timeout_minutes: int,
    sleep_seconds: int,
) -> Optional[Dict[str, int]]:
    deadline = time.time() + (timeout_minutes * 60)
    while time.time() < deadline:
        time.sleep(sleep_seconds)
        cprint(".", C.GRAY)
        stats = get_scan_report(session, resource_id, kind)
        if stats:
            return stats
    return None


def format_verdict(stats: Optional[Dict[str, int]]) -> Verdict:
    if not stats:
        return Verdict("Indisponible", None)
    total = sum(stats.get(k, 0) for k in ("harmless", "malicious", "suspicious", "timeout", "undetected"))
    malicious = int(stats.get("malicious", 0))
    if malicious == 0:
        return Verdict(f"Propre ({total} analyses)", False)
    return Verdict(f"{malicious}/{total} detections malveillantes", True)


# -----------------------------
# Export CSV
# -----------------------------
def export_scan_results(results: List[Dict[str, Any]], path_scanned: str) -> bool:
    if not results:
        cprint("Aucun resultat a exporter.", C.YELLOW)
        return False

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vt_scan_report_{ts}.csv"
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    delim = get_csv_delimiter()

    # Colonnes: on conserve toutes les clés + ScanDate + SourcePath comme PS
    fieldnames = list(results[0].keys()) + ["ScanDate", "SourcePath"]

    try:
        with open(filename, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, delimiter=delim)
            w.writeheader()
            for row in results:
                out = dict(row)
                out["ScanDate"] = scan_date
                out["SourcePath"] = path_scanned
                w.writerow(out)
        cprint(f"[OK] Rapport exporte : {filename}", C.GREEN)
        return True
    except OSError as e:
        cprint(f"Echec de l'export CSV : {e}", C.RED)
        return False


# -----------------------------
# Fonctions de scan (équivalents PS)
# -----------------------------
def scan_file(session: requests.Session, file_path_str: Optional[str] = None, auto_upload: bool = False) -> None:
    fp = (file_path_str or prompt("Chemin du fichier: ")).strip().strip('"')
    if not fp:
        cprint("Chemin invalide.", C.YELLOW)
        return
    p = Path(fp)
    if not p.exists() or not p.is_file():
        cprint(f"Fichier introuvable : {fp}", C.RED)
        return

    try:
        size = p.stat().st_size
    except OSError as e:
        cprint(f"Impossible d'acceder au fichier : {e}", C.RED)
        return

    if size > MAX_FILE_SIZE_BYTES:
        cprint("Fichier trop volumineux (>650MB - limite API VT)", C.RED)
        return

    try:
        sha256 = compute_sha256(p)
    except OSError as e:
        cprint(f"Impossible de calculer le hash SHA256 : {e}", C.RED)
        return

    cprint(f"Hash: {sha256}", C.CYAN)

    try:
        stats = get_scan_report(session, sha256, "files")
    except QuotaExceededError:
        cprint("Quota depasse ou acces refuse.", C.RED)
        return
    except InvalidApiKeyError:
        cprint("Cle API invalide ou non autorisee.", C.RED)
        return

    if stats:
        cprint(f"\n=== Resultat '{p.name}' (cache VT) ===", C.CYAN)
        verdict = format_verdict(stats)
        cprint(verdict.text, C.RED if verdict.is_malicious else C.GREEN)
        return

    cprint("\nFichier inconnu VT. Upload requis.", C.YELLOW)
    if not auto_upload:
        cprint("Consomme 1 quota (4/min). Continuer ? (o/N)", C.RED)
        confirm = prompt("Entrez 'o' pour continuer: ")
        if confirm.lower() != "o":
            cprint("Abandon. Utilisez option 4 pour re-verifier plus tard.", C.YELLOW)
            return

    upload_url = f"{BASE_URL}/files"
    try:
        with p.open("rb") as f:
            files = {"file": (p.name, f, "application/octet-stream")}
            cprint("Upload...", C.YELLOW)
            r = session.post(upload_url, files=files, timeout=HTTP_TIMEOUT_SEC)
    except requests.exceptions.RequestException as e:
        cprint(f"Erreur upload: {e}", C.RED)
        return
    except OSError as e:
        cprint(f"Erreur lecture fichier: {e}", C.RED)
        return

    if r.status_code == 401:
        cprint("Cle API invalide ou non autorisee.", C.RED)
        return
    if r.status_code == 403:
        cprint("Quota depasse ou acces refuse.", C.RED)
        return
    if r.status_code not in (200, 201):
        cprint(f"Erreur upload HTTP {r.status_code}: {r.text[:400]}", C.RED)
        return

    cprint("Upload OK!", C.GREEN)
    cprint("Polling analyse (max 4min)...", C.YELLOW)

    stats2 = wait_vt_analysis(session, sha256, "files", timeout_minutes=4, sleep_seconds=15)
    cprint(f"\n=== Resultat '{p.name}' ===", C.CYAN)
    verdict2 = format_verdict(stats2)
    if verdict2.is_malicious is None:
        cprint("Encore en analyse (re-testez plus tard avec opt 1/4)", C.YELLOW)
    else:
        cprint(verdict2.text, C.RED if verdict2.is_malicious else C.GREEN)


def scan_folder(session: requests.Session, folder_path_str: Optional[str] = None) -> None:
    folder = (folder_path_str or prompt("Chemin du dossier: ")).strip().strip('"')
    if not folder:
        cprint("Chemin invalide.", C.YELLOW)
        return
    root = Path(folder)
    if not root.exists() or not root.is_dir():
        cprint(f"Dossier introuvable : {folder}", C.RED)
        return

    files: List[Path] = []
    try:
        for p in sorted((x for x in root.rglob("*") if x.is_file()), key=lambda x: str(x).lower()):
            files.append(p)
            if len(files) >= 10:
                break
    except OSError as e:
        cprint(f"Impossible de parcourir le dossier : {e}", C.RED)
        return

    total = len(files)
    if total == 0:
        cprint("Aucun fichier trouve dans ce dossier.", C.YELLOW)
        return

    cprint(f"\n[ATTENTION] Scan limite aux {total} premiers fichiers (Quota API gratuit).", C.YELLOW)
    cprint(f"Debut du scan de {total} fichiers...", C.CYAN)

    results: List[Dict[str, Any]] = []
    error_count = 0

    for idx, fpath in enumerate(files, start=1):
        try:
            sha256 = compute_sha256(fpath)
            stats = get_scan_report(session, sha256, "files")
            if stats:
                verdict = format_verdict(stats)
                is_mal = bool(verdict.is_malicious)
                results.append(
                    {
                        "FileName": fpath.name,
                        "FilePath": str(fpath),
                        "FileSizeMB": round(fpath.stat().st_size / (1024 * 1024), 2),
                        "SHA256": sha256,
                        "Status": verdict.text,
                        "Malicious": is_mal,
                        "Detections": int(stats.get("malicious", 0)),
                        "TotalEngines": sum(stats.values()),
                        "ScanSuccess": True,
                        "ErrorMsg": "",
                    }
                )
                color = C.RED if is_mal else C.GREEN
                cprint(f"[{idx}/{total}] [+] {fpath.name} : {verdict.text}", color)
            else:
                results.append(
                    {
                        "FileName": fpath.name,
                        "FilePath": str(fpath),
                        "FileSizeMB": round(fpath.stat().st_size / (1024 * 1024), 2),
                        "SHA256": sha256,
                        "Status": "Inconnu (Non analyse)",
                        "Malicious": False,
                        "Detections": 0,
                        "TotalEngines": 0,
                        "ScanSuccess": True,
                        "ErrorMsg": "Non trouve dans le cache VT",
                    }
                )
                cprint(f"[{idx}/{total}] [?] {fpath.name} : Inconnu", C.GRAY)

        except QuotaExceededError:
            cprint("\n[QUOTA] DEPASSE. Arret du scan pour preserver l'API.", C.RED)
            cprint("Conseil : Attendez 1 minute ou passez a une cle API payante.", C.GRAY)
            break
        except InvalidApiKeyError:
            cprint("Cle API invalide ou non autorisee.", C.RED)
            error_count += 1
        except (OSError, requests.exceptions.RequestException) as e:
            error_count += 1
            results.append(
                {
                    "FileName": fpath.name,
                    "FilePath": str(fpath),
                    "FileSizeMB": round((fpath.stat().st_size if fpath.exists() else 0) / (1024 * 1024), 2),
                    "SHA256": sha256 if "sha256" in locals() else "",
                    "Status": "Erreur",
                    "Malicious": False,
                    "Detections": 0,
                    "TotalEngines": 0,
                    "ScanSuccess": False,
                    "ErrorMsg": str(e),
                }
            )
            cprint(f"[{idx}/{total}] [-] {fpath.name} : Echec du scan", C.RED)

        # Respect strict du délai comme dans PS
        time.sleep(DELAY_BETWEEN_REQUESTS)

    if results:
        cprint("\n--- Resume du scan ---", C.CYAN)
        _print_results_table(results)

        cprint("\nSouhaitez-vous exporter ces resultats en CSV ?", C.YELLOW)
        export_choice = prompt("Tapez 'o' pour exporter (Entree pour ignorer): ")
        if export_choice.lower() == "o":
            export_scan_results(results, folder)

    if error_count > 0:
        cprint(f"Le scan s'est termine avec {error_count} erreur(s).", C.YELLOW)


def _print_results_table(results: List[Dict[str, Any]]) -> None:
    headers = ["FileName", "Status", "Detections"]
    rows = [[str(r.get(h, "")) for h in headers] for r in results]
    widths = [max(len(h), *(len(row[i]) for row in rows)) for i, h in enumerate(headers)]
    line = " ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    sep = " ".join("-" * widths[i] for i in range(len(headers)))
    print(line)
    print(sep)
    for row in rows:
        print(" ".join(row[i].ljust(widths[i]) for i in range(len(headers))))


def scan_url(session: requests.Session, url_str: Optional[str] = None) -> None:
    raw = url_str or prompt("URL a scanner (HTTPS recommande): ")
    url = normalize_and_validate_url(raw)
    if not url:
        cprint("URL invalide", C.RED)
        return

    cprint(f"URL validee : {url}", C.CYAN)

    try:
        r = session.post(
            f"{BASE_URL}/urls",
            data={"url": url},
            timeout=HTTP_TIMEOUT_SEC,
            headers={**session.headers, "Content-Type": "application/x-www-form-urlencoded"},
        )
    except requests.exceptions.RequestException as e:
        cprint(f"Erreur scan URL: {e}", C.RED)
        return

    if r.status_code == 401:
        cprint("Cle API invalide ou non autorisee.", C.RED)
        return
    if r.status_code == 403:
        cprint("Quota depasse ou acces refuse.", C.RED)
        return
    if r.status_code not in (200, 201):
        cprint(f"Erreur scan URL HTTP {r.status_code}: {r.text[:400]}", C.RED)
        return

    try:
        payload = r.json()
        url_id = payload["data"]["id"]
    except (ValueError, KeyError, TypeError):
        cprint("Reponse serveur inattendue (impossible de lire l'ID).", C.RED)
        return

    cprint(f"ID Scan: {url_id}", C.GRAY)
    cprint("Scan lance. Attente des resultats (max 5 min)...", C.YELLOW)

    deadline = time.time() + (5 * 60)
    stats: Optional[Dict[str, int]] = None
    while time.time() < deadline:
        time.sleep(20)
        print(f"{C.GRAY}.", end=f"{C.RESET}", flush=True)
        try:
            stats = get_scan_report(session, url_id, "urls")
        except (QuotaExceededError, InvalidApiKeyError):
            break
        if stats:
            break
    print()

    if stats:
        cprint(f"\nResultat '{url}':", C.CYAN)
        verdict = format_verdict(stats)
        cprint(verdict.text, C.RED if verdict.is_malicious else C.GREEN)
    else:
        cprint("Analyse toujours en cours apres 5 minutes. Notez l'ID et re-testez plus tard.", C.YELLOW)


def scan_hash(session: requests.Session, hash_str: Optional[str] = None) -> None:
    h = (hash_str or prompt("SHA256 hash (64 caracteres): ")).strip()
    if not validate_sha256(h):
        cprint("Hash invalide : doit contenir exactement 64 caracteres hexadecimaux", C.RED)
        return

    try:
        stats = get_scan_report(session, h.lower(), "files")
    except QuotaExceededError:
        cprint("Quota depasse ou acces refuse.", C.RED)
        return
    except InvalidApiKeyError:
        cprint("Cle API invalide ou non autorisee.", C.RED)
        return

    cprint(f"\nResultat hash '{h}':", C.CYAN)
    verdict = format_verdict(stats)
    if verdict.is_malicious is None:
        cprint(verdict.text, C.YELLOW)
    else:
        cprint(verdict.text, C.RED if verdict.is_malicious else C.GREEN)


def check_existing_scan(session: requests.Session, analysis_id_str: Optional[str] = None) -> None:
    cprint("\n--- Consulter un scan existant ---", C.CYAN)
    analysis_id = (analysis_id_str or prompt("Entrez l'ID d'analyse VirusTotal: ")).strip()
    if not analysis_id:
        cprint("ID invalide.", C.YELLOW)
        return

    try:
        r = session.get(f"{BASE_URL}/analyses/{analysis_id}", timeout=HTTP_TIMEOUT_SEC)
    except requests.exceptions.RequestException as e:
        cprint(f"Impossible de recuperer l'analyse : {e}", C.RED)
        return

    if r.status_code == 401:
        cprint("Cle API invalide ou non autorisee.", C.RED)
        return
    if r.status_code == 403:
        cprint("Quota depasse ou acces refuse.", C.RED)
        return
    if r.status_code != 200:
        cprint(f"Impossible de recuperer l'analyse (HTTP {r.status_code}).", C.RED)
        return

    try:
        payload = r.json()
        status = payload["data"]["attributes"]["status"]
        if status != "completed":
            cprint("Analyse encore en cours.", C.YELLOW)
            return
        stats = payload["data"]["attributes"]["stats"]
        stats_norm = {
            "harmless": int(stats.get("harmless", 0)),
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "timeout": int(stats.get("timeout", 0)),
            "undetected": int(stats.get("undetected", 0)),
        }
    except (ValueError, KeyError, TypeError):
        cprint("Reponse serveur inattendue (stats).", C.RED)
        return

    cprint("\n=== Resultat analyse ===", C.CYAN)
    verdict = format_verdict(stats_norm)
    cprint(verdict.text, C.RED if verdict.is_malicious else C.GREEN)


# -----------------------------
# Menu gestion clé API (CRUD)
# -----------------------------
def api_key_management(session: requests.Session) -> None:
    cprint("\n--- Gestion de la Cle API ---", C.CYAN)
    while True:
        cprint("\n1. Ajouter/Nouvelle Cle", C.GREEN)
        cprint("2. Charger Cle Sauvegardee", C.CYAN)
        cprint("3. Tester Cle Actuelle", C.GRAY)
        cprint("4. Supprimer Cle Sauvegardee", C.YELLOW)
        cprint("0. Retour au menu principal", C.WHITE)
        print()

        choice = prompt("Choix: ")
        match choice:
            case "1":
                k = getpass.getpass("Entrez votre cle API: ").strip()
                if save_api_key(k):
                    update_headers(session, k)
                    cprint("Cle API ajoutee !", C.GREEN)
                else:
                    cprint("Impossible de sauvegarder la cle API.", C.RED)

            case "2":
                k = load_api_key()
                if k:
                    update_headers(session, k)
                    cprint("Cle API chargee !", C.GREEN)
                else:
                    cprint("Aucune cle sauvegardee detectee.", C.YELLOW)

            case "3":
                if test_api_key(session):
                    cprint("Cle valide !", C.GREEN)
                else:
                    cprint("Cle invalide !", C.RED)

            case "4":
                if delete_api_key():
                    cprint("Cle API locale supprimee", C.YELLOW)
                else:
                    cprint("Impossible de supprimer la cle API locale", C.RED)

            case "0":
                return
            case _:
                cprint("Choix invalide", C.YELLOW)


# -----------------------------
# UI: menu principal
# -----------------------------
def show_menu() -> None:
    clear_screen()
    cprint("=== VirusTotal Scanner CLI v1.2 ===", C.CYAN)
    cprint("(Edition Securisee)", C.GRAY)
    print()
    cprint("1. Scanner un fichier", C.GREEN)
    cprint("2. Scanner un dossier", C.GREEN)
    cprint("3. Scanner une URL", C.GREEN)
    cprint("4. Scanner via hash SHA256", C.GREEN)
    cprint("5. Gestion Cle API", C.YELLOW)
    cprint("6. Consulter un ID de scan existant", C.GRAY)
    cprint("0. Quitter", C.RED)
    print()


# -----------------------------
# Mode CLI optionnel (argparse)
# -----------------------------
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vt_scanner", description="VirusTotal Scanner CLI (Python)")
    sub = p.add_subparsers(dest="cmd")

    s1 = sub.add_parser("scan-file", help="Scanner un fichier (cache + upload optionnel)")
    s1.add_argument("path", type=str)
    s1.add_argument("--upload", action="store_true", help="Uploader si inconnu VT (sans confirmation)")

    s2 = sub.add_parser("scan-folder", help="Scanner un dossier (max 10 fichiers, cache only)")
    s2.add_argument("path", type=str)

    s3 = sub.add_parser("scan-url", help="Scanner une URL")
    s3.add_argument("url", type=str)

    s4 = sub.add_parser("scan-hash", help="Scanner via hash SHA256")
    s4.add_argument("sha256", type=str)

    s5 = sub.add_parser("check-analysis", help="Consulter un scan existant via analysis ID")
    s5.add_argument("analysis_id", type=str)

    s6 = sub.add_parser("api-key", help="Gérer la clé API")
    s6_sub = s6.add_subparsers(dest="api_cmd", required=True)
    s6_sub.add_parser("set", help="Entrer et sauvegarder une clé API")
    s6_sub.add_parser("test", help="Tester la clé actuelle")
    s6_sub.add_parser("delete", help="Supprimer la clé sauvegardée")

    return p


# -----------------------------
# Démarrage (équivalent PS)
# -----------------------------
def startup_session() -> Optional[requests.Session]:
    print()
    cprint("========================================================", C.CYAN)
    cprint(" VirusTotal Scanner CLI v1.2 - Edition Securisee", C.CYAN)
    cprint("========================================================", C.CYAN)
    print()

    k = load_api_key()
    if k:
        cprint("Cle API sauvegardee detectee", C.GRAY)
        cprint("Chargement automatique...", C.GRAY)
        session = build_session(k)
        if test_api_key(session):
            cprint("Cle API valide et operationnelle !", C.GREEN)
            return session
        cprint("Cle API sauvegardee invalide", C.YELLOW)
        cprint("Veuillez entrer une nouvelle cle API.", C.GRAY)

    # Saisie masquée
    k2 = getpass.getpass("Entrez votre cle API: ").strip()
    if not save_api_key(k2):
        cprint("Impossible de sauvegarder la cle API.", C.RED)
        return None

    session2 = build_session(k2)
    if not test_api_key(session2):
        cprint("Echec de validation de la cle API.", C.RED)
        return None

    cprint("Cle API sauvegardee et validee avec succes !", C.GREEN)
    return session2


def main() -> int:
    try:
        parser = build_arg_parser()
        args = parser.parse_args()

        session = startup_session()
        if session is None:
            return 1

        # Mode CLI (si subcommand)
        if args.cmd:
            match args.cmd:
                case "scan-file":
                    scan_file(session, args.path, auto_upload=bool(args.upload))
                case "scan-folder":
                    scan_folder(session, args.path)
                case "scan-url":
                    scan_url(session, args.url)
                case "scan-hash":
                    scan_hash(session, args.sha256)
                case "check-analysis":
                    check_existing_scan(session, args.analysis_id)
                case "api-key":
                    match args.api_cmd:
                        case "set":
                            k = getpass.getpass("Entrez votre cle API: ").strip()
                            if save_api_key(k):
                                update_headers(session, k)
                                cprint("Cle API ajoutee !", C.GREEN)
                            else:
                                cprint("Impossible de sauvegarder la cle API.", C.RED)
                                return 1
                        case "test":
                            return 0 if test_api_key(session) else 1
                        case "delete":
                            if delete_api_key():
                                cprint("Cle API locale supprimee", C.YELLOW)
                                return 0
                            cprint("Impossible de supprimer la cle API locale", C.RED)
                            return 1
            return 0

        # Mode interactif (par défaut)
        time.sleep(1)
        while True:
            show_menu()
            choice = prompt("Choix (0-6): ")

            match choice:
                case "1":
                    scan_file(session)
                case "2":
                    scan_folder(session)
                case "3":
                    scan_url(session)
                case "4":
                    scan_hash(session)
                case "5":
                    api_key_management(session)
                case "6":
                    check_existing_scan(session)
                case "0":
                    cprint("Au revoir !", C.CYAN)
                    return 0
                case _:
                    cprint("Choix invalide (0-6)", C.YELLOW)
                    time.sleep(2)

            if choice != "0":
                _ = prompt("Appuyez sur Entree pour continuer")

    except KeyboardInterrupt:
        print()
        cprint("Au revoir !", C.CYAN)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
