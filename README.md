# 🛡️ VirusTotal Scanner CLI

Scanner de fichiers, dossiers et URLs via l'API VirusTotal v3 en ligne de commande PowerShell.

![Version](https://img.shields.io/badge/version-1.2-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blueviolet)
![License](https://img.shields.io/badge/license-Personal%2FEdu-green)

---

## 📋 Table des Matières

- [Description](#-description)
- [Fonctionnalités](#-fonctionnalités)
- [Structure du Projet](#-structure-du-projet)
- [Prérequis](#%EF%B8%8F-prérequis)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Dépannage](#-dépannage)
- [Développement](#-développement)
- [Tests](#-tests)
- [Contribution](#-contribution)
- [Licence](#-licence)
- [Liens Utiles](#-liens-utiles)
- [Support](#-support)
- [Notes de Version](#-notes-de-version)

---

## 📖 Description

**VirusTotal Scanner CLI** est un outil en ligne de commande PowerShell permettant d'analyser rapidement des fichiers, dossiers et URLs via l'API VirusTotal v3. Idéal pour les administrateurs système, analystes sécurité et utilisateurs avancés.

**Version 1.2 - Edition Sécurisée** : Stockage chiffré de la clé API, gestion avancée des erreurs, export CSV et interface utilisateur améliorée.

---

## ✨ Fonctionnalités

| Option | Description |
| ------ | ----------- |
| **1** | Scanner un fichier (hash + upload optionnel) |
| **2** | Scanner un dossier (récursif, max 10 fichiers) + **Export CSV** |
| **3** | Scanner une URL (HTTPS recommandé) |
| **4** | Scanner via hash SHA256 |
| **5** | Gestion clé API (SecureString) |
| **6** | Consulter un scan existant |
| **0** | Quitter |

### Détails des Fonctionnalités

#### 🔐 Sécurité (v1.2)
- **SecureString** : Clé API chiffrée et stockée localement
- **Persistance automatique** : Chargement de la clé au démarrage
- **Test-ApiKey** : Validation automatique au lancement
- **Suppression sécurisée** : Option pour effacer la clé sauvegardée

#### 📊 Analyse (v1.1 + v1.2)
- **Cache VirusTotal** : Vérification automatique avant upload (économie de quota)
- **Upload Multipart** : Support des fichiers jusqu'à 650 MB
- **Polling Intelligent** : Attente automatique des résultats d'analyse (max 5 min)
- **Rapports Détaillés** : Affichage des détections par moteur antivirus
- **Export CSV** : Génération de rapports traçables avec timestamp
- **Barre de Progression** : Visibilité pendant le scan de dossiers
- **Gestion d'Erreurs Robuste** : Try/Catch dans toutes les fonctions de scan
- **Détection Quota 403** : Arrêt propre en cas de limite API dépassée

#### 🎯 Validation (v1.2)
- **Trim() URLs** : Suppression automatique des espaces dans les URLs
- **Validation Hash** : Vérification des 64 caractères hexadécimaux
- **Validation Schéma** : Contrôle HTTP/HTTPS obligatoire
- **BaseUrl Protégée** : `.Trim()` pour éviter les erreurs 400

---

## 📁 Structure du Projet

```text
vt-scanner-cli/
├── README.md           # Ce fichier
├── backup_README.md    # Sauvegarde du README.md
├── CHANGELOG.md        # Historique des versions
├── ROADMAP.md          # Feuille de route future
├── SECURITY.md         # Politique de sécurité
├── vt-scanner.ps1      # Script principal (~667 lignes)
├── digest.txt          # Documentation technique (gitingest)
├── .git/               # Dépôt Git
├── .gitignore          # Fichiers ignorés
└── .markdownlint.json  # Configuration markdownlint
```

---

## 🖥️ Prérequis

| Requis | Version | Vérification |
| ------ | ------- | ------------ |
| **PowerShell** | 5.1+ | `$PSVersionTable.PSVersion` |
| **Clé API VirusTotal** | Gratuite | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| **Connexion Internet** | Requise | - |
| **Git** (optionnel) | 2.x+ | `git --version` |

---

## 📥 Installation

### Méthode 1 : Cloner le dépôt (Recommandé)

```powershell
# Sous PowerShell 5.1+
git clone https://github.com/valorisa/vt-scanner-cli.git
cd vt-scanner-cli
```

### Méthode 2 : Téléchargement manuel

1. Téléchargez `vt-scanner.ps1` depuis GitHub
2. Placez-le dans un dossier de votre choix
3. Ouvrez PowerShell dans ce dossier

### Débloquer l'exécution

```powershell
# Débloquer le script (une seule fois)
Unblock-File -Path ".\vt-scanner.ps1"

# Ou autoriser l'exécution des scripts
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 🔑 Configuration

### Obtenir une clé API

1. Rendez-vous sur [https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
2. Connectez-vous ou créez un compte gratuit
3. Copiez votre clé API (48 caractères)

### Limites du compte gratuit

| Type | Limite | Reset |
| ---- | ------ | ----- |
| Fichiers/jour | 4 uploads | 24h |
| URLs/minute | 4 scans | 1min |
| Requêtes/minute | 60 | 1min |

### Vérifier sa clé API

```powershell
# Sous PowerShell 5.1+
$apiKey = "VOTRE_CLE_API"
$headers = @{ "x-apikey" = $apiKey }
Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/users/me" -Headers $headers
```

---

## 🚀 Usage

### Lancement

```powershell
# Sous PowerShell 5.1+
.\vt-scanner.ps1
```

### Menu Principal

```text
========================================================
    VirusTotal Scanner CLI v1.2 - Edition Securisee
========================================================

Cle API sauvegardee detectee
Chargement automatique...
Cle API valide et operationnelle !

=== VirusTotal Scanner CLI v1.2 ===
(Edition Securisee)

1. Scanner un fichier
2. Scanner un dossier
3. Scanner une URL
4. Scanner via hash SHA256
5. Gestion Cle API
6. Consulter un ID de scan existant
0. Quitter

Choix (0-6):
```

### Exemples d'Utilisation

#### Scanner un fichier

```text
Choix: 1
Chemin du fichier: C:\Users\bbrod\Downloads\test.exe
Hash: abc123...
=== Resultat 'test.exe' (cache VT) ===
Propre (62 analyses)
```

#### Scanner un dossier (avec export CSV)

```text
Choix: 2
Chemin du dossier: C:\Users\bbrod\Downloads
[ATTENTION] Scan limité aux 10 premiers fichiers (Quota API gratuit).
Début du scan de 10 fichiers...
  [+] fichier1.exe: Propre (62 analyses)
  [-] fichier2.dll: 2/62 detections malveillantes

--- Résumé du scan ---
FileName     Status              Detections
--------     ------              ----------
fichier1.exe Propre (62 analyses) 0
fichier2.dll 2/62 detections...  2

Souhaitez-vous exporter ces résultats en CSV ?
Tapez 'o' pour exporter (Entrée pour ignorer): o
[OK] Rapport exporte : vt_scan_report_20260308_171600.csv
```

#### Scanner une URL

```text
Choix: 3
URL a scanner: https://www.google.com
URL validee : https://www.google.com
ID Scan: u-xxxxx...
Scan lance. Attente des resultats (max 5 min)...
........
Resultat 'https://www.google.com':
Propre (89 analyses)
```

#### Scanner par hash

```text
Choix: 4
SHA256 hash: abc123def456...
Resultat hash 'abc123...':
Propre (70 analyses)
```

#### Gestion de la clé API (v1.2)

```text
Choix: 5

--- Gestion de la Cle API ---

1. Ajouter/Nouvelle Cle
2. Charger Cle Sauvegardee
3. Tester Cle Actuelle
4. Supprimer Cle Sauvegardee
0. Retour au menu principal

Choix: 3
Cle API valide et operationnelle !
```

#### Consulter un scan existant (v1.2)

```text
Choix: 6

--- Consulter un scan existant ---
Entrez l'ID d'analyse VirusTotal: xxxxx...
Recuperation de l'analyse...
=== Resultat analyse ===
Propre (75 analyses)
```

---

## 🔧 Dépannage

### Erreur 400 Bad Request

| Cause | Solution |
| ----- | -------- |
| Espaces dans l'URL API | Vérifier `$script:BaseUrl` sans espaces |
| Clé API invalide | Régénérer sur virustotal.com |
| Quota dépassé | Attendre 24h (fichiers) ou 1min (URLs) |

### Erreur Read-Host

| Cause | Solution |
| ----- | -------- |
| Prompt vide | Utiliser `Read-Host "texte"` (pas `""`) |

### Upload échoue

| Cause | Solution |
| ----- | -------- |
| Fichier trop volumineux | Max 650 MB (API VT) |
| Multipart mal formé | Utiliser `MemoryStream` + `StreamWriter` |

### ⚠️ Gitingest Aborted - Problème d'Encodage

**Problème :** Lors de l'exécution de `gitingest`, l'erreur suivante peut se produire :

```text
Error: 'utf-8' codec can't decode byte 0xe9 in position 124: invalid continuation byte
Aborted!
```

**Cause :** Un ou plusieurs fichiers du dépôt ne sont **pas encodés en UTF-8 sans BOM**. Les caractères accentués français (é, è, ê, à, etc.) sont mal interprétés.

**Solution :**

1. **Ouvrir chaque fichier texte dans Notepad++** :
   - `vt-scanner.ps1`
   - `README.md`
   - `CHANGELOG.md`
   - `ROADMAP.md`
   - `SECURITY.md`
   - `.markdownlint.json`

2. **Menu Encodage** → **Convertir en UTF-8** (⚠️ **PAS** "UTF-8-BOM")

3. **Vérifier en bas de Notepad++** : doit afficher `UTF-8` (sans "-BOM")

4. **Sauvegarder** avec `Ctrl+S`

5. **Relancer gitingest** :
   ```powershell
   gitingest
   ```

**Commande PowerShell pour vérifier l'encodage :**

```powershell
# Vérifier si un fichier est en UTF-8 sans BOM
$bytes = [System.IO.File]::ReadAllBytes(".\vt-scanner.ps1")
if ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    Write-Host "❌ Fichier avec BOM détecté - À corriger !" -ForegroundColor Red
} else {
    Write-Host "✅ Fichier UTF-8 sans BOM - OK" -ForegroundColor Green
}
```

**Fichiers concernés par l'encodage UTF-8 sans BOM :**

| Fichier | Critique |
| ------- | -------- |
| `vt-scanner.ps1` | ✅ Oui (caractères français) |
| `README.md` | ✅ Oui (caractères français) |
| `CHANGELOG.md` | ✅ Oui (caractères français) |
| `ROADMAP.md` | ✅ Oui (caractères français) |
| `SECURITY.md` | ✅ Oui (caractères français) |
| `.markdownlint.json` | ✅ Oui (JSON standard) |
| `.gitignore` | ⚠️ Recommandé |

### Le script ne se lance pas

```powershell
# Vérifier la version PowerShell
$PSVersionTable.PSVersion

# Débloquer le script
Unblock-File -Path ".\vt-scanner.ps1"

# Changer la politique d'exécution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Git Credential Manager - Warnings "multiple values"

**Problème :** Éventuels messages d'erreur lors des commandes Git (push) :

```text
warning: credential.helper has multiple values
'C:\Program Files\GitHub CLI\gh.exe' auth git-credential get: line 1: command not found
'C:\Program Files\GitHub CLI\gh.exe' auth git-credential store: line 1: command not found
```

**Cause :** Plusieurs valeurs sont configurées pour `credential.helper` dans Git (niveau système + global).

---

#### Solution complète

##### 1. PowerShell NORMAL (sans droits administrateur)

```powershell
# Diagnostic initial
git config --get-all credential.helper
# Si plusieurs valeurs s'affichent → problème confirmé

# Nettoyer les entrées gist.github.com (cause des erreurs gh.exe)
git config --global --unset-all credential.https://gist.github.com.helper

# Vérifier le nettoyage global
git config --global --list | Select-String "credential"
# Doit afficher uniquement : credential.helper=manager
```

##### 2. PowerShell ADMINISTRATEUR (droits requis)

> ⚠️ **Comment ouvrir PowerShell en Administrateur :**
> - Menu Démarrer → Chercher "PowerShell" → Clic droit → **"Exécuter en tant qu'administrateur"**
> - Ou raccourci : `Win + X` → "Windows PowerShell (admin)" / "Terminal (admin)"

```powershell
# Supprimer TOUTES les entrées credential.helper au niveau système
git config --system --unset-all credential.helper

# (Optionnel) Supprimer l'entrée Azure DevOps si tu ne l'utilises pas
git config --system --unset credential.https://dev.azure.com.usehttppath

# Vérifier ce qui reste au niveau système
git config --system --list | Select-String "credential"
# Doit afficher uniquement (si Azure gardé) :
# credential.https://dev.azure.com.usehttppath = true
# OU rien du tout (si Azure supprimé)
```

##### 3. PowerShell NORMAL (vérification finale)

```powershell
# Revenir dans ton projet
cd C:\Users\bbrod\Projets\vt-scanner-cli

# Vérifier qu'il ne reste qu'UNE SEULE valeur pour credential.helper
git config --get-all credential.helper
# ✅ RÉSULTAT ATTENDU : manager (une seule ligne)

# Tester un push (ne doit plus afficher de warning)
git push origin main
# ✅ RÉSULTAT ATTENDU : Everything up-to-date (sans warning)

# Tester un pull
git pull
# ✅ RÉSULTAT ATTENDU : Already up to date. (sans warning)
```

---

#### Tableau récapitulatif des commandes

| Commande | Mode | Objectif |
| -------- | ---- | -------- |
| `git config --get-all credential.helper` | 👤 Normal | Diagnostiquer le problème |
| `git config --list --show-origin --show-scope` | 👤 Normal | Voir toutes les configs par niveau |
| `git config --global --unset-all credential.https://gist.github.com.helper` | 👤 Normal | Supprimer entrées gist.github.com |
| `git config --system --unset-all credential.helper` | 🔒 **Admin** | **Supprimer doublons système** |
| `git config --system --unset credential.https://dev.azure.com.usehttppath` | 🔒 **Admin** | Optionnel : supprimer entrée Azure |
| `git push origin main` | 👤 Normal | Tester que tout fonctionne |
| `git pull` | 👤 Normal | Tester que tout fonctionne |

---

#### Résultats attendus après résolution

| Avant | Après |
| ----- | ----- |
| ⚠️ `warning: credential.helper has multiple values` | ✅ Plus aucun warning |
| ❌ `'C:\Program Files\GitHub CLI\gh.exe' ... command not found` | ✅ Plus aucune erreur gh.exe |
| ⚠️ 2-3 valeurs pour `credential.helper` | ✅ 1 seule valeur (`manager`) |
| ✅ `git push` fonctionnel (avec warnings) | ✅ `git push` fonctionnel (propre) |

---

#### Notes importantes

| Point | Détail |
| ----- | ------ |
| **Fichier modifié (Admin)** | `C:\Program Files (x86)\Git\etc\gitconfig` |
| **Fichier modifié (Normal)** | `C:\Users\<ton_user>\.gitconfig` |
| **Pourquoi Admin ?** | Le dossier `Program Files (x86)` nécessite des droits élevés |
| **Impact sur autres projets** | Aucun, la config globale `manager` reste active |
| **Réversible ?** | Oui, réinstaller GCM ou éditer manuellement les fichiers |

---

**Résultat :** Plus aucun warning, authentification Git fonctionne correctement ✅

---

### Vérification Rapide de l'Encodage des Fichiers
Pour éviter les futurs problèmes d'encodage, exécutez ce script pour vérifier tous les fichiers texte :

```powershell
# Sous PowerShell 5.1+
cd C:\Users\bbrod\Projets\vt-scanner-cli

$files = @("vt-scanner.ps1", "README.md", "CHANGELOG.md", "ROADMAP.md", "SECURITY.md", ".gitattributes", ".markdownlint.json")

Write-Host "`n=== Vérification encodage UTF-8 sans BOM ===" -ForegroundColor Cyan
foreach ($file in $files) {
    if (Test-Path $file) {
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $PWD $file))
        if ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            Write-Host "❌ $file : BOM détecté" -ForegroundColor Red
        } else {
            Write-Host "✅ $file : UTF-8 sans BOM" -ForegroundColor Green
        }
    }
}
```

---

## 💻 Développement

### Architecture du Script (v1.2)

| Fonction | Description | Version |
| -------- | ----------- | ------- |
| `Save-ApiKey` | Sauvegarde chiffrée de la clé API | v1.2 |
| `Load-ApiKey` | Chargement de la clé chiffrée | v1.2 |
| `ConvertFrom-Secure` | Conversion SecureString → texte clair | v1.2 |
| `Update-Headers` | Configure les en-têtes API | v1.0 |
| `Test-ApiKey` | Validation de la clé API | v1.2 |
| `Delete-ApiKey` | Suppression de la clé sauvegardée | v1.2 |
| `Show-Menu` | Affiche le menu principal | v1.0 |
| `Get-ScanReport` | Récupère les stats d'analyse | v1.0 |
| `Wait-VTAnalysis` | Polling avec timeout configurable | v1.2 |
| `Test-FileMalicious` | Formate le résultat | v1.0 |
| `Scan-File` | Upload multipart + polling | v1.0 |
| `Scan-Folder` | Scan récursif + export CSV | v1.1 |
| `Scan-Url` | Scan URL avec validation | v1.0 |
| `Scan-Hash` | Recherche par hash seul | v1.0 |
| `Export-ScanResults` | Export des résultats en CSV | v1.1 |
| `ApiKeyManagement` | Sous-menu gestion clé API | v1.2 |
| `Check-ExistingScan` | Consulter un scan existant | v1.2 |

**Total :** ~667 lignes (vs ~200 pour v1.0, ~370 pour v1.1)

### Corrections Appliquées (v1.0 → v1.2)

| Problème | Solution | Version |
| -------- | -------- | ------- |
| `Read-Host ""` vide | Prompt avec texte | v1.0 |
| Upload 400 | `MemoryStream` + `StreamWriter` | v1.0 |
| URL 400 | `$urlId = $scan.data.id` (sans split) | v1.0 |
| Espaces URL API | Suppression espaces dans `$BaseUrl` | v1.1 |
| Pas d'export CSV | Ajout `Export-ScanResults` | v1.1 |
| Scan-Folder fragile | Try/Catch + gestion 403 | v1.1 |
| Pas de progression | Ajout `Write-Progress` | v1.1 |
| Clé API en clair | SecureString + chiffrement | v1.2 |
| Pas de validation API | Ajout `Test-ApiKey` | v1.2 |
| Encodage fichiers | UTF-8 sans BOM | v1.2 |

---

## 🧪 Tests

### Test de connexion API

```powershell
# Sous PowerShell 5.1+
$apiKey = "VOTRE_CLE_API"
$headers = @{ "x-apikey" = $apiKey }
Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/users/me" -Headers $headers
```

### Test de scan fichier

```powershell
# Créer un fichier test
"test" | Out-File -FilePath test.txt

# Scanner avec l'option 1
.\vt-scanner.ps1
Choix: 1
Chemin: C:\chemin\vers\test.txt
```

### Test de scan dossier + export CSV

```powershell
# Sous PowerShell 5.1+
.\vt-scanner.ps1
Choix: 2
Chemin: C:\chemin\vers\dossier
# À la fin, taper 'o' pour exporter le CSV
```

### Test de scan URL

```powershell
# Sous PowerShell 5.1+
.\vt-scanner.ps1
Choix: 3
URL: https://example.com
```

### Test de validation d'encodage

```powershell
# Vérifier que tous les fichiers sont en UTF-8 sans BOM
$files = @("vt-scanner.ps1", "README.md", "CHANGELOG.md", "ROADMAP.md", "SECURITY.md")
foreach ($file in $files) {
    $bytes = [System.IO.File]::ReadAllBytes(".\$file")
    if ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Write-Host "❌ $file : BOM détecté" -ForegroundColor Red
    } else {
        Write-Host "✅ $file : UTF-8 sans BOM" -ForegroundColor Green
    }
}
```

---

## 🤝 Contribution

### Comment Contribuer

1. Forkez le dépôt
2. Créez une branche (`feature/nouvelle-fonction`)
3. Committez les changements (`git commit -m 'Ajout fonctionnalité'`)
4. Pushez vers la branche (`git push origin feature/nouvelle-fonction`)
5. Ouvrez une Pull Request

### Bonnes Pratiques

- ✅ Tester toutes les options avant commit
- ✅ Garder la compatibilité PowerShell 5.1+
- ✅ Documenter les nouvelles fonctions
- ✅ Respecter les limites API VirusTotal
- ✅ **Encoder tous les fichiers en UTF-8 sans BOM** (critique pour gitingest)
- ✅ Vérifier l'encodage avec Notepad++ avant commit

---

## 📄 Licence

Ce projet est fourni **tel quel** pour un usage **personnel et éducatif**.

| Usage | Autorisé |
| ----- | -------- |
| Personnel | ✅ Oui |
| Éducatif | ✅ Oui |
| Commercial | ❌ Non |
| Redistribution | ⚠️ Avec crédit |

---

## 🔗 Liens Utiles

| Ressource | Lien |
| --------- | ---- |
| **VirusTotal API v3** | [developers.virustotal.com](https://developers.virustotal.com/reference) |
| **Obtenir une clé API** | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| **Documentation PowerShell** | [docs.microsoft.com/powershell](https://docs.microsoft.com/powershell/) |
| **Dépôt GitHub** | [github.com/valorisa/vt-scanner-cli](https://github.com/valorisa/vt-scanner-cli) |
| **Gitingest** | [gitingest.com](https://gitingest.com) |

---

## 📞 Support

Pour toute question ou problème :

1. Consultez la section [Dépannage](#-dépannage)
2. Ouvrez une issue sur [GitHub](https://github.com/valorisa/vt-scanner-cli/issues)
3. Vérifiez votre quota API sur [VirusTotal](https://www.virustotal.com/gui/my-apikey)
4. Vérifiez l'encodage de vos fichiers (UTF-8 sans BOM)

---

**Développé avec pertinacité par valorisa**

*Version: 1.2 Secure Edition | PowerShell 5.1+ | API VirusTotal v3*

---

## 📝 Notes de Version

### v1.2 (Version Actuelle) - 08 mars 2026

#### 🔐 Nouvelles Fonctionnalités
- ✅ **SecureString** : Clé API chiffrée avec `Export-Clixml`
- ✅ **Persistance automatique** : Fichier `.vtapikey.secure` dans `%USERPROFILE%`
- ✅ **Test-ApiKey** : Validation automatique au démarrage
- ✅ **Delete-ApiKey** : Suppression sécurisée de la clé
- ✅ **ApiKeyManagement** : Sous-menu de gestion (options 5.1-5.3)
- ✅ **Check-ExistingScan** : Consulter un scan par ID (option 6)
- ✅ **Wait-VTAnalysis** : Timeout configurable (max 5 min)
- ✅ **Validation renforcée** : Hash 64 caractères, schéma HTTP/HTTPS

#### 🐛 Corrections
- ✅ **Encodage UTF-8 sans BOM** : Tous les fichiers convertis
- ✅ **BaseUrl .Trim()** : Protection contre les espaces accidentels
- ✅ **Test-ApiKey Response** : Vérification `[System.Net.WebException]` avant accès
- ✅ **gitingest aborted** : Résolu avec encodage UTF-8 correct

#### 📊 Statistiques
- **Lignes de code** : ~667 (vs ~370 en v1.1)
- **Fonctions** : 17 (vs 9 en v1.1)
- **Fichiers documentés** : 7 (tous en UTF-8 sans BOM)

### v1.1 (Version Précédente) - 06 mars 2026

- ✅ **NOUVEAU** : Export CSV des résultats de scan (option 2)
- ✅ **NOUVEAU** : Barre de progression pendant le scan de dossiers
- ✅ **NOUVEAU** : Détection explicite du quota API (erreur 403)
- ✅ **NOUVEAU** : Try/Catch robuste dans la boucle de scan
- ✅ **CORRECTION** : Espaces supprimés dans `$script:BaseUrl` (erreur 400)
- ✅ **CORRECTION** : Trim() sur les URLs utilisateur
- ✅ **CORRECTION** : Nettoyage contenu markdownlint.json du script

### v1.0 (Version Initiale) - 05 mars 2026

- ✅ Scanner de fichiers avec cache VT
- ✅ Upload multipart corrigé
- ✅ Scan d'URLs fonctionnel
- ✅ Scan par hash SHA256
- ✅ Scan de dossiers (max 10 fichiers)
- ✅ Gestion des erreurs améliorée
- ✅ Compatible PowerShell 5.1+

---

*README généré pour vt-scanner-cli - Dernière mise à jour : le 08 mars 2026*

---

## 📊 Résumé des Modifications par Version

| Élément | v1.0 | v1.1 | v1.2 |
| ------- | ---- | ---- | ---- |
| **Badge Version** | `1.0-blue` | `1.1-blue` | `1.2-blue` |
| **Lignes de code** | ~200 | ~370 | **~667** |
| **Fonctions** | 8 | 9 | **17** |
| **Export CSV** | ❌ | ✅ | ✅ |
| **Barre progression** | ❌ | ✅ | ✅ |
| **Détection quota 403** | ❌ | ✅ | ✅ |
| **SecureString API** | ❌ | ❌ | **✅** |
| **Persistance clé** | ❌ | ❌ | **✅** |
| **Test-ApiKey** | ❌ | ❌ | **✅** |
| **Check-ExistingScan** | ❌ | ❌ | **✅** |
| **Encodage UTF-8** | ⚠️ | ⚠️ | **✅** |
| **Notes de version** | v1.0 | v1.0 + v1.1 | **v1.0 + v1.1 + v1.2** |

---

## 📋 Instructions pour Appliquer

1. **Ouvrir Notepad++**
2. **Copier-coller** tout le contenu ci-dessus
3. **Menu Encodage** → **Convertir en UTF-8** (⚠️ **PAS** "UTF-8-BOM")
4. **Sauvegarder** sous `README.md` dans `C:\Users\bbrod\Projets\vt-scanner-cli\`
5. **Vérifier** en bas de Notepad++ : doit afficher `UTF-8` (sans BOM)

---

## ✅ Points Clés Ajoutés

| Section | Contenu |
| ------- | ------- |
| **Version badge** | Mis à jour `1.2-blue` |
| **Fonctionnalités** | Ajout options 5 (Gestion API) et 6 (Scan existant) |
| **Architecture** | 17 fonctions documentées avec version |
| **Dépannage** | Section complète sur gitingest + UTF-8 |
| **Tests** | Script de validation d'encodage ajouté |
| **Notes de version** | v1.2 détaillée avec statistiques |
| **Tableau comparatif** | v1.0 → v1.1 → v1.2 |
| **Bonnes pratiques** | Encodage UTF-8 sans BOM mentionné |

---

**Votre README.md est maintenant complet et à jour avec la version 1.2 !** 🚀
