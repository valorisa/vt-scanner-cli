# 🛡️ VirusTotal Scanner CLI

+ ![Version](https://img.shields.io/badge/version-1.0-blue)
+ ![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blueviolet)
+ ![License](https://img.shields.io/badge/license-Personal%2FEdu-green)

Scanner de fichiers, dossiers et URLs via l'API VirusTotal v3 en ligne de commande PowerShell.

---

## 📋 Table des Matières

- [Description](#-Description)
- [Fonctionnalités](#-fonctionnalités)
- [Prérequis](#%EF%B8%8F-prérequis)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Dépannage](#-dépannage)
- [Structure du Projet](#-structure-du-projet)
- [Développement](#-développement)
- [Tests](#-tests)
- [Contribution](#-contribution)
- [Licence](#-licence)
- [Liens Utiles](#-liens-utiles)
- [Support](#-Support)

---

## 📖 Description

**VirusTotal Scanner CLI** est un outil en ligne de commande PowerShell permettant d'analyser rapidement des fichiers, dossiers et URLs via l'API VirusTotal v3. Idéal pour les administrateurs système, analystes sécurité et utilisateur-s avancés.

---

## ✨ Fonctionnalités

| Option | Description |
| ------ | ----------- |
| **1** | Scanner un fichier (vérification cache + upload si nécessaire) |
| **2** | Scanner un dossier (récursif, max 10 fichiers) |
| **3** | Scanner une URL (HTTPS recommandé) |
| **4** | Scanner via hash SHA256 (sans upload) |
| **5** | Configurer clé API |
| **0** | Quitter |

---

## 🖥️ Prérequis

| Requis | Version | Vérification |
| ------ | ------- | ------------ |
| **PowerShell** | 5.1+ | `$PSVersionTable.PSVersion` |
| **Clé API VirusTotal** | Gratuite | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| **Connexion Internet** | Requise | - |

---

## 📥 Installation

### 1. Cloner le dépôt

```powershell
git clone https://github.com/valorisa/vt-scanner-cli.git
cd vt-scanner-cli
```

### 2. Débloquer l'exécution (si nécessaire)

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
3. Copiez votre clé API

### Limites du compte gratuit

| Type | Limite | Reset |
| ---- | ------ | ----- |
| Fichiers/jour | 4 uploads | 24h |
| URLs/minute | 4 scans | 1min |
| Requêtes/minute | 60 | 1min |

---

## 🚀 Utilisation

### Lancement

```powershell
.\vt-scanner.ps1
```

### Menu Principal

```text
=== VirusTotal Scanner CLI (PS5.1+) ===
1. Scanner un fichier (hash + upload optionnel)
2. Scanner un dossier (recursif, max 10 fichiers)
3. Scanner une URL (HTTPS recommande)
4. Scanner via hash SHA256
5. Configurer cle API
0. Quitter

Choix (0-5):
```

### Exemples

#### Scanner un fichier

```text
Choix: 1
Chemin du fichier: C:\Users\bbrod\Downloads\test.exe
Hash: abc123...
=== Resultat 'test.exe' (cache VT) ===
Propre (62 analyse)
```

#### Scanner une URL

```text
Choix: 3
URL a scanner: https://example.com
Scan lance. Attente (60s)...
Resultat 'https://example.com':
Propre (89 analyse)
```

#### Scanner par hash

```text
Choix: 4
SHA256 hash: abc123def456...
Resultat hash 'abc123...':
Propre (70 analyse)
```

---

## ⚠️ Limites API

| Ressource | Quota | Recommandation |
| --------- | ----- | -------------- |
| Upload fichiers | 4/jour | Vérifier cache d'abord |
| Scan URLs | 4/min | Attendre entre scans |
| Requêtes API | 60/min | Délai automatique 16s |

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

### Vérifier la clé API

```powershell
$apiKey = "VOTRE_CLE"
$headers = @{ "x-apikey" = $apiKey }
Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/users/me" -Headers $headers
```

---

## 📁 Structure du Projet

```text
vt-scanner-cli/
├── vt-scanner.ps1      # Script principal (~200 lignes)
├── README.md           # Ce fichier
├── digest.txt          # Documentation technique
└── .git/               # Dépôt Git
```

---

## 📝 Notes Techniques

### Corrections Appliquées (v1.0)

| Problème | Solution |
| -------- | -------- |
| `Read-Host ""` vide | Prompt avec texte |
| Upload 400 | `MemoryStream` + `StreamWriter` |
| URL 400 | `$urlId = $scan.data.id` (sans split) |
| Espaces URL API | Suppression espaces dans `$BaseUrl` |

### Fonctions Principales

- `Get-ScanReport` - Récupère les stats d'analyse
- `Test-FileMalicious` - Formate le résultat
- `Scan-File` - Upload multipart
- `Scan-Url` - Encodage base64 URL
- `Scan-Folder` - Scan récursif limité

---

## 📄 Licence

Ce projet est fourni **tel quel** pour un usage **personnel et éducatif**.

---

## 🔗 Liens Utiles

| Ressource | Lien |
| --------- | ---- |
| **VirusTotal API v3** | [developers.virustotal.com](https://developers.virustotal.com/reference) |
| **Obtenir une clé API** | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| **Documentation PowerShell** | [docs.microsoft.com/powershell](https://docs.microsoft.com/powershell/) |
| **Dépôt GitHub** | [github.com/valorisa/vt-scanner-cli](https://github.com/valorisa/vt-scanner-cli) |

---

## 📞 Support

Pour toute question ou problème :

1. Consultez la section [Dépannage](#dépannage)
2. Ouvrez une issue sur [GitHub](https://github.com/valorisa/vt-scanner-cli/issues)

---

**Développé avec ❤️ par valorisa**

*Version: 1.0 | PowerShell 5.1+ | API VirusTotal v3*







