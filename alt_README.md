# 🛡️ VirusTotal Scanner CLI

Scanner de fichiers, dossiers et URLs via l'API VirusTotal v3 en ligne de commande PowerShell.

![Version](https://img.shields.io/badge/version-1.0-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blueviolet)
![License](https://img.shields.io/badge/license-Personal%2FEdu-green)

---

## 📋 Table des Matières

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
- [Support](#-Support)
- [Notes de Version](#-Notes-de-Version)

---

## ✨ Fonctionnalités

| Option | Description |
| ------ | ----------- |
| **1** | Scanner un fichier (hash + upload optionnel) |
| **2** | Scanner un dossier (récursif, max 10 fichiers) |
| **3** | Scanner une URL (HTTPS recommandé) |
| **4** | Scanner via hash SHA256 |
| **5** | Configurer clé API |
| **0** | Quitter |

### Détails des Fonctionnalités

- **Cache VirusTotal** : Vérification automatique avant upload (économie de quota)
- **Upload Multipart** : Support des fichiers jusqu'à 650 MB
- **Polling Intelligent** : Attente automatique des résultats d'analyse
- **Rapports Détaillés** : Affichage des détections par moteur antivirus

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
$apiKey = "VOTRE_CLE"
$headers = @{ "x-apikey" = $apiKey }
Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/users/me" -Headers $headers
```

---

## 🚀 Usage

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

### Exemples d'Utilisation

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

#### Scanner un dossier

```text
Choix: 2
Chemin du dossier: C:\Users\bbrod\Downloads
Scan 10 fichiers...
  fichier1.exe: Propre (62 analyse)
  fichier2.dll: 2/62 detections malveillantes
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

### Le script ne se lance pas

```powershell
# Vérifier la version PowerShell
$PSVersionTable.PSVersion

# Débloquer le script
Unblock-File -Path ".\vt-scanner.ps1"

# Changer la politique d'exécution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## 💻 Développement

### Architecture du Script

| Fonction | Description |
| -------- | ----------- |
| `Update-Headers` | Configure les en-têtes API |
| `Show-Menu` | Affiche le menu principal |
| `Get-ScanReport` | Récupère les stats d'analyse |
| `Test-FileMalicious` | Formate le résultat |
| `Scan-File` | Upload multipart + polling |
| `Scan-Folder` | Scan récursif limité |
| `Scan-Url` | Encodage base64 URL |
| `Scan-Hash` | Recherche par hash seul |

### Corrections Appliquées (v1.0)

| Problème | Solution |
| -------- | -------- |
| `Read-Host ""` vide | Prompt avec texte |
| Upload 400 | `MemoryStream` + `StreamWriter` |
| URL 400 | `$urlId = $scan.data.id` (sans split) |
| Espaces URL API | Suppression espaces dans `$BaseUrl` |

---

## 🧪 Tests

### Test de connexion API

```powershell
$apiKey = "VOTRE_CLE"
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

### Test de scan URL

```powershell
.\vt-scanner.ps1
Choix: 3
URL: https://example.com
```

---

## 🤝 Contribution

### Comment Contribuer

1. Fork le dépôt
2. Créez une branche (`feature/nouvelle-fonction`)
3. Committez les changements (`git commit -m 'Ajout fonctionnalité'`)
4. Push vers la branche (`git push origin feature/nouvelle-fonction`)
5. Ouvrez une Pull Request

### Bonnes Pratiques

- Tester toutes les options avant commit
- Garder la compatibilité PowerShell 5.1+
- Documenter les nouvelles fonctions
- Respecter les limites API VirusTotal

---

## 📄 Licence

Ce projet est fourni **tel quel** pour un usage **personnel et éducatif**.

| Usage | Autorisé |
|-------|----------|
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

---

## 📞 Support

Pour toute question ou problème :

1. Consultez la section [Dépannage](#-dépannage)
2. Ouvrez une issue sur [GitHub](https://github.com/valorisa/vt-scanner-cli/issues)
3. Vérifiez votre quota API sur [VirusTotal](https://www.virustotal.com/gui/my-apikey)

---

**Développé avec ❤️ par valorisa**

*Version: 1.0 | PowerShell 5.1+ | API VirusTotal v3*

---

## 📝 Notes de Version

### v1.0 (Version Actuelle)

- ✅ Scanner de fichiers avec cache VT
- ✅ Upload multipart corrigé
- ✅ Scan d'URLs fonctionnel
- ✅ Scan par hash SHA256
- ✅ Scan de dossiers (max 10 fichiers)
- ✅ Gestion des erreurs améliorée
- ✅ Compatible PowerShell 5.1+

---

*README généré pour vt-scanner-cli - Dernière mise à jour: le 03 mars 2026*
