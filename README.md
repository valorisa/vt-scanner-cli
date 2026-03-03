# 🛡️ VirusTotal Scanner CLI

Scanner de fichiers, dossiers et URLs via l'API VirusTotal v3 en ligne de commande PowerShell.

## ✨ Fonctionnalités

| Option | Description |
|--------|-------------|
| **1** | Scanner un fichier (hash + upload optionnel) |
| **2** | Scanner un dossier (récursif, max 10 fichiers) |
| **3** | Scanner une URL (HTTPS recommandé) |
| **4** | Scanner via hash SHA256 |
| **5** | Configurer clé API |
| **0** | Quitter |

## 🖥️ Prérequis

- **PowerShell** 5.1+
- **Clé API VirusTotal** (gratuite)
- **Connexion Internet**

## 🚀 Utilisation

```powershell
.\vt-scanner.ps1

📄 Licence
Usage personnel et éducatif.

🔗 Liens
VirusTotal API : https://developers.virustotal.com/reference?spm=a2ty_o01.29997173.0.0.95695171LocGLs
Obtenir une clé API : https://www.virustotal.com/gui/my-apikey?spm=a2ty_o01.29997173.0.0.95695171LocGLs


---

### 3. **Vérifier le Script Final**

⚠️ **Important** : Assurez-vous que `vt-scanner.ps1` contient les corrections :

```powershell
# Vérifier qu'il n'y a pas d'espaces dans l'URL
(Get-Content vt-scanner.ps1 | Select-String "BaseUrl").Trim()

# Doit afficher : $script:BaseUrl = "https://www.virustotal.com/api/v3"
# ET NON : "https://www.virustotal.com/api/v3  "

