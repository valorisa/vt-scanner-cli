# ============================================================================
# VirusTotal Scanner CLI - VERSION 1.2 (PS5.1+ Secure Edition)
# ============================================================================
# Usage: .\vt-scanner.ps1
# Nouvelles fonctionnalités : SecureString + Export CSV + Gestion d'erreurs
# ============================================================================

param([string]$ApiKey = $null)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
# CONFIGURATION CENTRALE
# ============================================================================

$script:BaseUrl = "https://www.virustotal.com/api/v3".Trim()
$script:Headers = $null
$script:DelayBetweenRequests = 16
$script:ApiKeyFile = "$env:USERPROFILE\.vtapikey.secure"

# ============================================================================
# GESTION SECURISEE DE LA CLE API
# ============================================================================

function Save-ApiKey {
    [CmdletBinding()]
    param([SecureString]$SecureKey)
    try {
        $SecureKey | Export-Clixml -Path $script:ApiKeyFile -Force
        Write-Verbose "Cle API sauvegardee de maniere securisee."
        return $true
    }
    catch {
        Write-Warning "Impossible de sauvegarder la cle API : $($_.Exception.Message)"
        return $false
    }
}

function Load-ApiKey {
    [CmdletBinding()]
    param()
    if (Test-Path $script:ApiKeyFile) {
        try {
            return Import-Clixml -Path $script:ApiKeyFile
        }
        catch {
            Write-Warning "Impossible de charger la cle API."
            return $null
        }
    }
    else {
        return $null
    }
}

function ConvertFrom-Secure {
    [CmdletBinding()]
    param([SecureString]$Secure)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Update-Headers {
    [CmdletBinding()]
    param([string]$Key)
    
    # .Trim() supprime tous les espaces et retours à la ligne inutiles
    $cleanKey = $Key.Trim() 
    
    $script:Headers = @{
        "x-apikey" = $cleanKey
        "Accept" = "application/json"
        "User-Agent" = "VT-Scanner-CLI/1.2"
    }
}

function Test-ApiKey {
    [CmdletBinding()]
    param()
    try {
        $response = Invoke-RestMethod `
            -Uri "$script:BaseUrl/users/me" `
            -Headers $script:Headers `
            -Method Get `
            -TimeoutSec 30 `
            -ErrorAction Stop
        Write-Verbose "Cle API valide et API accessible"
        return $true
    }
    catch {
        $exception = $_.Exception
        if ($exception -is [System.Net.WebException] -and $exception.Response) {
            $httpResponse = $exception.Response
            if ($httpResponse.StatusCode -eq 401) {
                Write-Error "Cle API invalide ou non autorisee."
            }
            elseif ($httpResponse.StatusCode -eq 403) {
                Write-Error "Quota depasse ou acces refuse."
            }
            else {
                Write-Error "Erreur HTTP $($httpResponse.StatusCode) : $($exception.Message)"
            }
        }
        else {
            Write-Error "Erreur de connexion : $($exception.Message)"
        }
        return $false
    }
}

function Delete-ApiKey {
    [CmdletBinding()]
    param()
    if (Test-Path $script:ApiKeyFile) {
        try {
            Remove-Item $script:ApiKeyFile -Force
            Write-Host "Cle API locale supprimee" -ForegroundColor Yellow
            return $true
        }
        catch {
            Write-Warning "Impossible de supprimer la cle API locale"
            return $false
        }
    }
    return $true
}

# ============================================================================
# INTERFACE UTILISATEUR
# ============================================================================

function Show-Menu {
    [CmdletBinding()]
    param()
    Clear-Host
    Write-Host "=== VirusTotal Scanner CLI v1.2 ===" -ForegroundColor Cyan
    Write-Host "(Edition Securisee)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "1. Scanner un fichier" -ForegroundColor Green
    Write-Host "2. Scanner un dossier" -ForegroundColor Green
    Write-Host "3. Scanner une URL" -ForegroundColor Green
    Write-Host "4. Scanner via hash SHA256" -ForegroundColor Green
    Write-Host "5. Gestion Cle API" -ForegroundColor Yellow
    Write-Host "6. Consulter un ID de scan existant" -ForegroundColor Gray
    Write-Host "0. Quitter" -ForegroundColor Red
    Write-Host ""
}

# ============================================================================
# FONCTIONS API VIRUSTOTAL
# ============================================================================

function Get-ScanReport {
    [CmdletBinding()]
    param([string]$ResourceId, [string]$Type = "files")
    try {
        $uri = if ($Type -eq "urls") {
            "$script:BaseUrl/urls/$ResourceId"
        }
        else {
            "$script:BaseUrl/files/$ResourceId"
        }
        $response = Invoke-RestMethod `
            -Uri $uri `
            -Headers $script:Headers `
            -Method Get `
            -TimeoutSec 30 `
            -ErrorAction Stop
        return $response.data.attributes.last_analysis_stats
    }
    catch {
        Write-Verbose "Analyse non disponible."
        return $null
    }
}

function Wait-VTAnalysis {
    [CmdletBinding()]
    param([string]$Id, [string]$Type, [int]$TimeoutMinutes = 4)
    $timeout = (Get-Date).AddMinutes($TimeoutMinutes)
    $attempt = 0
    while ((Get-Date) -lt $timeout) {
        $attempt++
        Start-Sleep 15
        Write-Host "." -NoNewline -ForegroundColor Gray
        $stats = Get-ScanReport $Id $Type
        if ($stats) {
            Write-Host ""
            return $stats
        }
    }
    Write-Host ""
    return $null
}

function Test-FileMalicious {
    [CmdletBinding()]
    param($Stats)
    if (-not $Stats) { return "Indisponible" }
    $total = $Stats.harmless + $Stats.malicious + $Stats.suspicious + $Stats.timeout + $Stats.undetected
    if ($Stats.malicious -eq 0) { return "Propre ($total analyses)" }
    return "$($Stats.malicious)/$total detections malveillantes"
}

# ============================================================================
# EXPORT CSV (v1.1)
# ============================================================================

function Export-ScanResults {
    [CmdletBinding()]
    param([Array]$Results, [string]$PathScanned)
    if (-not $Results -or $Results.Count -eq 0) {
        Write-Warning "Aucun resultat a exporter."
        return
    }
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fileName = "vt_scan_report_$timestamp.csv"
    $exportData = $Results | Select-Object *,
        @{Name="ScanDate"; Expression={Get-Date -Format "yyyy-MM-dd HH:mm:ss"}},
        @{Name="SourcePath"; Expression={$PathScanned}}
    try {
        $exportData | Export-Csv -Path $fileName -Encoding UTF8 -NoTypeInformation -UseCulture
        Write-Host "[OK] Rapport exporte : $fileName" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Echec de l'export CSV : $($_.Exception.Message)"
        return $false
    }
}

# ============================================================================
# FONCTIONS DE SCAN
# ============================================================================

function Scan-File {
    [CmdletBinding()]
    param()
    $filePath = (Read-Host "Chemin du fichier").Trim()
    if (-not (Test-Path $filePath)) {
        Write-Error "Fichier introuvable : $filePath"
        return
    }
    $fileInfo = Get-Item $filePath
    if ($fileInfo.Length -gt 650MB) {
        Write-Error "Fichier trop volumineux (>650MB - limite API VT)"
        return
    }
    try {
        $sha256 = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToLower()
    }
    catch {
        Write-Error "Impossible de calculer le hash SHA256."
        return
    }
    Write-Host "Hash: $sha256" -ForegroundColor Cyan
    $stats = Get-ScanReport $sha256
    if ($stats) {
        $filename = Split-Path $filePath -Leaf
        Write-Host "`n=== Resultat '$filename' (cache VT) ===" -ForegroundColor Cyan
        Write-Host (Test-FileMalicious $stats) -ForegroundColor $(if($stats.malicious -gt 0){'Red'}else{'Green'})
        return
    }
    Write-Host "`nFichier inconnu VT. Upload requis." -ForegroundColor Yellow
    Write-Host "Consomme 1 quota (4/min). Continuer ? (o/N)" -ForegroundColor Red
    $confirm = Read-Host "Entrez 'o' pour continuer"
    if ($confirm -notmatch "^[oO]$") {
        Write-Host "Abandon. Utilisez option 4 pour re-verifier plus tard." -ForegroundColor Yellow
        return
    }
    $fileName = Split-Path $filePath -Leaf
    $boundary = "----WebKitFormBoundary$([guid]::NewGuid().ToString('N'))"
    $body = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.StreamWriter($body)
    $writer.AutoFlush = $true
    $writer.WriteLine("--$boundary")
    $writer.WriteLine("Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"")
    $writer.WriteLine("Content-Type: application/octet-stream")
    $writer.WriteLine()
    $writer.Flush()
    $fileBytes = [IO.File]::ReadAllBytes($filePath)
    $body.Write($fileBytes, 0, $fileBytes.Length)
    $writer.WriteLine()
    $writer.WriteLine("--$boundary--")
    $writer.Flush()
    $body.Position = 0
    $uploadHeaders = @{
        "x-apikey" = $script:Headers["x-apikey"]
        "Content-Type" = "multipart/form-data; boundary=$boundary"
        "Accept" = "application/json"
    }
    try {
        Write-Host "Upload..." -ForegroundColor Yellow
        $uploadResult = Invoke-WebRequest `
            -Uri "$script:BaseUrl/files" `
            -Method Post `
            -Headers $uploadHeaders `
            -Body $body `
            -UseBasicParsing
        Write-Host "Upload OK!" -ForegroundColor Green
        Write-Host "Polling analyse (max 4min)..." -ForegroundColor Yellow
        $stats = Wait-VTAnalysis $sha256 "files" 4
        $filename = Split-Path $filePath -Leaf
        Write-Host "`n=== Resultat '$filename' ===" -ForegroundColor Cyan
        if ($stats) {
            Write-Host (Test-FileMalicious $stats) -ForegroundColor $(if($stats.malicious -gt 0){'Red'}else{'Green'})
        }
        else {
            Write-Warning "Encore en analyse (re-testez dans 10min avec opt 1/4)"
        }
    }
    catch {
        Write-Error "Erreur upload: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $reader = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
                Write-Warning "Reponse serveur: $($reader.ReadToEnd())"
            }
            catch {}
        }
    }
    finally {
        $body.Dispose()
        $writer.Dispose()
    }
}

function Scan-Folder {
    [CmdletBinding()]
    param()
    $folderPath = (Read-Host "Chemin du dossier").Trim()
    $folderPath = $folderPath.Trim('"')
    if (-not (Test-Path $folderPath)) {
        Write-Error "Dossier introuvable : $folderPath"
        return
    }
    $files = Get-ChildItem -Path $folderPath -Recurse -File | Select-Object -First 10
    $totalFiles = $files.Count
    if ($totalFiles -eq 0) {
        Write-Warning "Aucun fichier trouve dans ce dossier."
        return
    }
    Write-Host "`n[ATTENTION] Scan limite aux $totalFiles premiers fichiers (Quota API gratuit)." -ForegroundColor Yellow
    Write-Host "Debut du scan de $totalFiles fichiers..." -ForegroundColor Cyan
    $results = @()
    $errorCount = 0
    $currentIndex = 0
    foreach ($file in $files) {
        $currentIndex++
        Write-Progress `
            -Activity "Scan du dossier" `
            -Status "Fichier : $($file.Name)" `
            -PercentComplete (($currentIndex / $totalFiles) * 100)
        try {
            $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower()
            $stats = Get-ScanReport $hash
            if ($stats) {
                $status = Test-FileMalicious $stats
                $isMalicious = ($stats.malicious -gt 0)
                $results += [PSCustomObject]@{
                    FileName     = $file.Name
                    FilePath     = $file.FullName
                    FileSizeMB   = [math]::Round($file.Length / 1MB, 2)
                    SHA256       = $hash
                    Status       = $status
                    Malicious    = $isMalicious
                    Detections   = $stats.malicious
                    TotalEngines = ($stats.harmless + $stats.malicious + $stats.suspicious + $stats.timeout + $stats.undetected)
                    ScanSuccess  = $true
                    ErrorMsg     = ""
                }
                $color = if ($isMalicious) { 'Red' } else { 'Green' }
                Write-Host "  [+] $($file.Name) : $status" -ForegroundColor $color
            }
            else {
                $results += [PSCustomObject]@{
                    FileName     = $file.Name
                    FilePath     = $file.FullName
                    FileSizeMB   = [math]::Round($file.Length / 1MB, 2)
                    SHA256       = $hash
                    Status       = "Inconnu (Non analyse)"
                    Malicious    = $false
                    Detections   = 0
                    TotalEngines = 0
                    ScanSuccess  = $true
                    ErrorMsg     = "Non trouve dans le cache VT"
                }
                Write-Host "  [?] $($file.Name) : Inconnu" -ForegroundColor Gray
            }
        }
        catch {
            $errorCount++
            $errMsg = $_.Exception.Message
            if ($errMsg -like "*403*" -or $errMsg -like "*Quota*") {
                Write-Host "`n  [QUOTA] DEPASSE. Arret du scan pour preserver l'API." -ForegroundColor Red
                Write-Host "  Conseil : Attendez 1 minute ou passez a une cle API payante." -ForegroundColor Gray
                break
            }
            Write-Host "  [-] $($file.Name) : Echec du scan" -ForegroundColor Red
            Write-Debug "Erreur detaillee : $errMsg"
            $results += [PSCustomObject]@{
                FileName     = $file.Name
                FilePath     = $file.FullName
                FileSizeMB   = [math]::Round($file.Length / 1MB, 2)
                SHA256       = $hash
                Status       = "Erreur"
                Malicious    = $false
                Detections   = 0
                TotalEngines = 0
                ScanSuccess  = $false
                ErrorMsg     = $errMsg
            }
        }
        Start-Sleep -Seconds $script:DelayBetweenRequests
    }
    Write-Progress -Activity "Scan du dossier" -Completed
    if ($results.Count -gt 0) {
        Write-Host "`n--- Resume du scan ---" -ForegroundColor Cyan
        $results | Format-Table FileName, Status, Detections -AutoSize
        Write-Host "`nSouhaitez-vous exporter ces resultats en CSV ?" -ForegroundColor Yellow
        $exportChoice = Read-Host "Tapez 'o' pour exporter (Entree pour ignorer)"
        if ($exportChoice -match "^[oO]$") {
            Export-ScanResults -Results $results -PathScanned $folderPath
        }
    }
    if ($errorCount -gt 0) {
        Write-Warning "Le scan s'est termine avec $errorCount erreur(s)."
    }
}

function Scan-Url {
    [CmdletBinding()]
    param()
    $url = (Read-Host "URL a scanner (HTTPS recommande)").Trim()
    if (-not $url.StartsWith("http")) { $url = "https://$url" }
    
    try {
        $uri = [System.Uri]$url
        if ($uri.Scheme -notin @('http','https')) { Write-Warning "URL invalide."; return }
    }
    catch { Write-Error "URL invalide"; return }

    try {
        Write-Host "URL validee : $url" -ForegroundColor Cyan
        $scan = Invoke-RestMethod `
            -Uri "$script:BaseUrl/urls" `
            -Method Post `
            -Headers $script:Headers `
            -Body "url=$url" `
            -ContentType "application/x-www-form-urlencoded" `
            -TimeoutSec 30 `
            -ErrorAction Stop
        
        $urlId = $scan.data.id
        Write-Host "ID Scan: $urlId" -ForegroundColor Gray
        Write-Host "Scan lance. Attente des resultats (max 5 min)..." -ForegroundColor Yellow
        
        # Amelioration : Boucle de 5 minutes
        $timeout = (Get-Date).AddMinutes(5)
        $stats = $null
        
        while ((Get-Date) -lt $timeout) {
            Start-Sleep 20
            Write-Host "." -NoNewline -ForegroundColor Gray
            $stats = Get-ScanReport $urlId "urls"
            if ($stats) { break }
        }
        
        Write-Host ""
        if ($stats) {
            Write-Host "`nResultat '$url':" -ForegroundColor Cyan
            Write-Host (Test-FileMalicious $stats) -ForegroundColor $(if($stats.malicious -gt 0){'Red'}else{'Green'})
        }
        else {
            Write-Warning "Analyse toujours en cours apres 5 minutes. Notez l'ID et re-testez plus tard."
        }
    }
    catch {
        Write-Error "Erreur scan URL: $($_.Exception.Message)"
    }
}

function Scan-Hash {
    [CmdletBinding()]
    param()
    $hash = (Read-Host "SHA256 hash (64 caracteres)").Trim()
    if ($hash.Length -ne 64) {
        Write-Error "Hash invalide : doit contenir exactement 64 caracteres hexadecimaux"
        return
    }
    $stats = Get-ScanReport $hash
    Write-Host "`nResultat hash '$hash':" -ForegroundColor Cyan
    Write-Host (Test-FileMalicious $stats) -ForegroundColor $(if($stats.malicious -gt 0){'Red'}else{'Green'})
}

function Check-ExistingScan {

    [CmdletBinding()]
    param()

    Write-Host "`n--- Consulter un scan existant ---" -ForegroundColor Cyan

    $analysisId = Read-Host "Entrez l'ID d'analyse VirusTotal"

    if ([string]::IsNullOrWhiteSpace($analysisId)) {
        Write-Warning "ID invalide."
        return
    }

    try {

        Write-Host "Recuperation de l'analyse..." -ForegroundColor Yellow

        $response = Invoke-RestMethod `
            -Uri "$script:BaseUrl/analyses/$analysisId" `
            -Headers $script:Headers `
            -Method Get `
            -TimeoutSec 30 `
            -ErrorAction Stop

        $status = $response.data.attributes.status

        if ($status -ne "completed") {
            Write-Warning "Analyse encore en cours."
            return
        }

        $stats = $response.data.attributes.stats

        Write-Host "`n=== Resultat analyse ===" -ForegroundColor Cyan
        Write-Host (Test-FileMalicious $stats) `
            -ForegroundColor $(if($stats.malicious -gt 0){'Red'}else{'Green'})

    }
    catch {

        Write-Error "Impossible de recuperer l'analyse : $($_.Exception.Message)"

    }
}

# ============================================================================
# MENU GESTION CLE API
# ============================================================================

function ApiKeyManagement {
    [CmdletBinding()]
    param()
    
    Write-Host "`n--- Gestion de la Cle API ---" -ForegroundColor Cyan
    
    while ($true) {
        Write-Host "`n1. Ajouter/Nouvelle Cle" -ForegroundColor Green
        Write-Host "2. Charger Cle Sauvegardee" -ForegroundColor Cyan
        Write-Host "3. Tester Cle Actuelle" -ForegroundColor Gray
        Write-Host "4. Supprimer Cle Sauvegardee" -ForegroundColor Yellow
        Write-Host "0. Retour au menu principal" -ForegroundColor White
        Write-Host ""
        
        $choice = Read-Host "Choix"
        
        switch ($choice) {
            "1" {
                $secure = Read-Host "Entrez votre cle API" -AsSecureString
                if (Save-ApiKey $secure) {
                    $ApiKey = ConvertFrom-Secure $secure
                    Update-Headers $ApiKey
                    Write-Host "Cle API ajoutee !" -ForegroundColor Green
                }
            }
            "2" {
                $secureKey = Load-ApiKey
                if ($secureKey) {
                    $ApiKey = ConvertFrom-Secure $secureKey
                    Update-Headers $ApiKey
                    Write-Host "Cle API chargee !" -ForegroundColor Green
                }
            }
            "3" {
                if (Test-ApiKey) { Write-Host "Cle valide !" -ForegroundColor Green }
                else { Write-Error "Cle invalide !" }
            }
            "4" { Delete-ApiKey }
            "0" { return } # <--- C'est ici qu'il faut changer 'break' par 'return'
            default { Write-Warning "Choix invalide" }
        }
    }
}

# ============================================================================
# DEMARRAGE
# ============================================================================

Write-Host ""
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "    VirusTotal Scanner CLI v1.2 - Edition Securisee" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host ""

$secureKey = Load-ApiKey
$apiKeyLoaded = $false

if ($secureKey) {
    Write-Host "Cle API sauvegardee detectee" -ForegroundColor Gray
    Write-Host "Chargement automatique..." -ForegroundColor DarkGray
    $ApiKey = ConvertFrom-Secure $secureKey
    Update-Headers $ApiKey
    if (Test-ApiKey) {
        $apiKeyLoaded = $true
        Write-Host "Cle API valide et operationnelle !" -ForegroundColor Green
    }
    else {
        Write-Warning "Cle API sauvegardee invalide" -ForegroundColor Yellow
        Write-Host "Veuillez entrer une nouvelle cle API." -ForegroundColor Gray
    }
}

if (-not $apiKeyLoaded) {
    $secureKey = Read-Host "Entrez votre cle API" -AsSecureString
    if (Save-ApiKey $secureKey) {
        $ApiKey = ConvertFrom-Secure $secureKey
        Update-Headers $ApiKey
        if (-not (Test-ApiKey)) {
            Write-Error "Echec de validation de la cle API."
            exit 1
        }
        Write-Host "Cle API sauvegardee et validee avec succes !" -ForegroundColor Green
    }
    else {
        Write-Error "Impossible de sauvegarder la cle API."
        exit 1
    }
}

Write-Host ""
Start-Sleep 1

while ($true) {
    Show-Menu
    $choice = (Read-Host "Choix (0-6)").Trim()
    
    switch ($choice) {
        "1" { Scan-File }
        "2" { Scan-Folder }
        "3" { Scan-Url }
        "4" { Scan-Hash }
        "5" { ApiKeyManagement }
        "6" { Check-ExistingScan }
        "0" {
            Write-Host "Au revoir !" -ForegroundColor Cyan
            exit 0
        }
        default {
            Write-Warning "Choix invalide (0-6)"
            Start-Sleep 2
        }
    }
    
    if ($choice -ne "0") {
        Read-Host "Appuyez sur Entree pour continuer"
    }
}
