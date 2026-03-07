# VirusTotal Scanner CLI - VERSION 1.1 (PS5.1+)
# Usage: .\vt-scanner.ps1
# Nouvelles fonctionnalites : Export CSV + Gestion d'erreurs robuste

param([string]$ApiKey = $null)

$script:BaseUrl = "https://www.virustotal.com/api/v3".Trim()
$script:Headers = $null
$script:DelayBetweenRequests = 16

function Update-Headers {
    param([string]$Key)
    $script:Headers = @{ "x-apikey" = $Key }
    Write-Host "Cle API configuree!" -ForegroundColor Green
}

function Show-Menu {
    Clear-Host
    Write-Host "=== VirusTotal Scanner CLI (PS5.1+) ===" -ForegroundColor Cyan
    Write-Host "1. Scanner un fichier (hash + upload optionnel)" -ForegroundColor Green
    Write-Host "2. Scanner un dossier (recursif, max 10 fichiers)" -ForegroundColor Green
    Write-Host "3. Scanner une URL (HTTPS recommande)" -ForegroundColor Green
    Write-Host "4. Scanner via hash SHA256" -ForegroundColor Green
    Write-Host "5. Configurer cle API" -ForegroundColor Yellow
    Write-Host "0. Quitter" -ForegroundColor Red
    Write-Host ""
}

function Get-ScanReport {
    param([string]$ResourceId, [string]$Type = "files")
    try {
        $uri = if($Type -eq "urls") {
            "$script:BaseUrl/urls/$ResourceId"
        } else {
            "$script:BaseUrl/files/$ResourceId"
        }
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $script:Headers -ErrorAction Stop
        return $response.data.attributes.last_analysis_stats
    }
    catch {
        return $null
    }
}

function Test-FileMalicious {
    param($Stats)
    if (-not $Stats) { return "Indisponible" }
    $total = $Stats.harmless + $Stats.malicious + $Stats.suspicious + $Stats.timeout + $Stats.undetected
    $result = "$($Stats.malicious)/$total detections malveillantes"
    if ($Stats.malicious -eq 0) { $result = "Propre ($total analyse)" }
    return $result
}

function Scan-File {
    $filePath = Read-Host "Chemin du fichier"
    if (-not (Test-Path $filePath)) {
        Write-Error "Fichier non trouve"
        return
    }
    $sha256 = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToLower()
    Write-Host "Hash: $sha256" -ForegroundColor Cyan

    $stats = Get-ScanReport $sha256
    if ($stats) {
        $filename = Split-Path $filePath -Leaf
        Write-Host "`n=== Resultat '$filename' (cache VT) ===" -ForegroundColor Cyan
        $status = Test-FileMalicious $stats
        $color = if($stats.malicious -gt 0) { 'Red' } else { 'Green' }
        Write-Host $status -ForegroundColor $color
        return
    }

    Write-Host "`nFichier inconnu VT. Upload requis." -ForegroundColor Yellow
    Write-Host "Consomme 1 quota (4/min). Continuer? (o/N)" -ForegroundColor Red

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

        $uploadResult = Invoke-WebRequest -Uri "$script:BaseUrl/files" -Method Post -Headers $uploadHeaders -Body $body -UseBasicParsing
        Write-Host "Upload OK!" -ForegroundColor Green

        Write-Host "Polling analyse (max 3min)..." -ForegroundColor Yellow
        for ($i = 0; $i -lt 9; $i++) {
            Start-Sleep 20
            Write-Host "." -NoNewline -ForegroundColor Gray
            $stats = Get-ScanReport $sha256
            if ($stats) { break }
        }

        $filename = Split-Path $filePath -Leaf
        Write-Host "`n`n=== Resultat '$filename' ===" -ForegroundColor Cyan

        if ($stats) {
            $status = Test-FileMalicious $stats
            $color = if($stats.malicious -gt 0) { 'Red' } else { 'Green' }
            Write-Host $status -ForegroundColor $color
        } else {
            Write-Warning "Encore en analyse (re-testez dans 10min avec opt 1/4)"
        }
    }
    catch {
        Write-Error "Upload erreur: $($_.Exception.Message)"
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

# NOUVELLE FONCTION : Export des resultats en CSV
function Export-ScanResults {
    param(
        [Array]$Results,
        [string]$PathScanned
    )

    if (-not $Results -or $Results.Count -eq 0) {
        Write-Warning "Aucun resultat a exporter."
        return
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fileName = "vt_scan_report_$timestamp.csv"

    $exportData = $Results | Select-Object *, @{Name="ScanDate"; Expression={Get-Date -Format "yyyy-MM-dd HH:mm:ss"}}, @{Name="SourcePath"; Expression={$PathScanned}}

    try {
        $exportData | Export-Csv -Path $fileName -Encoding UTF8 -NoTypeInformation -UseCulture
        Write-Host "[OK] Rapport exporte : $fileName" -ForegroundColor Green
    }
    catch {
        Write-Error "Echec de l'export CSV : $($_.Exception.Message)"
    }
}

# FONCTION Scan-Folder AMELIOREE (v1.1)
function Scan-Folder {
    $delay = if ($script:DelayBetweenRequests) { $script:DelayBetweenRequests } else { 16 }

    $folderPath = Read-Host "Chemin du dossier"
    $folderPath = $folderPath.Trim('"')

    if (-not (Test-Path $folderPath)) {
        Write-Error "Dossier non trouve : $folderPath"
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

        Write-Progress -Activity "Scan du dossier" -Status "Fichier : $($file.Name)" -PercentComplete (($currentIndex / $totalFiles) * 100)

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

        Start-Sleep -Seconds $delay
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

    $url = Read-Host "URL a scanner (HTTPS recommande)"

    $url = $url.Trim()
    if ($url -notmatch '^https?://') { $url = "https://$url" }
    $url = [System.Uri]::EscapeUriString($url)

    try {
        $uri = [System.Uri]$url
        if ($uri.Scheme -notin @('http','https')) {
            Write-Warning "URL invalide. HTTP/HTTPS uniquement."
            return
        }
    }
    catch {
        Write-Warning "Format d'URL incorrect. Exemple : https://example.com"
        return
    }

    try {

        Write-Host "URL validee : $url" -ForegroundColor Cyan

        $scan = Invoke-RestMethod `
            -Uri "$script:BaseUrl/urls" `
            -Method Post `
            -Headers $script:Headers `
            -Body "url=$url" `
            -ContentType "application/x-www-form-urlencoded" `
            -ErrorAction Stop

        $urlId = $scan.data.id

        Write-Host "ID Scan: $urlId" -ForegroundColor Gray
        Write-Host "Scan lance. Attente des resultats..." -ForegroundColor Yellow

        $stats = $null

        for ($i = 0; $i -lt 8; $i++) {

        Start-Sleep 15
        Write-Host "." -NoNewline -ForegroundColor Gray

        $stats = Get-ScanReport $urlId "urls"

        if ($stats) { break }
}

        Write-Host ""

        Write-Host "`nResultat '$url':" -ForegroundColor Cyan

        if ($stats) {
            Write-Host (Test-FileMalicious $stats) -ForegroundColor $(if($stats.malicious -gt 0){'Red'}else{'Green'})
        }
        else {
            Write-Warning "Analyse encore en cours."
        }
    }
    catch {
        Write-Error "Erreur API VirusTotal: $($_.Exception.Message)"
    }
}

function Scan-Hash {
    $hash = Read-Host "SHA256 hash (64 caracteres)"
    $stats = Get-ScanReport $hash
    Write-Host "`nResultat hash '$hash':" -ForegroundColor Cyan
    Write-Host (Test-FileMalicious $stats) -ForegroundColor $(if($stats.malicious -gt 0){'Red'}else{'Green'})
}

# DEMARRAGE
Write-Host "VirusTotal Scanner CLI - https://www.virustotal.com/gui/join-us/do-the-download" -ForegroundColor Cyan

if (-not $ApiKey) {
    $ApiKey = Read-Host "Entrez votre cle API"
}

Update-Headers $ApiKey

while ($true) {
    Show-Menu
    $choice = Read-Host "Choix (0-5)"

    switch ($choice) {
        "1" { Scan-File }
        "2" { Scan-Folder }
        "3" { Scan-Url }
        "4" { Scan-Hash }
        "5" { $newKey = Read-Host "Nouvelle cle"; Update-Headers $newKey }
        "0" { Write-Host "Au revoir!"; exit 0 }
        default { Write-Warning "Choix invalide (0-5)"; Start-Sleep 2 }
    }

    if ($choice -ne "0") {
        Read-Host "Appuyez sur Entree pour continuer"
    }
}

