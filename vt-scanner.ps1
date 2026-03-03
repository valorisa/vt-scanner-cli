# VirusTotal Scanner CLI - VERSION FINALE PS5.1+
# Usage: .\vt-scanner.ps1
param([string]$ApiKey = $null)

$script:BaseUrl = "https://www.virustotal.com/api/v3"
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

# ✅ FONCTION Scan-File CORRIGÉE
function Scan-File {
    $filePath = Read-Host "Chemin du fichier"
    if (-not (Test-Path $filePath)) {
        Write-Error "Fichier non trouve"
        return
    }
    $sha256 = (Get-FileHash $filePath -Algorithm SHA256).Hash.ToLower()
    Write-Host "Hash: $sha256" -ForegroundColor Cyan
    
    # VERIFICATION CACHE VT (priorite 1)
    $stats = Get-ScanReport $sha256
    if ($stats) {
        $filename = Split-Path $filePath -Leaf
        Write-Host "`n=== Resultat '$filename' (cache VT) ===" -ForegroundColor Cyan
        $status = Test-FileMalicious $stats
        $color = if($stats.malicious -gt 0) { 'Red' } else { 'Green' }
        Write-Host $status -ForegroundColor $color
        return
    }
    
    # NOUVEL UPLOAD
    Write-Host "`nFichier inconnu VT. Upload requis." -ForegroundColor Yellow
    Write-Host "Consomme 1 quota (4/min). Continuer? (o/N)" -ForegroundColor Red
    # ✅ CORRECTION: Prompt non vide
    $confirm = Read-Host "Entrez 'o' pour continuer"
    if ($confirm -notmatch "^[oO]$") {
        Write-Host "Abandon. Utilisez option 4 pour re-verifier plus tard." -ForegroundColor Yellow
        return
    }
    
    # ✅ CORRECTION: Upload via formulaire multipart simplifié
    $fileName = Split-Path $filePath -Leaf
    $boundary = "----WebKitFormBoundary$([guid]::NewGuid().ToString('N'))"
    
    # Construction du corps multipart
    $body = New-Object System.IO.MemoryStream
    $writer = New-Object System.IO.StreamWriter($body)
    $writer.AutoFlush = $true
    
    # En-tête du fichier
    $writer.WriteLine("--$boundary")
    $writer.WriteLine("Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"")
    $writer.WriteLine("Content-Type: application/octet-stream")
    $writer.WriteLine()
    $writer.Flush()
    
    # Contenu du fichier (bytes)
    $fileBytes = [IO.File]::ReadAllBytes($filePath)
    $body.Write($fileBytes, 0, $fileBytes.Length)
    
    # Fin du multipart
    $writer.WriteLine()
    $writer.WriteLine("--$boundary--")
    $writer.Flush()
    
    $body.Position = 0
    
    # ✅ CORRECTION: Headers corrects pour multipart
    $uploadHeaders = @{
        "x-apikey" = $script:Headers["x-apikey"]
        "Content-Type" = "multipart/form-data; boundary=$boundary"
        "Accept" = "application/json"
    }
    
    try {
        Write-Host "Upload..." -ForegroundColor Yellow
        
        # ✅ CORRECTION: Utilisation de Invoke-WebRequest pour mieux gérer le multipart
        $uploadResult = Invoke-WebRequest -Uri "$script:BaseUrl/files" -Method Post -Headers $uploadHeaders -Body $body -UseBasicParsing
        
        Write-Host "Upload OK!" -ForegroundColor Green
        
        # POLLING INTELLIGENT (3min max)
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

function Scan-Folder {
    $folderPath = Read-Host "Chemin du dossier"
    if (-not (Test-Path $folderPath)) {
        Write-Error "Dossier non trouve"
        return
    }
    $files = Get-ChildItem -Path $folderPath -Recurse -File | Select-Object -First 10
    Write-Host "Scan $($files.Count) fichiers..." -ForegroundColor Yellow
    $results = @()
    foreach ($file in $files) {
        $hash = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLower()
        $stats = Get-ScanReport $hash
        $status = Test-FileMalicious $stats
        $results += [PSCustomObject]@{
            Fichier = $file.Name
            Status = $status
            TailleMB = "{0:N1}" -f ($file.Length/1MB)
        }
        Write-Host "  $($file.Name): $status"
        Start-Sleep $script:DelayBetweenRequests
    }
    $results | Format-Table -AutoSize
}

# ✅ FONCTION Scan-Url CORRIGÉE
function Scan-Url {
    $url = Read-Host "URL a scanner (HTTPS recommande)"
    if (-not $url.StartsWith("http")) {
        Write-Warning "URL invalide. Ex: https://exemple.com"
        return
    }
    
    # ✅ CORRECTION: JSON compressé
    $body = @{ url = $url } | ConvertTo-Json -Compress
    
    try {
        # ✅ CORRECTION: Pas de -ContentType explicite
        $scan = Invoke-RestMethod -Uri "$script:BaseUrl/urls" -Method Post -Headers $script:Headers -Body $body
        
        # ✅ CORRECTION: ID URL direct (PAS de -split '/')
        $urlId = $scan.data.id
        Write-Host "ID Scan: $urlId" -ForegroundColor Gray
        
        Write-Host "Scan lance. Attente (60s)..." -ForegroundColor Yellow
        Start-Sleep 60
        
        $stats = Get-ScanReport $urlId "urls"
        
        Write-Host "`nResultat '$url':" -ForegroundColor Cyan
        if ($stats) {
            Write-Host (Test-FileMalicious $stats) -ForegroundColor $(if($stats.malicious -gt 0){'Red'}else{'Green'})
        } else {
            Write-Warning "Analyse encore en cours. Re-testez dans quelques minutes."
        }
    }
    catch {
        Write-Error "Erreur URL: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            try {
                $reader = New-Object IO.StreamReader($_.Exception.Response.GetResponseStream())
                Write-Warning "Reponse serveur: $($reader.ReadToEnd())"
            }
            catch {}
        }
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
if (-not $ApiKey) { $ApiKey = Read-Host "Entrez votre cle API" }
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
        default { Write-Warning "0-5"; Start-Sleep 2 }
    }
    if ($choice -ne "0") { Read-Host "Appuyez sur Entree pour continuer" }
}