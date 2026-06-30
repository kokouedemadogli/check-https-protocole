#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$UrlFile,

    [Parameter(Position = 1)]
    [string]$OutputFile = ("report_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
)

$ErrorActionPreference = 'Stop'

$script:TimeoutSeconds = 10
$script:TimeoutMilliseconds = $script:TimeoutSeconds * 1000

function Get-HostNameFromInput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RawValue
    )

    $candidate = $RawValue.Trim()
    if ([string]::IsNullOrWhiteSpace($candidate)) {
        return $null
    }

    if ($candidate -notmatch '^[a-z][a-z0-9+\.-]*://') {
        $candidate = "https://$candidate"
    }

    $uri = $null
    if (-not [Uri]::TryCreate($candidate, [UriKind]::Absolute, [ref]$uri)) {
        return $null
    }

    if ($uri.Scheme -notin @('http', 'https')) {
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($uri.Host) -and $candidate -like 'https://*') {
        $fallbackUri = $null
        if ([Uri]::TryCreate($candidate.Replace('https://', 'http://'), [UriKind]::Absolute, [ref]$fallbackUri)) {
            $uri = $fallbackUri
        }
    }

    if ([string]::IsNullOrWhiteSpace($uri.Host)) {
        return $null
    }

    return $uri.IdnHost
}

function Test-DnsResolution {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName
    )

    try {
        return [System.Net.Dns]::GetHostAddresses($HostName).Count -gt 0
    }
    catch {
        return $false
    }
}

function Test-PortConnectivity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $false)]
        [int]$Port = 443
    )

    $tcpClient = [System.Net.Sockets.TcpClient]::new()
    try {
        $connectTask = $tcpClient.ConnectAsync($HostName, $Port)
        if (-not $connectTask.Wait($script:TimeoutMilliseconds)) {
            return $false
        }

        $connectTask.GetAwaiter().GetResult()
        return $tcpClient.Connected
    }
    catch {
        return $false
    }
    finally {
        $tcpClient.Dispose()
    }
}

function Resolve-SslProtocol {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProtocolName
    )

    if ([Enum]::GetNames([System.Security.Authentication.SslProtocols]) -contains $ProtocolName) {
        return [System.Security.Authentication.SslProtocols]::$ProtocolName
    }

    return $null
}

function Test-ProtocolSupport {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [Parameter(Mandatory = $true)]
        [string]$ProtocolName
    )

    $protocol = Resolve-SslProtocol -ProtocolName $ProtocolName
    if ($null -eq $protocol) {
        return [pscustomobject]@{
            Result = 'N/A'
            Error  = ''
        }
    }

    $validationCallback = [System.Net.Security.RemoteCertificateValidationCallback]{
        param($Sender, $Certificate, $Chain, $SslPolicyErrors)
        return $true
    }

    $tcpClient = [System.Net.Sockets.TcpClient]::new()
    $sslStream = $null

    try {
        $connectTask = $tcpClient.ConnectAsync($HostName, 443)
        if (-not $connectTask.Wait($script:TimeoutMilliseconds)) {
            return [pscustomobject]@{
                Result = 'FALSE'
                Error  = ''
            }
        }

        $connectTask.GetAwaiter().GetResult()

        $sslStream = [System.Net.Security.SslStream]::new($tcpClient.GetStream(), $false, $validationCallback)

        $options = [System.Net.Security.SslClientAuthenticationOptions]::new()
        $options.TargetHost = $HostName
        $options.EnabledSslProtocols = $protocol
        $options.CertificateRevocationCheckMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck

        $authenticateTask = $sslStream.AuthenticateAsClientAsync($options)
        if (-not $authenticateTask.Wait($script:TimeoutMilliseconds)) {
            return [pscustomobject]@{
                Result = 'FALSE'
                Error  = ''
            }
        }

        $authenticateTask.GetAwaiter().GetResult()

        if ($sslStream.IsAuthenticated) {
            return [pscustomobject]@{
                Result = 'TRUE'
                Error  = ''
            }
        }

        return [pscustomobject]@{
            Result = 'FALSE'
            Error  = ''
        }
    }
    catch {
        $baseException = $_.Exception.GetBaseException()
        $message = [string]$baseException.Message

        if ($baseException -is [System.PlatformNotSupportedException] -or
            $baseException -is [System.NotSupportedException] -or
            $message -match 'not supported|unsupported|no protocols available') {
            return [pscustomobject]@{
                Result = 'N/A'
                Error  = ''
            }
        }

        if ($baseException -is [System.Security.Authentication.AuthenticationException] -or
            $baseException -is [System.IO.IOException] -or
            $baseException -is [System.Net.Sockets.SocketException] -or
            $baseException -is [System.TimeoutException]) {
            return [pscustomobject]@{
                Result = 'FALSE'
                Error  = ''
            }
        }

        return [pscustomobject]@{
            Result = 'FALSE'
            Error  = $message
        }
    }
    finally {
        if ($null -ne $sslStream) {
            $sslStream.Dispose()
        }

        $tcpClient.Dispose()
    }
}

function Get-HttpStatusCode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostName,

        [bool]$Port443Open = $false,
        [bool]$Port8080Open = $false,
        [bool]$Port8000Open = $false,
        [bool]$Port80Open = $false
    )

    $previousProgressPreference = $global:ProgressPreference
    $global:ProgressPreference = 'SilentlyContinue'

    try {
        $trials = [System.Collections.Generic.List[string]]::new()
        if ($Port443Open)  { $trials.Add("https://$HostName") }
        if ($Port8080Open) { $trials.Add("http://${HostName}:8080") }
        if ($Port8000Open) { $trials.Add("http://${HostName}:8000") }
        if ($Port80Open)   { $trials.Add("http://$HostName") }

        foreach ($url in $trials) {
            try {
                $response = Invoke-WebRequest `
                    -Uri $url `
                    -MaximumRedirection 10 `
                    -SkipCertificateCheck `
                    -SkipHttpErrorCheck `
                    -TimeoutSec $script:TimeoutSeconds
                return [int]$response.StatusCode
            }
            catch { }
        }
        return ''
    }
    finally {
        $global:ProgressPreference = $previousProgressPreference
    }
}

function Write-ReportRow {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]$Columns
    )

    Add-Content -Path $Path -Value ($Columns -join "`t")
}

if (-not (Test-Path -LiteralPath $UrlFile -PathType Leaf)) {
    throw "Le fichier '$UrlFile' est introuvable."
}

Set-Content -Path $OutputFile -Value "URL`tSSL 2.0`tSSL 3.0`tTLS 1.0`tTLS 1.1`tSECURED`t443`t8000`t8080`t80`tREPONSE HTTP`tERREUR"

$lineNumber = 0
foreach ($rawUrl in Get-Content -LiteralPath $UrlFile) {
    $lineNumber++

    if ([string]::IsNullOrWhiteSpace($rawUrl) -or $rawUrl -match '^\s*#') {
        continue
    }

    $hostName = Get-HostNameFromInput -RawValue $rawUrl
    if ([string]::IsNullOrWhiteSpace($hostName)) {
        Write-Warning "Nom d'hôte vide à la ligne $lineNumber, ligne ignorée."
        continue
    }

    Write-Host "  -> Test de $hostName ..."

    $ssl2 = ''
    $ssl3 = ''
    $tls10 = ''
    $tls11 = ''
    $secured = ''
    $httpCode = ''
    $errorMessage = ''
    $p443 = ''
    $p8000 = ''
    $p8080 = ''
    $p80 = ''

    if (-not (Test-DnsResolution -HostName $hostName)) {
        $errorMessage = 'Le DNS ne résout pas'
        Write-ReportRow -Path $OutputFile -Columns @($hostName, $ssl2, $ssl3, $tls10, $tls11, $secured, $p443, $p8000, $p8080, $p80, $httpCode, $errorMessage)
        Write-Host '    [ECHEC DNS]'
        continue
    }

    $p443  = if (Test-PortConnectivity -HostName $hostName -Port 443)  { 'TRUE' } else { 'FALSE' }
    $p8000 = if (Test-PortConnectivity -HostName $hostName -Port 8000) { 'TRUE' } else { 'FALSE' }
    $p8080 = if (Test-PortConnectivity -HostName $hostName -Port 8080) { 'TRUE' } else { 'FALSE' }
    $p80   = if (Test-PortConnectivity -HostName $hostName -Port 80)   { 'TRUE' } else { 'FALSE' }

    Write-Host "    Ports: 443=$p443  8000=$p8000  8080=$p8080  80=$p80"

    if ($p443 -eq 'FALSE' -and $p8000 -eq 'FALSE' -and $p8080 -eq 'FALSE' -and $p80 -eq 'FALSE') {
        $errorMessage = 'Tous les ports testés sont fermés'
    }
    else {
        $httpCode = Get-HttpStatusCode -HostName $hostName `
            -Port443Open ($p443 -eq 'TRUE') `
            -Port8080Open ($p8080 -eq 'TRUE') `
            -Port8000Open ($p8000 -eq 'TRUE') `
            -Port80Open ($p80 -eq 'TRUE')

        if ($p443 -eq 'TRUE') {
            $ssl2Result  = Test-ProtocolSupport -HostName $hostName -ProtocolName 'Ssl2'
            $ssl3Result  = Test-ProtocolSupport -HostName $hostName -ProtocolName 'Ssl3'
            $tls10Result = Test-ProtocolSupport -HostName $hostName -ProtocolName 'Tls'
            $tls11Result = Test-ProtocolSupport -HostName $hostName -ProtocolName 'Tls11'

            $ssl2  = $ssl2Result.Result
            $ssl3  = $ssl3Result.Result
            $tls10 = $tls10Result.Result
            $tls11 = $tls11Result.Result

            foreach ($protocolResult in @($ssl2Result, $ssl3Result, $tls10Result, $tls11Result)) {
                if ([string]::IsNullOrWhiteSpace($errorMessage) -and -not [string]::IsNullOrWhiteSpace($protocolResult.Error)) {
                    $errorMessage = $protocolResult.Error
                }
            }

            if ($ssl2 -eq 'TRUE' -or $ssl3 -eq 'TRUE' -or $tls10 -eq 'TRUE' -or $tls11 -eq 'TRUE') {
                $secured = 'FALSE'
            }
            else {
                $secured = 'TRUE'
            }
        }
        # If port 443 not open: protocols and SECURED remain empty
    }

    Write-Host "    SSL2=$ssl2  SSL3=$ssl3  TLS1.0=$tls10  TLS1.1=$tls11  SECURED=$secured  HTTP=$httpCode"
    Write-ReportRow -Path $OutputFile -Columns @($hostName, $ssl2, $ssl3, $tls10, $tls11, $secured, $p443, $p8000, $p8080, $p80, $httpCode, $errorMessage)
}

Write-Host ''
Write-Host "Rapport enregistré dans : $OutputFile"
