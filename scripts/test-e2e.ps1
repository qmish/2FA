param(
    [Parameter(Mandatory = $true)]
    [string]$BaseUrl,
    [string]$Username = "",
    [SecureString]$Password
)

$env:E2E_BASE_URL = $BaseUrl
if ($Username -ne "") { $env:E2E_USERNAME = $Username }
if ($Password) {
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try {
        $env:E2E_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

& "C:\Program Files\Go\bin\go.exe" test ./internal/e2e -count=1
