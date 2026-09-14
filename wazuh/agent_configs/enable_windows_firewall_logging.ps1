<#
  Enables Windows Defender Firewall connection logging (allowed + dropped)
  for all profiles, at a size that survives a busy attack-sim run.
  Run as Administrator on win-target.
#>

$LogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"

foreach ($profile in @('Domain','Public','Private')) {
    Set-NetFirewallProfile -Profile $profile `
        -LogAllowed True `
        -LogBlocked True `
        -LogFileName $LogPath `
        -LogMaxSizeKilobytes 32767
}

# Wazuh's agent needs read access to the log file.
icacls $LogPath /grant "NT AUTHORITY\SYSTEM:(R)" 2>$null

Write-Host "Firewall logging enabled. Log path: $LogPath"
Write-Host "Verify entries are being written with: Get-Content `"$LogPath`" -Tail 20 -Wait"
