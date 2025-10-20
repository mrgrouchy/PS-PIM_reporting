[CmdletBinding()]
param(
  [int]$Days = 30,
  [datetime]$StartDate = (Get-Date).AddDays(-$Days),
  [datetime]$EndDate   = (Get-Date),
  [switch]$CompletedOnly,
  [string]$OutputPath = (Get-Location)   # <-- NEW: where index.html lives
)

# --- minimal dependency: Microsoft.Graph.Authentication only ---
if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
  Write-Verbose "Installing Microsoft.Graph.Authentication (CurrentUser)…"
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -ErrorAction SilentlyContinue -Verbose:$false
}

# Connect once (needs AuditLog.Read.All)
if (-not (Get-MgContext)) {
  Write-Verbose "Connecting to Graph (AuditLog.Read.All)…"
  Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All" -ErrorAction Stop
} else {
  Write-Verbose "Using existing Graph context."
}

# Helpers
function ODataUtc([datetime]$d) { $d.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss'Z'") }
function Get-ADetail { param($arr,[string[]]$keys)
  if (-not $arr) { return $null }
  $lk = $keys | ForEach-Object { $_.ToLower() }
  ($arr | Where-Object { $lk -contains ($_.key.ToLower()) } | Select-Object -First 1).value
}

$start = ODataUtc $StartDate
$end   = ODataUtc $EndDate
Write-Verbose "Window: $start .. $end"

# Strict PIM activation phrases
$activityFilter = if ($CompletedOnly) {
  "(activityDisplayName eq 'Add member to role completed (PIM activation)')"
} else {
  "(" +
    "activityDisplayName eq 'Add member to role requested (PIM activation)' or " +
    "activityDisplayName eq 'Add member to role completed (PIM activation)'" +
  ")"
}

# Full OData filter: PIM RoleManagement only, within time window
$filter = "$activityFilter and (category eq 'RoleManagement') and activityDateTime ge $start and activityDateTime le $end"
# Encode and build URL
$qs   = '$filter=' + [uri]::EscapeDataString($filter) + '&$top=999'
$uri  = "/v1.0/auditLogs/directoryAudits?$qs"
Write-Verbose "GET $uri"

# Fetch with paging
$events = @()
try {
  $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
  $page = 1
  while ($resp.value) {
    Write-Verbose "Page $page : received $($resp.value.Count) events"
    $events += $resp.value
    if ($resp.'@odata.nextLink') {
      $page++
      $resp = Invoke-MgGraphRequest -Method GET -Uri $resp.'@odata.nextLink' -OutputType PSObject
    } else { break }
  }
} catch {
  Write-Error "Failed to fetch audit logs: $($_.Exception.Message)"
  return
}

Write-Verbose "Total fetched: $($events.Count)"

# Shape (no IDs) → Timestamp, MemberUPN, Member, Role, Justification, Activity, Result, ResultReason
$rows = foreach ($e in $events) {
  # Member (affected user)
  $tUser  = $e.targetResources | Where-Object { $_.type -match '^User$' } | Select-Object -First 1
  $member = $tUser.displayName
  $upn    = $tUser.userPrincipalName
  if (-not $upn -and $e.additionalDetails) {
    $upn    = Get-ADetail $e.additionalDetails @('UserPrincipalName','TargetUserPrincipalName','AssigneeUPN','SubjectUserPrincipalName')
    if (-not $member) { $member = Get-ADetail $e.additionalDetails @('TargetUser','Assignee','Member','SubjectDisplayName') }
  }

  # Role (best-effort from targetResources or additionalDetails — no external lookups)
  $tRole = $e.targetResources | Where-Object { $_.type -match '^role$|UnifiedRoleDefinition$' } | Select-Object -First 1
  $role  = $tRole.displayName
  if (-not $role -and $e.additionalDetails) {
    $role = Get-ADetail $e.additionalDetails @('RoleDefinitionName','Role','RoleName','PrivilegedRole','Role Display Name','RoleDefinitionDisplayName')
  }

  # Justification
  $just = Get-ADetail $e.additionalDetails @('Justification','Reason')

  $resultReason =
  if ($e.resultReason -and ($e.resultReason -ne $just)) { $e.resultReason } else { $null }
  
  [pscustomobject]@{
    Timestamp     = $e.activityDateTime
    MemberUPN     = $upn
    Member        = $member
    Role          = $role
    Justification = $just
    Activity      = $e.activityDisplayName
    Result        = $e.result
    ResultReason  = if ($e.resultReason -and ($e.resultReason -ne $just)) { $e.resultReason } else { $null }
  }
}

# =========================
# Output + merge (append-only)
# =========================
$makeKey = {
  param($e,$upn,$role)
  # Fallback key in case old data lacks Id
  "{0}|{1}|{2}|{3}|{4}" -f ($e.activityDateTime), ($upn ?? ''), ($role ?? ''), ($e.activityDisplayName ?? ''), ($e.result ?? '')
}

# Shape rows (now include Id + Key for dedupe; Id won't be shown by the page)
$rows = foreach ($e in $events) {
  # Member
  $tUser  = $e.targetResources | Where-Object { $_.type -match '^User$' } | Select-Object -First 1
  $member = $tUser.displayName
  $upn    = $tUser.userPrincipalName
  if (-not $upn -and $e.additionalDetails) {
    $upn = Get-ADetail $e.additionalDetails @('UserPrincipalName','TargetUserPrincipalName','AssigneeUPN','SubjectUserPrincipalName')
    if (-not $member) { $member = Get-ADetail $e.additionalDetails @('TargetUser','Assignee','Member','SubjectDisplayName') }
  }

  # Role
  $tRole = $e.targetResources | Where-Object { $_.type -match '^role$|UnifiedRoleDefinition$' } | Select-Object -First 1
  $role  = $tRole.displayName
  if (-not $role -and $e.additionalDetails) {
    $role = Get-ADetail $e.additionalDetails @('RoleDefinitionName','Role','RoleName','PrivilegedRole','Role Display Name','RoleDefinitionDisplayName')
  }

  # Justification
  $just = Get-ADetail $e.additionalDetails @('Justification','Reason')

  [pscustomobject]@{
    Id            = $e.id                          # <-- used for dedupe, not displayed
    Key           = & $makeKey $e $upn $role       # <-- fallback if Id missing in older data
    Timestamp     = $e.activityDateTime
    MemberUPN     = $upn
    Member        = $member
    Role          = $role
    Justification = $just
    Activity      = $e.activityDisplayName
    Result        = $e.result
    ResultReason  = $e.resultReason
  }
}

# Where to persist
$webDir       = Get-Location
$storeJson    = Join-Path $webDir "PIM_Activations.json"
$storeJs      = Join-Path $webDir "PIM_Activations.data.js"
$stamp        = Get-Date -Format 'yyyyMMdd_HHmmss'

# Load existing store (if any)
$existing = @()
if (Test-Path $storeJson) {
  try   { $existing = Get-Content $storeJson -Raw | ConvertFrom-Json }
  catch { Write-Warning "Couldn't read existing PIM_Activations.json: $($_.Exception.Message)" }
}
if (-not ($existing -is [System.Collections.IEnumerable])) { $existing = @() }

# Build hash sets for dedupe
$seenIds  = [System.Collections.Generic.HashSet[string]]::new()
$seenKeys = [System.Collections.Generic.HashSet[string]]::new()

foreach ($r in $existing) {
  if ($r.PSObject.Properties.Match('Id').Count -gt 0 -and $r.Id) { $null = $seenIds.Add([string]$r.Id) }
  if ($r.PSObject.Properties.Match('Key').Count -gt 0 -and $r.Key) { $null = $seenKeys.Add([string]$r.Key) }
}

# Partition new rows into (new vs already stored)
$newRows = @()
foreach ($r in $rows) {
  $hasId = ($r.Id -ne $null -and $r.Id -ne "")
  $dupById  = $hasId -and $seenIds.Contains([string]$r.Id)
  $dupByKey = -not $hasId -and $seenKeys.Contains([string]$r.Key)

  if (-not ($dupById -or $dupByKey)) {
    # remember in sets so we don't add duplicates within this batch
    if ($hasId) { $null = $seenIds.Add([string]$r.Id) } else { $null = $seenKeys.Add([string]$r.Key) }
    $newRows += $r
  }
}

# Merge and sort (keep everything we have, newest first)
$merged = @($existing + $newRows) | Sort-Object Timestamp -Descending

# (Optional) cap the store so it doesn't grow forever.
$cutoff = (Get-Date).AddDays(-365)
$merged = $merged | Where-Object { [datetime]$_.Timestamp -ge $cutoff }

# Console summary
Write-Host ("🧮 Existing: {0}, New this run: {1}, Total now: {2}" -f $existing.Count, $newRows.Count, $merged.Count)

# CSV export (only the NEW rows this run), omit Id/Key in CSV
if ($newRows.Count -gt 0) {
  $newCsv = Join-Path $webDir ("PIM_Activations_new_{0}.csv" -f $stamp)
  $newRows | Select-Object Timestamp,MemberUPN,Member,Role,Justification,Activity,Result,ResultReason |
    Export-Csv -NoTypeInformation -Path $newCsv
  Write-Host "✅ CSV (new rows): $newCsv"
} else {
  Write-Host "✅ No new rows to export this run."
}

# Persist: JSON store (atomic)
$jsonAll = $merged | ConvertTo-Json -Depth 6
$tmpJson = "$storeJson.tmp"
Set-Content -Path $tmpJson -Value $jsonAll -Encoding utf8
Move-Item -Path $tmpJson -Destination $storeJson -Force
Write-Host "✅ Store updated: $storeJson"

# Persist: offline JS bundle for the webpage (atomic)
$jsBody  = "window.PIM_ACTIVATIONS = " + $jsonAll + ";"
$tmpJs   = "$storeJs.tmp"
Set-Content -Path $tmpJs -Value $jsBody -Encoding utf8
Move-Item -Path $tmpJs -Destination $storeJs -Force
Write-Host "✅ Web data updated: $storeJs"

