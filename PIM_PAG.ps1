#Requires -Modules Microsoft.Graph

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('PIM','PAG','Both')]
    [string]$LookupMode = 'Both',

    [Parameter(Mandatory=$false)]
    [string]$OutputFolder = (Get-Location).Path
)

# -------------------- Mode Booleans --------------------
$DoPIM = $LookupMode -in @('PIM','Both')
$DoPAG = $LookupMode -in @('PAG','Both')

# -------------------- Helpers --------------------
function Join-List([object[]]$arr) {
    @($arr | Where-Object { $_ -and $_.ToString().Trim() -ne '' }) -join ';'
}
function Split-List([string]$s) {
    if (-not $s) { return @() }
    return @($s -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) | Sort-Object -Unique
}
function Get-ReportKey($o) {
    # Composite key (principalId + roleDefinitionId + scope)
    $pKey  = $null
    $rKey  = $null
    $scope = $null
    if ($o.PSObject.Properties.Name -contains 'PrincipalObjectId') { $pKey = $o.PrincipalObjectId }
    if (-not $pKey -and $o.PSObject.Properties.Name -contains 'Principal') { $pKey = $o.Principal }
    if ($o.PSObject.Properties.Name -contains 'RoleDefinitionId') { $rKey = $o.RoleDefinitionId }
    if (-not $rKey -and $o.PSObject.Properties.Name -contains 'AssignedRole') { $rKey = $o.AssignedRole }
    if ($o.PSObject.Properties.Name -contains 'AssignedRoleScope') { $scope = $o.AssignedRoleScope }
    if (-not $pKey -or -not $rKey -or -not $scope) { return $null }
    return ("{0}|{1}|{2}" -f $pKey, $rKey, $scope)
}

# Read an existing *.data.js file (if present) and return the JSON payload as objects
function Load-ExistingJs([string]$path, [string]$globalName) {
    if (-not (Test-Path $path)) { return @() }
    try {
        $raw = Get-Content -Path $path -Raw
        # Expect format: window.<globalName> = [ ... ];
        $pattern = "window\.$([regex]::Escape($globalName))\s*=\s*(\[.*\])\s*;"
        $m = [regex]::Match($raw, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($m.Success) {
            $json = $m.Groups[1].Value
            $data = $json | ConvertFrom-Json
            if ($data -isnot [System.Collections.IEnumerable]) { return @($data) }
            return @($data)
        }
        else { return @() }
    } catch {
        Write-Warning "Existing JS at '$path' could not be parsed. Treating as first run. $($_.Exception.Message)"
        return @()
    }
}

# Write data to a *.data.js file with a global variable your site can read.
function Save-Js([object[]]$data, [string]$path, [string]$globalName) {
    $null = New-Item -Path (Split-Path $path -Parent) -ItemType Directory -Force -ErrorAction SilentlyContinue
    $json = $data | Sort-Object PrincipalDisplayName | ConvertTo-Json -Depth 12
    $banner = "// Generated on $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK') — do not edit by hand`n"
    $body   = "window.$globalName = $json;"
    Set-Content -Path $path -Encoding utf8 -Value ($banner + $body)
}

# -------------------- CONNECT --------------------
#try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}

$scopes = @("Directory.Read.All","Group.Read.All")
if ($DoPIM) { $scopes += "RoleManagement.Read.Directory" }
if ($DoPAG) { $scopes += @("RoleManagement.Read.Directory","PrivilegedAccess.Read.AzureADGroup") }
$scopes = $scopes | Select-Object -Unique

# Quiet connect
Connect-MgGraph -Scopes $scopes | Out-Null

# -------------------- Containers --------------------
$roles           = @()
$roleactivations = @()
$Proles          = @()

# -------------------- PIM (Directory Roles) --------------------
if ($DoPIM) {
    $rolesAssignments  = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal
    $rolesWithDefsOnly = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty roleDefinition

    # Map roleDefinition onto each role (key = RoleDefinitionId)
    $roleDefById = @{}
    foreach ($r in $rolesWithDefsOnly) {
        if ($r.roleDefinition) { $roleDefById[$r.roleDefinition.Id] = $r.roleDefinition }
    }
    foreach ($role in $rolesAssignments) {
        $rd = $null
        if ($role.roleDefinitionId -and $roleDefById.ContainsKey($role.roleDefinitionId)) {
            $rd = $roleDefById[$role.roleDefinitionId]
        }
        Add-Member -InputObject $role -MemberType NoteProperty -Name roleDefinition1 -Value $rd -Force
    }

    # Role eligibilities (unify shape)
    $eligibility = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty roleDefinition,principal -Verbose:$false -ErrorAction Stop |
        Select-Object id,principalId,directoryScopeId,roleDefinitionId,status,principal,
            @{n="roleDefinition1";e={$_.roleDefinition}}

    # Merge PIM objects
    $roles += $rolesAssignments
    $roles += $eligibility

    # PIM activations (AssignmentType = Activated)
    $roleactivations = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -Filter "AssignmentType eq 'Activated'" -Verbose:$false -ErrorAction Stop

    # Mark duplicates (compare assignment Id to RoleAssignmentOriginId)
    foreach ($act in $roleactivations) {
        $roles |
            Where-Object { $_.Id -eq $act.RoleAssignmentOriginId } |
            ForEach-Object { Add-Member -InputObject $_ -MemberType NoteProperty -Name "Duplicate" -Value $true -Force }
    }

    if (!$roles) { Write-Warning "No valid PIM role assignments found." }
}

# -------------------- PAG (Privileged Access Groups) --------------------
if ($DoPAG) {

    if (-not $DoPIM) {
        # We still need role assignment shells to locate group-principal items and (optionally) attach role defs
        $roles = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal
        try {
            $rolesWithDefsOnly = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty roleDefinition
            $roleDefById = @{}
            foreach ($r in $rolesWithDefsOnly) {
                if ($r.roleDefinition) { $roleDefById[$r.roleDefinition.Id] = $r.roleDefinition }
            }
            foreach ($role in $roles) {
                $rd = $null
                if ($role.roleDefinitionId -and $roleDefById.ContainsKey($role.roleDefinitionId)) { $rd = $roleDefById[$role.roleDefinitionId] }
                Add-Member -InputObject $role -MemberType NoteProperty -Name roleDefinition1 -Value $rd -Force
            }
        } catch {
            Write-Warning "Couldn't expand roleDefinition for PAG-only run: $($_.Exception.Message)"
        }
    }

    # Identify roles with Group principal
    $Proles = $roles | Where-Object { $_.Principal.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }

    if ($Proles) {
        foreach ($role in $Proles) {
            # Track eligibility read success (default false)
            $role | Add-Member -MemberType NoteProperty -Name "PAGEligibleReadSucceeded" -Value $false -Force

            # Initialize containers
            $dMembers   = @{}
            $dMembersId = @()
            $eMembers   = @{}
            $eMembersId = @()

            # Active (transitive) members
            try {
                $transitive = Get-MgGroupTransitiveMember -GroupId $role.PrincipalId `
                    -Property id,displayName,userPrincipalName -Verbose:$false -ErrorAction Stop
                foreach ($member in $transitive) {
                    $upn = $member.AdditionalProperties.userPrincipalName
                    $dMembers[$member.Id] = $upn
                    if ($upn) {
                        # UPN only
                        $dMembersId += $upn
                    } elseif ($member.AdditionalProperties.displayName) {
                        # Display name only, no GUID suffix
                        $dMembersId += $member.AdditionalProperties.displayName
                    }
                }
                # Normalize (trim, dedupe)
                $dMembersId = $dMembersId | ForEach-Object { $_.Trim() } | Sort-Object -Unique
            }
            catch {
                Write-Warning ("Transitive member read failed for group {0}: {1}" -f $role.PrincipalId, $_.Exception.Message)
            }
            $role | Add-Member -MemberType NoteProperty -Name "Active group members" -Value $dMembers -Force
            $role | Add-Member -MemberType NoteProperty -Name "Active group members IDs" -Value (@($dMembersId) -join ";") -Force

            # Eligible members (PAG)
            try {
                $eligible = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule `
                    -Filter "groupId eq '$($role.principalId)'" `
                    -ExpandProperty principal `
                    -Verbose:$false -ErrorAction Stop

                foreach ($member in $eligible) {
                    $memberId = $member.principal.Id
                    $upn      = $member.principal.AdditionalProperties.userPrincipalName
                    $eMembers[$memberId] = $upn
                    if ($upn) {
                        $eMembersId += $upn
                    } elseif ($member.principal.AdditionalProperties.displayName) {
                        $eMembersId += $member.principal.AdditionalProperties.displayName
                    }
                }
                $eMembersId = $eMembersId | ForEach-Object { $_.Trim() } | Sort-Object -Unique
                $role.PAGEligibleReadSucceeded = $true
            }
            catch {
                # Preserve last known eligible list in merge phase
                Write-Warning ("PAG eligibility read failed for group {0}: {1}" -f $role.PrincipalId, $_.Exception.Message)
            }
            $role | Add-Member -MemberType NoteProperty -Name "Eligible group members" -Value $eMembers -Force
            $role | Add-Member -MemberType NoteProperty -Name "Eligible group members IDs" -Value (@($eMembersId) -join ";") -Force
        }
    }

    # If PIM did not run, limit $roles to only group-principal roles for PAG report
    if (-not $DoPIM) {
        $roles = @($Proles)
    }
}

# -------------------- BUILD REPORTS (separate PIM/PAG) --------------------
$nowUtc = (Get-Date).ToUniversalTime().ToString("s") + "Z"

# Normalize input list
$roles           = @($roles) | Where-Object { $_ }
$roleactivations = @($roleactivations)

# Prepare collectors
$reportPIM = @()   # All PIM directory role records (users, SvcPrincipals, groups)
$reportPAG = @()   # Only group-principal records with PAG enrichment

foreach ($role in $roles) {
    if (-not $role) { continue }
    if ($role.PSObject.Properties.Name -contains 'Duplicate' -and $role.Duplicate) { continue }

    # Determine if group principal
    $ptypeFull = $null
    $isGroup = $false
    if ($role.PSObject.Properties.Match('principal').Count -gt 0 -and
        $role.principal -and
        $role.principal.AdditionalProperties) {
        $ptypeFull = $role.principal.AdditionalProperties.'@odata.type'
        $isGroup   = ($ptypeFull -eq '#microsoft.graph.group')
    }

    # Normalize assignment info
    if (-not $role.status) {
        $role | Add-Member -MemberType NoteProperty -Name "Start time" -Value "Permanent" -Force
        $role | Add-Member -MemberType NoteProperty -Name "End time"   -Value "Permanent" -Force
        $role | Add-Member -MemberType NoteProperty -Name "AssignmentType" -Value "Permanent" -Force
        $activeRole = @()
        $role | Add-Member -MemberType NoteProperty -Name "Activated for" -Value $null -Force
    }
    else {
        if ($isGroup) {
            if (-not ($role.PSObject.Properties.Name -contains 'Active group members')) {
                $role | Add-Member -MemberType NoteProperty -Name "Active group members" -Value @{} -Force
            }
            $activeMembersMap = $role.'Active group members'
            if (-not $activeMembersMap) { $activeMembersMap = @{} }

            $activeRole = @()
            if ($role.roleDefinitionId) {
                $activeRole = $roleactivations | Where-Object {
                    ($_.roleDefinitionId -eq $role.roleDefinitionId) -and
                    ($_.MemberType -eq "Group") -and
                    ($activeMembersMap.ContainsKey($_.principalId))
                }
            }
            $activatedFor = @($activeRole | ForEach-Object { $activeMembersMap[$_.principalId] }) -join ";"
            $role | Add-Member -MemberType NoteProperty -Name "Activated for" -Value $activatedFor -Force
        }
        else {
            $activeRole = @()
            if ($role.roleDefinitionId -and $role.PrincipalId) {
                $activeRole = $roleactivations | Where-Object {
                    ($_.roleDefinitionId -eq $role.roleDefinitionId) -and
                    ($_.PrincipalId -eq $role.PrincipalId)
                }
            }
            $role | Add-Member -MemberType NoteProperty -Name "Activated for" -Value $null -Force
        }

        $start = $activeRole | Select-Object -ExpandProperty startDateTime -ErrorAction Ignore | Sort-Object | Select-Object -First 1
        $end   = $activeRole | Select-Object -ExpandProperty endDateTime   -ErrorAction Ignore | Sort-Object -Descending | Select-Object -First 1

        $role | Add-Member -MemberType NoteProperty -Name "Start time"     -Value ($start ? (Get-Date $start -Format g) : $null) -Force
        $role | Add-Member -MemberType NoteProperty -Name "End time"       -Value ($end   ? (Get-Date $end   -Format g) : $null) -Force
        $role | Add-Member -MemberType NoteProperty -Name "AssignmentType" -Value ($start ? "Eligible (Active)" : "Eligible") -Force
    }

    # Principal details (display)
    $principalVal     = $role.PrincipalId
    $principalDisplay = $null
    if ($ptypeFull) {
        $aprops = $role.principal.AdditionalProperties
        $principalDisplay = $aprops.displayName
        switch ($ptypeFull) {
            '#microsoft.graph.user'             { if ($aprops.userPrincipalName) { $principalVal = $aprops.userPrincipalName } }
            '#microsoft.graph.servicePrincipal' { if ($aprops.appId)             { $principalVal = $aprops.appId } }
            '#microsoft.graph.group'            { $principalVal = $role.PrincipalId }
            default                             { $principalVal = $role.PrincipalId }
        }
    }
    $principalTypeShort = if ($ptypeFull) { $ptypeFull.Split(".")[-1] } else { $null }

    # Role definition
    $rd           = if ($role.PSObject.Properties.Name -contains 'roleDefinition1') { $role.roleDefinition1 } else { $null }
    $assignedRole = if ($rd) { $rd.displayName } else { $null }
    $isBuiltIn    = if ($rd) { $rd.isBuiltIn }   else { $null }
    $templateId   = if ($rd) { $rd.templateId }  else { $null }

    # Optional group member IDs
    $activeIds        = if ($role.PSObject.Properties.Name -contains 'Active group members IDs')   { $role.'Active group members IDs' }   else { $null }
    $eligibleIds      = if ($role.PSObject.Properties.Name -contains 'Eligible group members IDs') { $role.'Eligible group members IDs' } else { $null }
    $activatedForDisp = if ($role.PSObject.Properties.Name -contains 'Activated for')               { $role.'Activated for' }              else { $null }

    # Internal keys/flags
    $principalObjectId = $role.PrincipalId
    $roleDefId         = $role.roleDefinitionId
    $objId             = $role.Id
    $pagEligRead       = if ($role.PSObject.Properties.Name -contains 'PAGEligibleReadSucceeded') { $role.PAGEligibleReadSucceeded } else { $null }

    $line = [ordered]@{
        "Principal"                           = $principalVal
        "PrincipalDisplayName"                = $principalDisplay
        "PrincipalType"                       = $principalTypeShort
        "AssignedRole"                        = $assignedRole
        "AssignedRoleScope"                   = $role.directoryScopeId
        "AssignmentType"                      = $role.AssignmentType
        "AssignmentStartDate"                 = $role.'Start time'
        "AssignmentEndDate"                   = $role.'End time'
        "ActiveGroupMembers"                  = $activeIds
        "EligibleGroupMembers"                = $eligibleIds
        "GroupEligibleAssignmentActivatedFor" = $activatedForDisp
        "IsBuiltIn"                           = $isBuiltIn
        "RoleTemplate"                        = $templateId

        # Keys & tracking
        "PrincipalObjectId"                   = $principalObjectId
        "RoleDefinitionId"                    = $roleDefId
        "ObjectId"                            = $objId
        "PAGEligibleReadSucceeded"            = $pagEligRead
        "EligibleGroupMembersAdded"           = $null
        "EligibleGroupMembersRemoved"         = $null
        "LastUpdatedUtc"                      = $nowUtc
    }

    # Send to both collectors; PAG JSON will only include group-principal rows
    $reportPIM += [pscustomobject]$line
    if ($isGroup) {
        $reportPAG += [pscustomobject]$line
    }
}

# -------------------- MERGE (PAG only, from prior .data.js) --------------------
$pagPath   = Join-Path -Path $OutputFolder -ChildPath "AdministratorsReport-PAG.data.js"
$pagGlobal = 'PAG_REPORT'

# Add a safe null-check for $reportPAG before using .Count
if ($DoPAG -and $reportPAG -and $reportPAG.Count -gt 0) {

    $existingPAG    = Load-ExistingJs -path $pagPath -globalName $pagGlobal
    $existingPAGIdx = @{}

    if ($existingPAG) {
        foreach ($e in $existingPAG) {
            $k = Get-ReportKey $e
            if ($k) { $existingPAGIdx[$k] = $e }
        }
    }

    foreach ($cur in $reportPAG) {
        $key = Get-ReportKey $cur
        if (-not $key) { continue }

        $prev = $null
        if ($existingPAGIdx.ContainsKey($key)) { $prev = $existingPAGIdx[$key] }

        $curEligible  = Split-List $cur.EligibleGroupMembers
        $prevEligible = Split-List $(if ($prev) { $prev.EligibleGroupMembers } else { $null })

       
        $readSucceeded = [bool](
            ($cur.PSObject.Properties.Nameed -eq $true)
        )


        if ($readSucceeded) {
            # Compute added/removed deltas (defensively ignore null/empty tokens)
            $added   = @($curEligible  | Where-Object { $_ -and ($_ -notin $prevEligible) })
            $removed = @($prevEligible | Where-Object { $_ -and ($_ -notin $curEligible) })

            # Persist current eligible list and deltas
            $cur.EligibleGroupMembers        = if ($curEligible.Count) { Join-List $curEligible } else { $null }
            $cur.EligibleGroupMembersAdded   = if ($added.Count)       { Join-List $added }       else { $null }
            $cur.EligibleGroupMembersRemoved = if ($removed.Count)     { Join-List $removed }     else { $null }
        }
        else {
            # Preserve prior snapshot if current read failed
            if ($prev -and $prev.EligibleGroupMembers) {
                $cur.EligibleGroupMembers        = $prev.EligibleGroupMembers
                $cur.EligibleGroupMembersAdded   = $null
                $cur.EligibleGroupMembersRemoved = $null
            }
        }
    }
}

# -------------------- EXPORT JS FILES --------------------
$pimPath   = Join-Path -Path $OutputFolder -ChildPath "AdministratorsReport-PIM.data.js"
$pimGlobal = 'PIM_REPORT'
# $pagPath and $pagGlobal already defined above

if ($DoPIM) {
    Save-Js -data $reportPIM -path $pimPath -globalName $pimGlobal
}
if ($DoPAG) {
    Save-Js -data $reportPAG -path $pagPath -globalName $pagGlobal
}

# -------------------- END-OF-RUN SUMMARY (Verbose only) --------------------
$allPIM = @()
$allPAG = @()
if ($DoPIM) { $allPIM = $reportPIM }
if ($DoPAG) { $allPAG = $reportPAG }

# PIM breakdown
$pimPerm  = ($allPIM | Where-Object { $_.AssignmentType -eq 'Permanent' }).Count
$pimElig  = ($allPIM | Where-Object { $_.AssignmentType -eq 'Eligible' }).Count
$pimActv  = ($allPIM | Where-Object { $_.AssignmentType -eq 'Eligible (Active)' }).Count

# PAG breakdown
$pagReadSucceeded       = ($allPAG | Where-Object { $_.PAGEligibleReadSucceeded -eq $true }).Count
$pagReadFailedPreserved = ($allPAG | Where-Object { $_.PAGEligibleReadSucceeded -ne $true -and $_.EligibleGroupMembers }).Count
$changed = $allPAG | Where-Object { $_.PAGEligibleReadSucceeded -eq $true -and ( $_.EligibleGroupMembersAdded -or $_.EligibleGroupMembersRemoved ) }
$addedTotal   = ($changed | ForEach-Object { ($_.'EligibleGroupMembersAdded'   -split ';').Count }) | Measure-Object -Sum | Select-Object -ExpandProperty Sum
$removedTotal = ($changed | ForEach-Object { ($_.'EligibleGroupMembersRemoved' -split ';').Count }) | Measure-Object -Sum | Select-Object -ExpandProperty Sum

Write-Verbose ("==== Summary ({0}) ====" -f $LookupMode)
if ($DoPIM) {
    Write-Verbose ("PIM JS : {0} | Records: {1} | Permanent: {2}, Eligible: {3}, Eligible (Active): {4}" -f $pimPath, $allPIM.Count, $pimPerm, $pimElig, $pimActv)
}
if ($DoPAG) {
    Write-Verbose ("PAG JS : {0} | Records: {1} | Eligible read OK: {2}, Preserved from prior: {3}, Changed this run: {4} (+{5}/-{6})" -f `
        $pagPath, $allPAG.Count, $pagReadSucceeded, $pagReadFailedPreserved, $changed.Count, ($addedTotal ?? 0), ($removedTotal ?? 0))
    $preview = $changed | Select-Object -First 5 PrincipalDisplayName, AssignedRole, AssignedRoleScope, EligibleGroupMembersAdded, EligibleGroupMembersRemoved
    if ($preview) {
        Write-Verbose "Top changes (up to 5):"
        foreach ($p in $preview) {
            Write-Verbose ("- {0} | {1} | scope: {2} | +[{3}] -[{4}]" -f `
                ($p.PrincipalDisplayName ?? $p.Principal), `
                ($p.AssignedRole ?? $p.RoleDefinitionId), `
                $p.AssignedRoleScope, `
                ($p.EligibleGroupMembersAdded   ?? ''), `
                ($p.EligibleGroupMembersRemoved ?? ''))
        }
    }
}
Write-Verbose ("Last updated (UTC): {0:yyyy-MM-ddTHH:mm:ssZ}" -f (Get-Date).ToUniversalTime())
Write-Verbose "=============================="
