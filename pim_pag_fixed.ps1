# Connect
Write-Output "Connecting to Graph"
#Connect-MgGraph -Identity -NoWelcome
Connect-MgGraph
Write-Output "Connected to Graph, running script"

# --- Collect role assignments and role defs ---
$roles  = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal
$roles1 = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty roleDefinition

# Map roleDefinition onto each role (key = RoleDefinitionId)
$roleDefById = @{}
foreach ($r in $roles1) {
    if ($r.roleDefinition) {
        $roleDefById[$r.roleDefinition.Id] = $r.roleDefinition
    }
}
foreach ($role in $roles) {
    $rd = $null
    if ($role.roleDefinitionId -and $roleDefById.ContainsKey($role.roleDefinitionId)) {
        $rd = $roleDefById[$role.roleDefinitionId]
    }
    Add-Member -InputObject $role -MemberType NoteProperty -Name roleDefinition1 -Value $rd -Force
}

# Include eligibilities (unify shape with roleDefinition1)
$roles += Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ExpandProperty roleDefinition,principal -Verbose:$false -ErrorAction Stop |
    Select-Object id,principalId,directoryScopeId,roleDefinitionId,status,principal,
        @{n="roleDefinition1";e={$_.roleDefinition}}

# Collect PIM activations
$roleactivations = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -Filter "AssignmentType eq 'Activated'" -Verbose:$false -ErrorAction Stop

# Mark duplicates (compare assignment Id to RoleAssignmentOriginId)
foreach ($act in $roleactivations) {
    $roles |
        Where-Object { $_.Id -eq $act.RoleAssignmentOriginId } |
        ForEach-Object { Add-Member -InputObject $_ -MemberType NoteProperty -Name "Duplicate" -Value $true -Force }
}

if (!$roles) { Write-Host "No valid role assignments found, verify the required permissions have been granted?"; return }

$rtemp = $roles | Where-Object { -not $_.Duplicate }
Write-Output "A total of $($rtemp.count) role assignments were found"
Write-Output "$(($rtemp | Where-Object {$_.directoryScopeId -eq "/"}).Count) are tenant-wide and $(($rtemp | Where-Object {$_.directoryScopeId -ne "/"}).Count) are AU-scoped."
Write-Output "$(($rtemp | Where-Object { -not $_.status }).Count) roles are permanently assigned, you might want to address that!"

# --- PAG group handling ---
$Proles = $roles | Where-Object { $_.Principal.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }
if (!$Proles) { Write-Host "No role assignments with Group principal found, skipping PAG collection" }

foreach ($role in $Proles) {
    Write-Host "Collecting Privileged Access Group members for $($role.PrincipalId) ..."

    # Active (transitive) members
    $dMembers   = @{}
    $dMembersId = @()
    $transitive = Get-MgGroupTransitiveMember -GroupId $role.PrincipalId -Property id,displayName,userPrincipalName -Verbose:$false -ErrorAction Stop
    foreach ($member in $transitive) {
        $upn = $member.AdditionalProperties.userPrincipalName
        $dMembers[$member.Id] = $upn
        if ($upn) { $dMembersId += $upn } else { $dMembersId += "$($member.AdditionalProperties.displayName) ($($member.Id))" }
    }
    $role | Add-Member -MemberType NoteProperty -Name "Active group members" -Value $dMembers -Force
    $role | Add-Member -MemberType NoteProperty -Name "Active group members IDs" -Value ($dMembersId -join ";") -Force

    # Eligible members (not expanding groups) — use $memberId, not $pid
    $eMembers   = @{}
    $eMembersId = @()
    $eligible   = Get-MgIdentityGovernancePrivilegedAccessGroupEligibilitySchedule -Filter "groupId eq '$($role.principalId)'" -ExpandProperty principal -Verbose:$false -ErrorAction Stop
    foreach ($member in $eligible) {
        $memberId = $member.principal.Id
        $upn      = $member.principal.AdditionalProperties.userPrincipalName
        $eMembers[$memberId] = $upn
        $eMembersId += ($upn ? $upn : "$($member.principal.AdditionalProperties.displayName) ($memberId)")
    }
    $role | Add-Member -MemberType NoteProperty -Name "Eligible group members" -Value $eMembers -Force
    $role | Add-Member -MemberType NoteProperty -Name "Eligible group members IDs" -Value ($eMembersId -join ";") -Force
}

# --- Build report ---
Write-Host "Preparing the output..."
$report = @()

foreach ($role in $roles) {
    if ($role.Duplicate) { continue }

    if (-not $role.status) {
        # Permanent assignment
        $role | Add-Member -MemberType NoteProperty -Name "Start time" -Value "Permanent" -Force
        $role | Add-Member -MemberType NoteProperty -Name "End time"   -Value "Permanent" -Force
        $role | Add-Member -MemberType NoteProperty -Name "AssignmentType" -Value "Permanent" -Force
    } else {
        # Eligible (maybe active)
        if ($role.principal.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group') {
            $activeRole = $roleactivations | Where-Object {
                ($_.roleDefinitionId -eq $role.roleDefinitionId) -and
                ($role."Active group members".ContainsKey($_.principalId)) -and
                ($_.MemberType -eq "Group")
            }
            $activatedFor = ($activeRole | ForEach-Object { $role."Active group members"[$_.principalId] }) -join ";"
            $role | Add-Member -MemberType NoteProperty -Name "Activated for" -Value $activatedFor -Force
        } else {
            $activeRole = $roleactivations | Where-Object {
                ($_.roleDefinitionId -eq $role.roleDefinitionId) -and ($_.PrincipalId -eq $role.PrincipalId)
            }
            $role | Add-Member -MemberType NoteProperty -Name "Activated for" -Value $null -Force
        }

        # Dates for activations (fix for &amp; HTML and selection)
        $start = $activeRole | Select-Object -ExpandProperty startDateTime -ErrorAction Ignore | Sort-Object | Select-Object -First 1
        $end   = $activeRole | Select-Object -ExpandProperty endDateTime   -ErrorAction Ignore | Sort-Object -Descending | Select-Object -First 1

        $role | Add-Member -MemberType NoteProperty -Name "Start time"     -Value ($start ? (Get-Date $start -Format g) : $null) -Force
        $role | Add-Member -MemberType NoteProperty -Name "End time"       -Value ($end   ? (Get-Date $end   -Format g) : $null) -Force
        $role | Add-Member -MemberType NoteProperty -Name "AssignmentType" -Value ($start ? "Eligible (Active)" : "Eligible") -Force
    }

    $principalVal = switch ($role.principal.AdditionalProperties.'@odata.type') {
        '#microsoft.graph.user'             { $role.principal.AdditionalProperties.userPrincipalName }
        '#microsoft.graph.servicePrincipal' { $role.principal.AdditionalProperties.appId }
        '#microsoft.graph.group'            { $role.principalId }
        default                             { $role.principalId }
    }

    $reportLine = [ordered]@{
        "Principal"                           = $principalVal
        "PrincipalDisplayName"                = $role.principal.AdditionalProperties.displayName
        "PrincipalType"                       = $role.principal.AdditionalProperties.'@odata.type'.Split(".")[-1]
        "AssignedRole"                        = $role.roleDefinition1.displayName
        "AssignedRoleScope"                   = $role.directoryScopeId
        "AssignmentType"                      = $role.AssignmentType
        "AssignmentStartDate"                 = $role.'Start time'
        "AssignmentEndDate"                   = $role.'End time'
        "ActiveGroupMembers"                  = $role.'Active group members IDs'
        "EligibleGroupMembers"                = $role.'Eligible group members IDs'
        "GroupEligibleAssignmentActivatedFor" = $role.'Activated for'
        "IsBuiltIn"                           = $role.roleDefinition1.isBuiltIn
        "RoleTemplate"                        = $role.roleDefinition1.templateId
    }
    $report += [pscustomobject]$reportLine
}

# --- Export CSV ---
$filename = "AdministratorsReport.csv"
$AttachmentPath = Join-Path -Path (Get-Location) -ChildPath $filename
$report | Sort-Object PrincipalDisplayName | Export-Csv $AttachmentPath -NoTypeInformation -Encoding UTF8
$MessageAttachment = [Convert]::ToBase64String([IO.File]::ReadAllBytes($AttachmentPath))

# --- Email details ---
$from    = "sendingaddress@something.com" # Sender UPN or UserId with mailbox & Mail.Send
$subject = "Administrator Accounts"
$type    = "HTML"
$save    = $true
$EmailBody = @"
<h2>Administrator Accounts Report</h2>
<p>Please find the attached CSV export.</p>
<p>Total records: $($report.Count)</p>
"@

$params = @{
    Message = @{
        Subject = $subject
        Body    = @{
            ContentType = $type
            Content     = $EmailBody
        }
        ToRecipients = @(
            @{ EmailAddress = @{ Address = "receivingaddress@something.com" } }
        )
        Attachments = @(
            @{
                "@odata.type" = "#microsoft.graph.fileAttachment"
                Name          = $filename
                ContentType   = "text/csv"
                ContentBytes  = $MessageAttachment
            }
        )
    }
    SaveToSentItems = $save
}

# Send message
#Send-MgUserMail -UserId $from -BodyParameter $params
Write-Output "Email sent to recipients with attachment: $filename"
