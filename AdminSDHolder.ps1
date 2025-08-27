$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectClass=user)(admincount=1))"
$searcher.PropertiesToLoad.Add("name") > $null
$searcher.PropertiesToLoad.Add("samaccountname") > $null
$searcher.PropertiesToLoad.Add("admincount") > $null
$searcher.PropertiesToLoad.Add("distinguishedname") > $null
$searcher.PropertiesToLoad.Add("useraccountcontrol") > $null
$searcher.PropertiesToLoad.Add("memberof") > $null
$results = $searcher.FindAll()

$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainName = $domain.Name -replace '\.', '_'
$total = $results.Count
$counter = 0
$output = @()

$highPrivGroupNames = @("Domain Admins", "Enterprise Admins", "Schema Admins")

foreach ($result in $results) {
    $counter++
    Write-Progress -Activity "Analyzing AdminSDHolder users..." `
                   -Status "Processing user $counter of $total" `
                   -PercentComplete (($counter / $total) * 100)
    
    $p = $result.Properties
    $userAccountControl = if($p["useraccountcontrol"].Count -gt 0) { $p["useraccountcontrol"][0] } else { 0 }
    $groups = if($p["memberof"].Count -gt 0) { $p["memberof"] -join "; " } else { "" }
    
    # High privilege check
    $isHighPriv = $false
    if ($groups -ne "") {
        foreach ($grpName in $highPrivGroupNames) {
            if ($groups -like "*$grpName*") { 
                $isHighPriv = $true
                break 
            }
        }
    }
    
    # Determine HighPrivilege status
    $highPrivStatus = if ($isHighPriv) { 
        "True"     # Confirmed high privilege
    } elseif ($groups -eq "") {
        "No Group Membership"    # Unknown (could be nested)
    } else { 
        "False"           # Has groups but not high privilege
    }
    
    $output += [PSCustomObject]@{
        Name = if($p["name"].Count -gt 0) { $p["name"][0] } else { "N/A" }
        SamAccountName = if($p["samaccountname"].Count -gt 0) { $p["samaccountname"][0] } else { "N/A" }
        HighPrivilege = $highPrivStatus
        DistinguishedName = if($p["distinguishedname"].Count -gt 0) { $p["distinguishedname"][0] } else { "N/A" }
        Groups = if($groups -eq "") { "No Groups" } else { $groups }
        UserAccountControl = $userAccountControl
        AdminCount = if($p["admincount"].Count -gt 0) { $p["admincount"][0] } else { "N/A" }
    }
}

# Exclude system accounts and disabled users
$filteredUsers = @()
foreach ($user in $output) {
    $isDisabled = ($user.UserAccountControl -band 2) -ne 0
    if ($user.SamAccountName -ne "krbtgt" -and
        $user.SamAccountName -ne "Administrator" -and
        -not $user.SamAccountName.EndsWith('$') -and
        -not $isDisabled) {
        $filteredUsers += $user
    }
}

$fileName = "adminsdholder_users_$domainName.csv"
$filteredUsers | Export-Csv -Path ".\$fileName" -NoTypeInformation -Encoding Unicode

Write-Host "=== ADMINSDHOLDER USER ANALYSIS ===" -ForegroundColor Yellow
Write-Host "Total users found: $($output.Count)" -ForegroundColor White
Write-Host "Users requiring review: $($filteredUsers.Count)" -ForegroundColor Green
Write-Host "CSV file saved with Unicode encoding: $fileName" -ForegroundColor Cyan

$filteredUsers | Format-Table -AutoSize
