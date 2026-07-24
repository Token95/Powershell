<#
Author: Devon Brown
Lab: Active Directory identity and compliance audit

Purpose:
This script imports the active directory module, verifies domain
connectivity, identifies enabled user accounts that have been inactive
for at least 90 days, reviews privileged group membership, flags
potential non-compliance, exports the findings to ad_audit.csv, and
creates a summary file named ad_summary.txt.

Important:
this script performs read-only active directory auditing.
it does not disable accounts or remove group members.
#>

clear-host

# ------------------------------------------------------------
# LAB INFORMATION
# ------------------------------------------------------------

write-host "starting active directory compliance audit..." -foregroundcolor cyan
write-host "student: devon brown" -foregroundcolor green
write-host "------------------------------------------------------------"


# ------------------------------------------------------------
# SCRIPT SETTINGS
# ------------------------------------------------------------

# determine the folder where the powershell script is stored.
# the csv report and summary file will be saved in this folder.

$scriptfolder = split-path -parent $myinvocation.mycommand.path

# define the output file locations.

$csvfile = join-path $scriptfolder "ad_audit.csv"
$summaryfile = join-path $scriptfolder "ad_summary.txt"

# define the inactivity threshold required by the assignment.

$stalethresholddays = 90

# calculate the date that separates active accounts from stale accounts.

$stalecutoffdate = (get-date).adddays(-$stalethresholddays)

# list the privileged groups that will be reviewed.
# these are common high-impact active directory groups.

$privilegedgroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Backup Operators"
)

# define the accounts that are authorized to hold privileged access.
#
# update this list to match the approved administrative accounts
# in your lab environment or instructor-provided scenario.

$approvedprivilegedaccounts = @(
    "administrator",
    "your-approved-admin-account"
)

# create an empty collection that will hold every audit result.

$auditresults = @()


# ------------------------------------------------------------
# IMPORT ACTIVE DIRECTORY MODULE
# ------------------------------------------------------------

try {

    write-host "importing the active directory module..." -foregroundcolor cyan

    # stop produces an exception if the module cannot be imported.
    # this allows the catch block to display a clear error.
    import-module activedirectory -erroraction stop

    write-host "active directory module imported successfully." `
        -foregroundcolor green
}
catch {

    write-host "active directory module could not be imported." `
        -foregroundcolor red

    write-host "error: $($_.exception.message)" `
        -foregroundcolor red

    write-host ""
    write-host "verify that rsat active directory tools are installed." `
        -foregroundcolor yellow

    exit
}


# ------------------------------------------------------------
# CONFIRM DOMAIN CONNECTIVITY
# ------------------------------------------------------------

try {

    write-host "checking active directory domain connectivity..." `
        -foregroundcolor cyan

    # get-addomain confirms that the computer can contact
    # active directory and retrieve the current domain.

    $domain = get-addomain -erroraction stop

    # locate an available domain controller.

    $domaincontroller = get-addomaincontroller `
        -discover `
        -erroraction stop

    write-host "domain connection successful." -foregroundcolor green
    write-host "domain: $($domain.dnsroot)"
    write-host "domain controller: $($domaincontroller.hostname)"
    write-host "------------------------------------------------------------"
}
catch {

    write-host "active directory domain connectivity failed." `
        -foregroundcolor red

    write-host "error: $($_.exception.message)" `
        -foregroundcolor red

    write-host ""
    write-host "verify that:" -foregroundcolor yellow
    write-host "1. the computer is connected to the company network or vpn."
    write-host "2. the computer is joined to or can reach the domain."
    write-host "3. dns can resolve the domain controller."
    write-host "4. your account has permission to query active directory."

    exit
}


# ------------------------------------------------------------
# ENUMERATE AND FLAG STALE ACCOUNTS
# ------------------------------------------------------------

write-host "reviewing enabled user accounts..." -foregroundcolor cyan
write-host "stale account threshold: $stalethresholddays days"
write-host "cutoff date: $stalecutoffdate"

try {

    # retrieve all enabled users and request the properties
    # needed for the account audit.

    $users = get-aduser `
        -filter "Enabled -eq 'True'" `
        -properties lastlogondate, created, passwordlastset, description `
        -erroraction stop

    foreach ($user in $users) {

        # assume the user is compliant unless a stale condition is found.

        $status = "Compliant"
        $finding = "Enabled account has recent logon activity."

        # an account with no last logon date may never have been used.
        # it should still be reviewed as potentially stale.

        if ($null -eq $user.lastlogondate) {

            $status = "Review Required"
            $finding = "Enabled account has no recorded last logon date."
        }

        # flag users whose last logon date is older than 90 days.

        elseif ($user.lastlogondate -lt $stalecutoffdate) {

            $status = "Non-Compliant"
            $finding = "Enabled account has been inactive for 90 or more days."
        }

        # add the user audit result to the report collection.

        $auditresults += [pscustomobject]@{
            "Audit Type"       = "User Account"
            "Name"             = $user.name
            "Username"         = $user.samaccountname
            "Group"            = ""
            "Enabled"          = $user.enabled
            "Last Logon"       = $user.lastlogondate
            "Days Inactive"    = if ($user.lastlogondate) {
                [math]::floor(
                    ((get-date) - $user.lastlogondate).totaldays
                )
            }
            else {
                "Never"
            }
            "Compliance Status" = $status
            "Finding"           = $finding
        }
    }

    write-host "user accounts reviewed: $($users.count)" `
        -foregroundcolor green
}
catch {

    write-host "user account enumeration failed." -foregroundcolor red
    write-host "error: $($_.exception.message)" -foregroundcolor red
}


# ------------------------------------------------------------
# REVIEW PRIVILEGED GROUP MEMBERSHIP
# ------------------------------------------------------------

write-host "------------------------------------------------------------"
write-host "reviewing privileged group membership..." -foregroundcolor cyan


foreach ($groupname in $privilegedgroups) {

    try {

        # Confirm that the privileged group exists.
        $group = get-adgroup `
            -identity $groupname `
            -erroraction stop

        # Retrieve direct and nested group members.
        $members = get-adgroupmember `
            -identity $group `
            -recursive `
            -erroraction stop

        write-host "$groupname members found: $(@($members).count)"

        foreach ($member in $members) {

            # Default to non-compliant until the account is confirmed
            # against the approved privileged account list.
            $status = "Non-Compliant"
            $finding = "Privileged member is not listed as an approved account."

            # Mark approved accounts as compliant.
            if ($approvedprivilegedaccounts -contains $member.samaccountname) {
                $status = "Compliant"
                $finding = "Privileged member is listed as approved."
            }

            # Nested groups should be reviewed separately.
            if ($member.objectclass -eq "group") {
                $status = "Review Required"
                $finding = "Nested privileged group requires manual review."
            }

            # Add one report object for each privileged member.
            $auditresults += [pscustomobject]@{
                "Audit Type"        = "Privileged Membership"
                "Name"              = $member.name
                "Username"          = $member.samaccountname
                "Group"             = $groupname
                "Enabled"           = ""
                "Last Logon"        = ""
                "Days Inactive"     = ""
                "Compliance Status" = $status
                "Finding"           = $finding
            }
        }
    }
    catch {

        write-host "could not review group: $groupname" `
            -foregroundcolor yellow

        write-host "reason: $($_.exception.message)" `
            -foregroundcolor darkyellow

        # Add unavailable or failed groups to the audit report.
        $auditresults += [pscustomobject]@{
            "Audit Type"        = "Privileged Group"
            "Name"              = $groupname
            "Username"          = ""
            "Group"             = $groupname
            "Enabled"           = ""
            "Last Logon"        = ""
            "Days Inactive"     = ""
            "Compliance Status" = "Review Required"
            "Finding"           = "Group could not be queried or does not exist."
        }
    }
}

# ------------------------------------------------------------
# EXPORT AUDIT RESULTS TO CSV
# ------------------------------------------------------------

try {

    $auditresults |
        sort-object "Audit Type", "Compliance Status", Name |
        export-csv `
            -path $csvfile `
            -notypeinformation `
            -encoding utf8 `
            -force

    write-host "------------------------------------------------------------"
    write-host "csv audit report created successfully." `
        -foregroundcolor green

    write-host "report location: $csvfile" `
        -foregroundcolor yellow
}
catch {

    write-host "csv export failed." -foregroundcolor red
    write-host "error: $($_.exception.message)" -foregroundcolor red
}


# ------------------------------------------------------------
# CALCULATE SUMMARY TOTALS
# ------------------------------------------------------------

$totalusers = @(
    $auditresults |
        where-object {
            $_."Audit Type" -eq "User Account"
        }
).count

$staleaccounts = @(
    $auditresults |
        where-object {
            $_."Audit Type" -eq "User Account" -and
            $_."Compliance Status" -eq "Non-Compliant"
        }
).count

$neverloggedon = @(
    $auditresults |
        where-object {
            $_."Audit Type" -eq "User Account" -and
            $_."Days Inactive" -eq "Never"
        }
).count

$privilegedmembers = @(
    $auditresults |
        where-object {
            $_."Audit Type" -eq "Privileged Membership"
        }
).count

$noncompliantprivileged = @(
    $auditresults |
        where-object {
            $_."Audit Type" -eq "Privileged Membership" -and
            $_."Compliance Status" -eq "Non-Compliant"
        }
).count

$reviewrequired = @(
    $auditresults |
        where-object {
            $_."Compliance Status" -eq "Review Required"
        }
).count


# ------------------------------------------------------------
# CREATE SUMMARY
# ------------------------------------------------------------

$summary = @"
ACTIVE DIRECTORY COMPLIANCE AUDIT SUMMARY
Student: Devon Brown
Audit Date: $(get-date -format "yyyy-MM-dd HH:mm:ss")

Domain: $($domain.dnsroot)
Domain Controller: $($domaincontroller.hostname)
Stale Account Threshold: $stalethresholddays days

RESULTS
------------------------------------------------------------
Enabled User Accounts Reviewed: $totalusers
Stale Enabled Accounts: $staleaccounts
Accounts With No Last Logon: $neverloggedon
Privileged Memberships Reviewed: $privilegedmembers
Non-Compliant Privileged Members: $noncompliantprivileged
Items Requiring Manual Review: $reviewrequired

OUTPUT FILES
------------------------------------------------------------
CSV Report: $csvfile
Summary File: $summaryfile

IMPORTANT
------------------------------------------------------------
This audit is read-only. Accounts marked as non-compliant or requiring
review should be validated against the organization's approved account
and privileged-access records before any administrative action is taken.
"@

try {

    write-host "------------------------------------------------------------"
    write-host $summary -foregroundcolor cyan

    $summary |
        out-file `
            -filepath $summaryfile `
            -encoding utf8 `
            -force

    write-host "summary file created successfully." `
        -foregroundcolor green

    write-host "summary location: $summaryfile" `
        -foregroundcolor yellow
}
catch {

    write-host "summary file creation failed." -foregroundcolor red
    write-host "error: $($_.exception.message)" -foregroundcolor red
}

write-host "------------------------------------------------------------"
write-host "active directory compliance audit completed." `
    -foregroundcolor green

    
