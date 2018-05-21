
function Get-SuspiciousOAuthGrants {
    <#
    .SYNOPSIS

        Searches Azure AD for suspicious user OAuth Grants

        Author: Douglas Bienstock (@doughsec)
        License: GPL 3.0
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        When a user consents to an OAuth application in Office365 it creates
        an OAuth "grant" associated with that user's account and the Service
        Principal Object of the application that resides in that user's tenant. 
        This function searches for those OAuth grants, attempting to find
        suspicious grants based on certain characteristics.

    .PARAMETER All

        Boolean. Specifies if you want to return all OAuth grants in the tenant

    .PARAMETER Scopes

        A list of suspicious scopes to search for. Defaults to "offline_access" only.

    .PARAMETER Threshold

        A Service Principal with fewer OAuth grants than the Threshold is considered
        suspicious automatically. Set to a number that represents a small percentage of
        your tenant total user count. Defaults to 10.

    
#>

    param(
        [Switch]
        $All,

        [String[]]
        $Scopes = @("offline_access"),

        [Int]
        $Threshold = 10,

        [Switch]
        $Output,

        [String]
        $OutputPath= "suspicious grants.csv"
    )

    try { 
        $var = Get-AzureADTenantDetail;
    } catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
        Connect-AzureAd;
    }

    $tenantWhitelist = @(
        "f8cdef31-a31e-4b4a-93e4-5f571e91255a" #the Microsoft Services tenant. Where a lot of O365 services live
    )

    Get-AzureADServicePrincipal  | Where-Object { !$tenantWhitelist.contains( $_.AppOwnerTenantID ) } | ForEach-Object {
        $spn = $_;
        $objID = $spn.ObjectID;
        $grants = Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $objID;

        $suspicious = $FALSE;

        # If the SPN has fewer OAuth grants than the threshold, we mark all the grants as suspicious
        if($grants.length -lt $Threshold) { $suspicious= $TRUE; }

        if($grants) {
 
            foreach ($grant in $grants) {
                if($All) {
                    $user = Get-AzureADUser -ObjectId $grant.PrincipalId;

                    $userGrant = New-Object PSObject;
                    $userGrant | Add-Member Noteproperty 'ObjectID' $grant.objectId;
                    $userGrant | Add-Member Noteproperty 'User' $user.UserPrincipalName;
                    $userGrant | Add-Member Noteproperty 'AppDisplayName' $spn.DisplayName;
                    $userGrant | Add-Member Noteproperty 'AppPublisherName' $spn.PublisherName;
                    $userGrant | Add-Member Noteproperty 'AppReplyURLs' $spn.ReplyUrls;
                    $userGrant | Add-Member Noteproperty 'GrantConsentType' $grant.consentType;
                    $userGrant | Add-Member Noteproperty 'GrantScopes' $grant.scope;

                    Write-Output $userGrant;

                    if($Output) {
                        $userGrant | Export-CSV -notypeinformation -append $OutputPath;
                    }
                }
                
                # If any of the suspicious scopes are part of this grant, we mark it as suspicious
                foreach($scope in $Scopes) {
                    if($grant.scope.contains($scope)) {
                        $suspicious= $TRUE;
                        break;
                    }
                }

                # If the SPN was granted to all users via an admin we ignore it as legit
                if($grant.consentType -eq "AllPrincipals") {
                    $suspicious= $FALSE;
                }
                
                if(!$All -and $suspicious -eq $TRUE ) {
                    $user = Get-AzureADUser -ObjectId $grant.PrincipalId;

                    $userGrant = New-Object PSObject;
                    $userGrant | Add-Member Noteproperty 'User' $user.UserPrincipalName;
                    $userGrant | Add-Member Noteproperty 'AppDisplayName' $spn.DisplayName;
                    $userGrant | Add-Member Noteproperty 'AppPublisherName' $spn.PublisherName;
                    $userGrant | Add-Member Noteproperty 'AppReplyURLs' $spn.ReplyUrls;
                    $userGrant | Add-Member Noteproperty 'GrantConsentType' $grant.consentType;
                    $userGrant | Add-Member Noteproperty 'GrantScopes' $grant.scope;

                    Write-Output $userGrant;

                    if($Output) {
                        $userGrant | Export-CSV -notypeinformation -append $OutputPath;
                    }
                }
                
                
            }
               
        }
    }

}
