# OAuthHunting

By Doug Bienstock [(@doughsec)](https://twitter.com/doughsec)

A collection of scripts to help administrators hunt for malicious OAuth applications in cloud environments. Looks for granting of suspicious scopes, frequency of grants, and hopefully a whitelist/blacklist as time goes on.

# Scripts

## get-suspiciousoauth.ps1

Requires to be run as an Office 365 Global Admin. Queries the tenant for all OAuthPermission grants and filters them for suspicious entries.

### Arguments

`-All` returns All OAuthPermissionGrants

`-Scopes` A comma separated list of suspicious scopes to look for. Defaults to "offline_access"

`-Threshold` The number of grants in a tenant below which an application is considered suspicious. This is filtered as an OR condition with the scopes parameter.

`-Output` Outputs results to CSV

`-OutputPath` Where to write the CSV
