#########################################################################
#
# TITLE: PSUtils PowerShell Module
# DESCRIPTION: Provides a set of useful utilities
# AUTHOR: fr3dd
# VERSION: 1.1
# NOTES: Import-Module -Name PSUtils
#
#Requires -Version 5.1
#
#########################################################################

[CmdletBinding()]
Param()

#region Active Directory Domain Services Cmdlets

<#
.SYNOPSIS
    Used to add an additional attribute value in an attribute on an Active Directory object.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to update Active Directory
    object attributes where the ActiveDirectory module is not available or desired.
.PARAMETER DistinguishedName
    This is an mandatory parameter which specifies the exact distinguishedName of the
    target object to update.
.PARAMETER AttributeName
    This is a mandatory parameter which defines the attribute name on the target Active 
    Directory object to add values to.
.PARAMETER AttributeValue
    This is a mandatory parameter which defines the additional value that should be added
    to the defined attribute on the target Active Directory object.
.PARAMETER Server
    This is an optional parameter which specifies the target Domain Controller to leverage
    for the object update.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the search.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether an object was updated or not.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $testUser = Get-ADDSUser -Identity 'testuser';
    Add-ADDSMultivalueAttribute -DistinguishedName $testUser.distinguishedName -AttributeName 'proxyAddresses' -AttributeValue 'smtp:jdoe@company.com';

    The preceding example searches for a user called 'testuser' on the Domain Controller named 'DC1' using 
    the credentials stored in $creds. Once that object is returned, the 'smtp:jdoe@company.com' is added
    to the 'proxyAddresses' attribute.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Add-ADDSMultivalueAttribute {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the object distinguished name' )]
        [String] $DistinguishedName,

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the AD DS Domain Controller name to use' )]
        [String] $Server = '',

        [Parameter( Position = 2, Mandatory = $true, HelpMessage = 'Enter the attribute name' )]
        [String] $AttributeName,

        [Parameter( Position = 3, Mandatory = $true, HelpMessage = 'Enter the additional attribute value' )]
        [String] $AttributeValue,

        [Parameter( Position = 4, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: Add-ADDSMultivalueAttribute';
        Write-Verbose -Message ( " -DistinguishedName = {0}" -f $DistinguishedName );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -AttributeName = {0}" -f $AttributeName );
        Write-Verbose -Message ( " -AttributeValue = {0}" -f $AttributeValue );

        if ( $null -ne $Credential ) {
            Write-Verbose -Message ( " -Credential.UserName = {0}" -f $Credential.UserName );
        }

        [String] $bindString = '';
        [Hashtable] $Script:attributeTypes = @{
            'member' = 'DistinguishedName'
            'proxyAddresses' = 'String'
            'servicePrincipalName' = 'String'
            'uid' = 'String'
        }
    }
    Process { }
    End {
        try {
            if ( [regex]::Match( $DistinguishedName, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                if ( $Server -eq '' ) {
                    $bindString = "LDAP://{0}/{1}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name, $DistinguishedName;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f $Server, $DistinguishedName;
                }
                Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );
    
                if ( $null -eq $Credential ) {
                    $de = New-Object System.DirectoryServices.DirectoryEntry( $bindString );
                } else {
                    $de = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $Credential.UserName, ( $Credential.GetNetworkCredential().Password ), [DirectoryServices.AuthenticationTypes]::Secure );
                }
    
                if ( $null -ne $de.distinguishedName ) {
                    Write-Verbose -Message 'An object was found at the specified path';

                    if ( $de.Properties.Contains( $AttributeName ) ) {
                        Write-Verbose -Message ( "The attribute named {0} is present" -f $AttributeName );

                        if ( $Script:attributeTypes[ $key ] -eq 'DistinguishedName' ) {
                            Write-Verbose -Message ( "The attribute named {0} expects a distinguishedName value" -f $AttributeName );
                            if ( [regex]::Match( $AttributeValue, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                                Write-Verbose -Message 'Verify that the value does not already exist within the attribute';
                                if ( $de.Properties[ $AttributeName ].Values.Contains( $AttributeValue ) ) {
                                    Write-Warning -Message ( "The following value is already set on the attribute: {0}" -f $AttributeValue );
                                } else {
                                    Write-Verbose -Message ( "Add '{0}' to attribute {1}" -f $AttributeValue, $AttributeName );
                                    try {
                                        $de.Properties[ $AttributeName ].Values.Add( $AttributeValue );
                                        $de.CommitChanges();
                                    }
                                    catch {
                                        Write-Warning -Message 'Failed to set attribute value. Please check your permissions.';
                                    }
                                }
                            } else {
                                Write-Warning -Message ( "The following value is not a recognized distinguishedName: {0}" -f $AttributeValue );
                            }
                        } else {
                            Write-Verbose -Message 'The attribute is assumed to be a string';
                            if ( $de.Properties[ $AttributeName ].Values.Contains( $AttributeValue ) ) {
                                Write-Warning -Message ( "The following value is already set on the attribute: {0}" -f $AttributeValue );
                            } else {
                                Write-Verbose -Message ( "Add '{0}' to attribute {1}" -f $AttributeValue, $AttributeName );
                                try {
                                    $de.Properties[ $AttributeName ].Values.Add( $AttributeValue );
                                    $de.CommitChanges();
                                }
                                catch {
                                    Write-Warning -Message 'Failed to set attribute value. Please check your permissions.';
                                }
                            }
                        }
                    } else {
                        Write-Verbose -Message ( "The attribute named '{0}' does not currently have a value" -f $AttributeName );
                        Write-Verbose -Message ( "Add '{0}' to attribute {1}" -f $AttributeValue, $AttributeName );
                        try {
                            $de.Properties[ $AttributeName ].Values.Add( $AttributeValue );
                            $de.CommitChanges();
                        }
                        catch {
                            Write-Warning -Message 'Failed to set attribute value. Please check your permissions.';
                        }
                    }
                } else {
                    Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
                }
            } else {
                Write-Warning -Message ( "The following is not a proper distinguished name value: {0}" -f $DistinguishedName );
            }
        } catch { } # Throw away the error because it is false anyway
    }
}

<#
.SYNOPSIS
    Used to add an Active Directory Domain Services account into a local machine group
.DESCRIPTION

.PARAMETER ComputerName
    This is the target Windows machine name that has the group to be added to.
.PARAMETER LocalGroupName
    This is the local group name on the target machine to add an domain principal to.
.PARAMETER DomainName
    This is the NetBIOS domain name of the domain principal to be added into the defined local group.
.PARAMETER PrincipalName
    This is the account or group name in the specified domain to be added to the defined local group.
.PARAMETER PrincipalType
    This defines the type of account that is to be added to the local machine group. This defaults to user as that is the most common scenario.
.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS
    None.
.EXAMPLE
    Add-ADDSPrincipalToLocalGroup -ComputerName 'SERVER1' -LocalGroupName 'Administrators' -DomainName 'MYDOMAIN' -PrincipalName 'joeuser' -PrincipalType 'user'
.LINK
    https://github.com/fr3dd/PSUtils.git
.NOTES
    Author: fr3dd
    Version: 1.0.0
#>

function Add-ADDSPrincipalToLocalGroup {
    [CmdletBinding()]
    Param(
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the target server name' )]
        [String] $ComputerName,

        [Parameter( Position = 1, Mandatory = $true, HelpMessage = 'Enter the local group name to update' )]
        [String] $LocalGroupName,

        [Parameter( Position = 2, Mandatory = $true, HelpMessage = 'Enter the NetBIOS name for the domain' )]
        [String] $DomainName,

        [Parameter( Position = 3, Mandatory = $true, HelpMessage = 'Enter the account name of the domain object' )]
        [String] $PrincipalName,

        [Parameter( Position = 4, Mandatory = $false, HelpMessage = 'Enter the AD DS object type' )]
        [ValidateSet( 'computer', 'group', 'user' )]
        [String] $PrincipalType = 'user'
    )

    Write-Verbose -Message 'Cmdlet: Add-ADDSPrincipalToLocalGroup';
    Write-Verbose -Message ( " -ComputerName = {0}" -f $ComputerName );
    Write-Verbose -Message ( " -LocalGroupName = {0}" -f $LocalGroupName );
    Write-Verbose -Message ( " -DomainName = {0}" -f $DomainName );
    Write-Verbose -Message ( " -PrincipalName = {0}" -f $PrincipalName );
    Write-Verbose -Message ( " -PrincipalType = {0}" -f $PrincipalType );

    $serverConnectionPath = "WinNT://{0}/{1},group" -f $ComputerName, $LocalGroupName;
    Write-Verbose -Message ( "`$serverConnectionPath = {0}" -f $serverConnectionPath );

    try {
        Write-Verbose -Message 'Connecting to machine and specified group';
        $winNTGroup = [ADSI] $serverConnectionPath;
    } catch {
        Write-Warning -Message 'Unable to connect to the specified machine and group combination';
        break;
    }

    $domainConnectionPath = "WinNT://{0}/{1},{2}" -f $DomainName, $PrincipalName, $PrincipalType;
    Write-Verbose -Message ( "`$domainConnectionPath = {0}" -f $domainConnectionPath );

    try {
        Write-Verbose -Message 'Connecting to domain and specified security principal';
        $winNTDomainPrincipal = [ADSI] $domainConnectionPath;
    } catch {
        Write-Warning -Message 'Unable to connect to the specified domain and principal combination';
        break;
    }

    try {
        Write-Verbose -Message 'Adding domain security principal to the local server group';
        $winNTGroup.Add( $winNTDomainPrincipal.Path );
    } catch {
        Write-Warning -Message 'Failed to add domain security principal to local group';
    }
}

<#
.SYNOPSIS
    Used to clear an attribute value on an Active Directory object.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to update Active Directory
    object attributes where the ActiveDirectory module is not available or desired.
.PARAMETER DistinguishedName
    This is an mandatory parameter which specifies the exact distinguishedName of the
    target object to update.
.PARAMETER AttributeName
    This is a mandatory parameter which defines the attribute name that should be cleared
    on the target Active Directory object.
.PARAMETER Server
    This is an optional parameter which specifies the target Domain Controller to leverage
    for the object update.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the search.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether an object was updated or not.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $testUser = Get-ADDSUser -Identity 'testuser';
    Clear-ADDSAttribute -DistinguishedName $testUser.distinguishedName -AttributeName 'adminDescription';

    The preceding example searches for a user called 'testuser' on the Domain Controller named 'DC1' using 
    the credentials stored in $creds. Once that object is returned, the 'adminDescription' is cleared.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Clear-ADDSAttribute {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the object distinguished name' )]
        [String] $DistinguishedName,

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the AD DS Domain Controller name to use' )]
        [String] $Server = '',

        [Parameter( Position = 2, Mandatory = $true, HelpMessage = 'Enter the attribute name to clear' )]
        [String] $AttributeName,

        [Parameter( Position = 3, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: Clear-ADDSAttribute';
        Write-Verbose -Message ( " -DistinguishedName = {0}" -f $DistinguishedName );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -AttributeName = {0}" -f $AttributeName );

        if ( $null -ne $Credential ) {
            Write-Verbose -Message ( " -Credential.UserName = {0}" -f $Credential.UserName );
        }

        [String] $bindString = '';
        [Hashtable] $Script:attributeTypes = @{
            'accountExpires' = 'IADsLargeInteger'
            'adminCount' = 'Int32'
            'adminDescription' = 'SingleValueString'
            'c' = 'SingleValueString'
            'cn' = 'SingleValueString'
            'co' = 'SingleValueString'
            'comment' = 'SingleValueString'
            'company' = 'SingleValueString'
            'countryCode' = 'SingleValueString'
            'deliverAndRedirect' = 'Boolean'
            'department' = 'SingleValueString'
            'description' = 'SingleValueString'
            'directReports' = 'MultiValueString'
            'displayName' = 'SingleValueString'
            'division' = 'SingleValueString'
            'dNSHostName' = 'SingleValueString'
            'employeeID' = 'SingleValueString'
            'employeeNumber' = 'SingleValueString'
            'employeeType' = 'SingleValueString'
            'extensionAttribute1' = 'SingleValueString'
            'extensionAttribute2' = 'SingleValueString'
            'extensionAttribute3' = 'SingleValueString'
            'extensionAttribute4' = 'SingleValueString'
            'extensionAttribute5' = 'SingleValueString'
            'extensionAttribute6' = 'SingleValueString'
            'extensionAttribute7' = 'SingleValueString'
            'extensionAttribute8' = 'SingleValueString'
            'extensionAttribute9' = 'SingleValueString'
            'extensionAttribute10' = 'SingleValueString'
            'extensionAttribute11' = 'SingleValueString'
            'extensionAttribute12' = 'SingleValueString'
            'extensionAttribute13' = 'SingleValueString'
            'extensionAttribute14' = 'SingleValueString'
            'extensionAttribute15' = 'SingleValueString'
            'facsimileTelephoneNumber' = 'SingleValueString'
            'gidNumber' = 'Int32'
            'groupType' = 'Int32'
            'givenName' = 'SingleValueString'
            'homeDirectory' = 'SingleValueString'
            'homeDrive' = 'SingleValueString'
            'homeMDB' = 'SingleValueString'
            'info' = 'SingleValueString'
            'initials' = 'SingleValueString'
            'isCriticalSystemObject' = 'Boolean'
            'l' = 'SingleValueString'
            'legacyExchangeDN' = 'SingleValueString'
            'lockoutTime' = 'IADsLargeInteger'
            'loginShell' = 'SingleValueString'
            'logonCount' = 'Int32'
            'mDBOverQuotaLimit' = 'Int32'
            'mDBStorageQuota' = 'Int32'
            'mDBUseDefaults' = 'Boolean'
            'mail' = 'SingleValueString'
            'mailNickname' = 'SingleValueString'
            'managedBy' = 'SingleValueString'
            'manager' = 'SingleValueString'
            'mobile' = 'SingleValueString'
            'ms-DS-ConsistencyGuid' = 'GUID'
            'msExchArchiveGUID' = 'GUID'
            'msExchArchiveName' = 'SingleValueString'
            'msExchArchiveStatus' = 'Int32'
            'msExchAssistantName' = 'SingleValueString'
            'msExchEnableModeration' = 'Boolean'
            'msExchHideFromAddressLists' = 'Boolean'
            'msExchHomeServerName' = 'SingleValueString'
            'msExchLitigationHoldDate' = 'DateTime'
            'msExchLitigationHoldOwner' = 'SingleValueString'
            'msExchMailboxGuid' = 'GUID'
            'msExchMasterAccountSid' = 'StringSID'
            'msExchRecipientDisplayType' = 'Int32'
            'msExchRecipientTypeDetails' = 'IADsLargeInteger'
            'msExchRemoteRecipientType' = 'IADsLargeInteger'
            'msExchResourceCapacity' = 'Int32'
            'msExchResourceDisplay' = 'SingleValueString'
            'msExchUsageLocation' = 'SingleValueString'
            'msExchVersion' = 'IADsLargeInteger'
            'msNPAllowDialin' = 'Boolean'
            'msRTCSIP-FederationEnabled' = 'Boolean'
            'msRTCSIP-PrimaryHomeServer' = 'SingleValueString'
            'msRTCSIP-PrimaryUserAddress' = 'SingleValueString'
            'msRTCSIP-UserEnabled' = 'Boolean'
            'msSFU30NisDomain' = 'SingleValueString'
            'o' = 'SingleValueString'
            'operatingSystem' = 'SingleValueString'
            'operatingSystemVersion' = 'SingleValueString'
            'pager' = 'SingleValueString'
            'physicalDeliveryOfficeName' = 'SingleValueString'
            'postalCode' = 'SingleValueString'
            'postOfficeBox' = 'SingleValueString'
            'proxyAddresses' = 'MultiValueString'
            'pwdLastSet' = 'IADsLargeInteger'
            'sAMAccountName' = 'SingleValueString'
            'scriptPath' = 'SingleValueString'
            'servicePrincipalName' = 'MultiValueString'
            'shadowExpire' = 'Int32'
            'shadowFlag' = 'Int32'
            'shadowInactive' = 'Int32'
            'shadowLastChange' = 'Int32'
            'shadowMax' = 'Int32'
            'shadowMin' = 'Int32'
            'shadowWarning' = 'Int32'
            'sn' = 'SingleValueString'
            'st' = 'SingleValueString'
            'streetAddress' = 'SingleValueString'
            'targetAddress' = 'SingleValueString'
            'telephoneAssistant' = 'SingleValueString'
            'telephoneNumber' = 'SingleValueString'
            'title' = 'SingleValueString'
            'uid' = 'SingleValueString'
            'uidNumber' = 'Int32'
            'unixHomeDirectory' = 'SingleValueString'
            'userAccountControl' = 'Int32'
            'userPrincipalName' = 'SingleValueString'
            'userWorkstations' = 'SingleValueString'
            'wwWWHomePage' = 'SingleValueString'
        }
    }
    Process { }
    End {
        try {
            if ( [regex]::Match( $DistinguishedName, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                if ( $Server -eq '' ) {
                    $bindString = "LDAP://{0}/{1}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name, $DistinguishedName;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f $Server, $DistinguishedName;
                }
                Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );
    
                if ( $null -eq $Credential ) {
                    $de = New-Object System.DirectoryServices.DirectoryEntry( $bindString );
                } else {
                    $de = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $Credential.UserName, ( $Credential.GetNetworkCredential().Password ), [DirectoryServices.AuthenticationTypes]::Secure );
                }
    
                if ( $null -ne $de.distinguishedName ) {
                    Write-Verbose -Message 'An object was found at the specified path';

                    if ( $de.Properties.Contains( $AttributeName ) ) {
                        try {
                            $de.Properties[ $AttributeName ].Clear();
                            $de.CommitChanges();
                        }
                        catch {
                            Write-Warning -Message 'Failed to set attribute value. Please check your permissions.';
                        }
                    }
                } else {
                    Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
                }
            } else {
                Write-Warning -Message ( "The following is not a proper distinguished name value: {0}" -f $DistinguishedName );
            }
        } catch { } # Throw away the error because it is false anyway
    }
}

function Get-ADDSAttributeValue {
    Param
    (
        [String] $AttributeName,

        [Object] $SearchResult
    )

    if ( $script:attributeTypes.Contains( $AttributeName ) ) {
        $attributeType = $script:attributeTypes.Item( $AttributeName )

        switch ( $attributeType ) {
            'SingleValueString' {
                if ( $SearchResult.Properties.Contains( $AttributeName ) ) {
                    return $SearchResult.Properties.Item( $AttributeName )[ 0 ];
                } else {
                    return '';
                }
            } 'DateTime' {
                if ( $SearchResult.Properties.Contains( $AttributeName ) ) {
                    return ( Get-Date -Date $SearchResult.Properties.Item( $AttributeName )[ 0 ] -Format u );
                } else {
                    return '';
                }
            } 'Int32' {
                if ( $SearchResult.Properties.Contains( $AttributeName ) ) {
                    return [Convert]::ToInt32( $SearchResult.Properties.Item( $AttributeName )[ 0 ] );
                } else {
                    return 0;
                }
            } 'IADsLargeInteger' {
                if ( $SearchResult.Properties.Contains( $AttributeName ) ) {
                    switch ( $AttributeName ) {
                        'accountExpires' {
                            if ( $SearchResult.Properties.Item( $AttributeName )[ 0 ] -eq '9223372036854775807' ) {
                                return '(never)';
                            } else {
                                $iADSLargInteger = [DateTime]::FromFileTime( $SearchResult.Properties.Item( $AttributeName )[ 0 ] ).ToString();
                                return ( Get-Date -Date $iADSLargInteger -Format u );
                            }
                        } 'lockoutTime' {
                            if ( $SearchResult.Properties.Item( $AttributeName )[ 0 ] -eq '0' ) {
                                return '(not locked)';
                            } else {
                                $iADSLargInteger = [DateTime]::FromFileTime( $SearchResult.Properties.Item( $AttributeName )[ 0 ] ).ToString();
                                return ( Get-Date -Date $iADSLargInteger -Format u );
                            }
                        } 'pwdLastSet' {
                            if ( $SearchResult.Properties.Item( $AttributeName )[ 0 ] -eq '0' ) {
                                return '(never)';
                            } else {
                                $iADSLargInteger = [DateTime]::FromFileTime( $SearchResult.Properties.Item( $AttributeName )[ 0 ] ).ToString();
                                return ( Get-Date -Date $iADSLargInteger -Format u );
                            }
                        } default {
                            $iADSLargInteger = [DateTime]::FromFileTime( $SearchResult.Properties.Item( $AttributeName )[ 0 ] ).ToString();
                            return ( Get-Date -Date $iADSLargInteger -Format u );
                        }
                    }
                } else {
                    return 0;
                }
            } 'Boolean' {
                if ( $SearchResult.Properties.Contains( $AttributeName ) ) {
                    return [Convert]::ToBoolean( $SearchResult.Properties.Item( $AttributeName )[ 0 ] );
                } else {
                    return $false;
                }
            } 'GUID' {
                if ( $SearchResult.Properties.Contains( $AttributeName ) ) {
                    [Byte[]] $guidBytes = $SearchResult.Properties.Item( $AttributeName )[ 0 ];
                    [Guid] $guidData = New-Object Guid( ,$guidBytes );
                    return $guidData.Guid.ToString();
                } else {
                    return '';
                }
            } 'MultiValueString' {
                if ( $SearchResult.Properties.Contains( $AttributeName ) ) {
                    $stringCollection = [Collections.ArrayList] @();

                    foreach ( $stringValue in $SearchResult.Properties.Item( $AttributeName ) ) {
                        [Void] $stringCollection.Add( $stringValue );
                    }

                    $stringCollection.Sort();

                    return (,$stringCollection.ToArray());
                } else {
                    return @();
                }
            } 'StringSid' {
                if ( $SearchResult.Properties.Contains( $AttributeName ) ) {
                    [Byte[]] $sidBytes = $SearchResult.Properties.Item( $AttributeName )[ 0 ];
                    [Security.Principal.SecurityIdentifier] $sid = New-Object Security.Principal.SecurityIdentifier( $sidBytes, 0 );
                    return $sid.Value;
                } else {
                    return '';
                }
            } 'MultiValueStringSid' {
                if ( $SearchResult.Properties.Contains( $AttributeName ) ) {
                    $sidStrings = [Collections.ArrayList] @();

                    foreach ( $sidValue in $SearchResult.Properties.Item( $AttributeName ) ) {
                        [Byte[]] $sidBytes = $sidValue;
                        [Security.Principal.SecurityIdentifier] $sid = New-Object Security.Principal.SecurityIdentifier( $sidValue, 0 );
                        [Void] $sidStrings.Add( $sid.Value );
                    }

                    $sidStrings.Sort();

                    return (,$sidStrings.ToArray());
                } else {
                    return '';
                }
            } 'TSEncodedBlob' {
                $tsValues = [Hashtable] [ordered] @{
                    'AllowLogon' = $false
                    'BrokenConnectionAction' = 'Disconnect from session'
                    'ConnectClientDrivesAtLogon' = $false
                    'ConnectClientPrintersAtLogon' = $false
                    'DefaultToMainPrinter' = $false
                    'EnableRemoteControl' = ''
                    'HomeDirectory' = ''
                    'HomeDrive' = ''
                    'InitialProgram' = ''
                    'MaxConnectionTime' = 0
                    'MaxDisconnectionTime' = 0
                    'MaxIdleTime' = 0
                    'ReconnectionAction' = 'From any client'
                    'ProfilePath' = ''
                    'WorkDirectory' = ''
                };

                if ( $SearchResult.Properties.Contains( $AttributeName ) ) {
                    $adsiObject = [ADSI] $SearchResult.Path;

                    $allowLogon = $adsiObject.PSBase.InvokeGet( 'AllowLogon' );

                    if ( $allowLogon -eq 1 ) {
                        $tsValues.AllowLogon = $true;
                    }

                    $brokenConnectionAction = $adsiObject.PSBase.InvokeGet( 'BrokenConnectionAction' );

                    if ( $brokenConnectionAction -eq 1 ) {
                        $tsValues.BrokenConnectionAction = 'End session';
                    }

                    $connectClientDrivesAtLogon = $adsiObject.PSBase.InvokeGet( 'ConnectClientDrivesAtLogon' );

                    if ( $connectClientDrivesAtLogon -eq 1 ) {
                        $tsValues.ConnectClientDrivesAtLogon = $true;
                    }

                    $connectClientPrintersAtLogon = $adsiObject.PSBase.InvokeGet( 'ConnectClientPrintersAtLogon' );

                    if ( $connectClientPrintersAtLogon -eq 1 ) {
                        $tsValues.ConnectClientPrintersAtLogon = $true;
                    }

                    $defaultToMainPrinter = $adsiObject.PSBase.InvokeGet( 'DefaultToMainPrinter' );

                    if ( $defaultToMainPrinter -eq 1 ) {
                        $tsValues.DefaultToMainPrinter = $true;
                    }

                    $enableRemoteControl = $adsiObject.PSBase.InvokeGet( 'EnableRemoteControl' );

                    switch ( $enableRemoteControl ) {
                        0 {
                            $tsValues.EnableRemoteControl = 'Disabled';
                        } 1 {
                            $tsValues.EnableRemoteControl = 'Interact with session but requires user permission';
                        } 2 {
                            $tsValues.EnableRemoteControl = 'Interact with session without user permission';
                        } 3 {
                            $tsValues.EnableRemoteControl = 'View session but requires user permission';
                        } 4 {
                            $tsValues.EnableRemoteControl = 'View session without user permission';
                        } default {
                            $tsValues.EnableRemoteControl = 'Unknown remote control option';
                        }
                    }

                    $maxConnectionTime = $adsiObject.PSBase.InvokeGet( 'MaxConnectionTime' );

                    switch ( $maxConnectionTime ) {
                        0 {
                            $tsValues.MaxConnectionTime = 'Never';
                        } 1 {
                            $tsValues.MaxConnectionTime = '1 minute';
                        } 5 {
                            $tsValues.MaxConnectionTime = '5 minutes';
                        } 10 {
                            $tsValues.MaxConnectionTime = '10 minutes';
                        } 15 {
                            $tsValues.MaxConnectionTime = '15 minutes';
                        } 30 {
                            $tsValues.MaxConnectionTime = '30 minutes';
                        } 60 {
                            $tsValues.MaxConnectionTime = '1 hour';
                        } 120 {
                            $tsValues.MaxConnectionTime = '2 hours';
                        } 180 {
                            $tsValues.MaxConnectionTime = '3 hours';
                        } 1440 {
                            $tsValues.MaxConnectionTime = '1 day';
                        } 2880 {
                            $tsValues.MaxConnectionTime = '2 days';
                        } default {
                            $tsValues.MaxConnectionTime = "{0} minutes" -f $maxConnectionTime;
                        }
                    }

                    $maxDisconnectionTime = $adsiObject.PSBase.InvokeGet( 'MaxDisconnectionTime' );
                    
                    switch ( $maxDisconnectionTime ) {
                        0 {
                            $tsValues.MaxDisconnectionTime = 'Never';
                        } 1 {
                            $tsValues.MaxDisconnectionTime = '1 minute';
                        } 5 {
                            $tsValues.MaxDisconnectionTime = '5 minutes';
                        } 10 {
                            $tsValues.MaxDisconnectionTime = '10 minutes';
                        } 15 {
                            $tsValues.MaxDisconnectionTime = '15 minutes';
                        } 30 {
                            $tsValues.MaxDisconnectionTime = '30 minutes';
                        } 60 {
                            $tsValues.MaxDisconnectionTime = '1 hour';
                        } 120 {
                            $tsValues.MaxDisconnectionTime = '2 hours';
                        } 180 {
                            $tsValues.MaxDisconnectionTime = '3 hours';
                        } 1440 {
                            $tsValues.MaxDisconnectionTime = '1 day';
                        } 2880 {
                            $tsValues.MaxDisconnectionTime = '2 days';
                        } default {
                            $tsValues.MaxDisconnectionTime = "{0} minutes" -f $maxDisconnectionTime;
                        }
                    }

                    $maxIdleTime = $adsiObject.PSBase.InvokeGet( 'MaxIdleTime' );

                    switch ( $maxIdleTime ) {
                        0 {
                            $tsValues.MaxIdleTime = 'Never';
                        } 1 {
                            $tsValues.MaxIdleTime = '1 minute';
                        } 5 {
                            $tsValues.MaxIdleTime = '5 minutes';
                        } 10 {
                            $tsValues.MaxIdleTime = '10 minutes';
                        } 15 {
                            $tsValues.MaxIdleTime = '15 minutes';
                        } 30 {
                            $tsValues.MaxIdleTime = '30 minutes';
                        } 60 {
                            $tsValues.MaxIdleTime = '1 hour';
                        } 120 {
                            $tsValues.MaxIdleTime = '2 hours';
                        } 180 {
                            $tsValues.MaxIdleTime = '3 hours';
                        } 1440 {
                            $tsValues.MaxIdleTime = '1 day';
                        } 2880 {
                            $tsValues.MaxIdleTime = '2 days';
                        } default {
                            $tsValues.MaxIdleTime = "{0} minutes" -f $maxIdleTime;
                        }
                    }

                    $reconnectionAction = $adsiObject.PSBase.InvokeGet( 'ReconnectionAction' );

                    if ( $reconnectionAction -eq 1 ) {
                        $tsValues.ReconnectionAction = 'From originating client only';
                    }

                    $terminalServicesHomeDirectory = $adsiObject.PSBase.InvokeGet( 'TerminalServicesHomeDirectory' );
                    $tsValues.HomeDirectory = $terminalServicesHomeDirectory;

                    $terminalServicesHomeDrive = $adsiObject.PSBase.InvokeGet( 'TerminalServicesHomeDrive' );
                    $tsValues.HomeDrive = $terminalServicesHomeDrive;

                    $terminalServicesInitialProgram = $adsiObject.PSBase.InvokeGet( 'TerminalServicesInitialProgram' );
                    $tsValues.InitialProgram = $terminalServicesInitialProgram;

                    $terminalServicesProfilePath = $adsiObject.PSBase.InvokeGet( 'TerminalServicesProfilePath' );
                    $tsValues.ProfilePath = $terminalServicesProfilePath;

                    $terminalServicesWorkDirectory = $adsiObject.PSBase.InvokeGet( 'TerminalServicesWorkDirectory' );
                    $tsValues.WorkDirectory = $terminalServicesWorkDirectory;

                    $adsiObject.Close();
                    $adsiObject.Dispose();
                    $adsiObject = $null;

                    return $tsValues;
                } else {
                    return $tsValues;
                }
            }
        }
    } else {
        return '';
    }

    #----------------------------------------------------------------------------------------------------------
    trap {
        Write-Warning -Message ( "ERROR: AttributeName={0}, Object={1}, Message={2}" -f $AttributeName, $SearchResult.Path, $_.Exception.Message );
        Continue;
    }
    #----------------------------------------------------------------------------------------------------------
}

<#
.SYNOPSIS
    Retrieves computer objects from Active Directory.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to access Active Directory
    computer objects where the ActiveDirectory module is not available.
.PARAMETER Identity
    This is an optional parameter which specifies the name of the object to search for.
.PARAMETER LDAPFilter
    This is an optional parameter which defines and LDAP fileter string to use for the search.
    If you are unfamiliar with LDAP search strings, you can learn by doing a saved query in the
    Active Directory Users and Computers console and looking at the search string. As an additional
    option, you can simply pipe the output through a Where-Object clause to filter the results.
.PARAMETER Server
    This is an optional parameter which specifies the target Domain Controller to search.
.PARAMETER SearchBase
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER SearchScope
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the search.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a custom object that represents each returned object. If more than one object is
    returned from the cmdlet, a collection will the returned.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $adComputers = Get-ADDSComputer;

    The preceding example searches for all computer objects in the current domain using the current credentials.
.EXAMPLE
    $domainControllers = Get-ADDSComputer -SearchBase 'OU=Domain Controllers,DC=labthat,DC=com';

    The preceding example searches for all computer objects in the 'Domain Controllers' OU.
.EXAMPLE
    $domainControllers = Get-ADDSComputer -LDAPFilter '(&(objectClass=computer)(sAMAccountName=SERVER*))';

    The preceding example searches for all computer objects in the domain that have a name starting with 'SERVER'.
.EXAMPLE
    $creds = Get-Credential;
    $myComp = Get-ADDSComputer -Identity 'SERVER1' -Server 'MYDC01' -Credential $creds;

    The preceding example searches for a computer called 'SERVER1' on the Domain Controller named 'MYDC01' using 
    the credentials stored in $creds.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Get-ADDSComputer {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Enter the desired name to look for' )]
        [String] $Identity = '',

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the desired object type to search for' )]
        [String] $LDAPFilter = '',

        [Parameter( Position = 2, Mandatory = $false, HelpMessage = 'Enter the AD DS Domain Controller name to look for' )]
        [String] $Server = '',

        [Parameter( Position = 3, Mandatory = $false, HelpMessage = 'Enter the AD DS path to start the search' )]
        [String] $SearchBase = '',

        [Parameter( Position = 4, Mandatory = $false, HelpMessage = 'Enter the AD DS path to start the search' )]
        [ValidateSet( 'Base', 'OneLevel', 'Subtree' )]
        [String] $SearchScope = 'Subtree',

        [Parameter( Position = 5, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: Get-ADDSComputer';
        Write-Verbose -Message ( " -Identity = {0}" -f $Identity );
        Write-Verbose -Message ( " -LDAPFilter = {0}" -f $LDAPFilter );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -SearchBase = {0}" -f $SearchBase );
        Write-Verbose -Message ( " -SearchScope = {0}" -f $SearchScope );

        [String] $bindString = '';
        [Hashtable] $script:attributeTypes = @{
            'adminDescription' = 'SingleValueString'
            'canonicalName' = 'SingleValueString'
            'cn' = 'SingleValueString'
            'comment' = 'SingleValueString'
            'description' = 'SingleValueString'
            'distinguishedName' = 'SingleValueString'
            'dNSHostName' = 'SingleValueString'
            'isCriticalSystemObject' = 'Boolean'
            'lastLogonTimestamp' = 'IADsLargeInteger'
            'logonCount' = 'Int32'
            'managedBy' = 'SingleValueString'
            'memberOf' = 'MultiValueString'
            'msDS-parentdistname' = 'SingleValueString'
            'msDS-PrincipalName' = 'SingleValueString'
            'objectGUID' = 'GUID'
            'objectSid' = 'StringSID'
            'operatingSystem' = 'SingleValueString'
            'operatingSystemVersion' = 'SingleValueString'
            'primaryGroupID' = 'Int32'
            'primaryGroupToken' = 'Int32'
            'pwdLastSet' = 'IADsLargeInteger'
            'sAMAccountName' = 'SingleValueString'
            'serverReferenceBL' = 'SingleValueString'
            'servicePrincipalName' = 'MultiValueString'
            'userAccountControl' = 'Int32'
            'whenChanged' = 'DateTime'
            'whenCreated' = 'DateTime'
        }

        $jsonAttributes = [Collections.ArrayList] @(
            'adminDescription',
            'comment'
        )

        $script:isMultiValued = [Collections.ArrayList] @(
            'memberOf',
            'servicePrincipalName'
        );

        $script:isReadOnly = [Collections.ArrayList] @(
            '_bcObjectType',
            '_bcID',
            'canonicalName',
            'cn',
            'distinguishedName',
            'dNSHostName',
            'isCriticalSystemObject',
            'lastLogonTimestamp',
            'logonCount',
            'objectGUID',
            'objectSid',
            'operatingSystem',
            'operatingSystemVersion',
            'primaryGroupToken',
            'pwdLastSet',
            'serverReferenceBL',
            'whenChanged',
            'whenCreated'
        );
    }
    Process { }
    End {
        try {
            if ( $Server -eq '' ) {
                if ( $SearchBase -eq '' ) {
                    $bindString = "LDAP://{0}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name, $SearchBase;
                }
            } else {
                if ( $SearchBase -eq '' ) {
                    $bindString = "LDAP://{0}" -f $Server;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f $Server, $SearchBase;
                }
            }

            Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );

            if ( $null -eq $Credential ) {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString );
            } else {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $Credential.UserName, ( $Credential.GetNetworkCredential().Password ), [DirectoryServices.AuthenticationTypes]::Secure );
            }

            if ( $null -ne $domainRoot.distinguishedName ) {
                $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher;
                $domainSearcher.SearchRoot = $domainRoot;
                $domainSearcher.SearchScope = $SearchScope;
                $domainSearcher.PageSize = 1000;
                $domainSearcher.PropertiesToLoad.Clear();
                $domainSearcher.PropertiesToLoad.AddRange( $script:attributeTypes.Keys );

                if ( $LDAPFilter -eq '' ) {
                    if ( $Identity -eq '' ) {
                        $domainSearcher.Filter = "(&(sAMAccountType=805306369)(sAMAccountName=*))";
                        Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                        $searchResults = $domainSearcher.FindAll();
                    } else {
                        if ( [regex]::Match( $Identity, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                            $domainSearcher.Filter = "(distinguishedName={0})" -f $Identity;
                        } else {
                            $domainSearcher.Filter = "(&(sAMAccountType=805306369)(sAMAccountName={0}$))" -f $Identity;
                        }

                        Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                        $searchResults = $domainSearcher.FindOne();
                    }
                } else {
                    $domainSearcher.Filter = $LDAPFilter;
                    Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                    $searchResults = $domainSearcher.FindAll();
                }

                $output = [Collections.ArrayList] @();

                if ( $searchResults.Count -gt 0 ) {
                    Write-Verbose -Message ( "`$searchResults.Count = {0}" -f $searchResults.Count );
                    foreach ( $searchResult in $searchResults ) {
                        $operatingSystem = Get-ADDSAttributeValue -AttributeName 'operatingSystem' -SearchResult $searchResult;
                        if ( $operatingSystem.Contains( '®' ) ) {
                            $operatingSystem = $operatingSystem.Replace( '®', '' );
                        }
                        [Object] $template = [pscustomobject][ordered] @{
                            '_bcObjectType' = 'adComputer'
                            '_bcID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'adminDescription' = Get-ADDSAttributeValue -AttributeName 'adminDescription' -SearchResult $searchResult
                            'canonicalName' = Get-ADDSAttributeValue -AttributeName 'canonicalName' -SearchResult $searchResult
                            'cn' = Get-ADDSAttributeValue -AttributeName 'cn' -SearchResult $searchResult
                            'comment' = Get-ADDSAttributeValue -AttributeName 'comment' -SearchResult $searchResult
                            'description' = Get-ADDSAttributeValue -AttributeName 'description' -SearchResult $searchResult
                            'distinguishedName' = Get-ADDSAttributeValue -AttributeName 'distinguishedName' -SearchResult $searchResult
                            'dNSHostName' = Get-ADDSAttributeValue -AttributeName 'dNSHostName' -SearchResult $searchResult
                            'isCriticalSystemObject' = Get-ADDSAttributeValue -AttributeName 'isCriticalSystemObject' -SearchResult $searchResult
                            'lastLogonTimestamp' = Get-ADDSAttributeValue -AttributeName 'lastLogonTimestamp' -SearchResult $searchResult
                            'logonCount' = Get-ADDSAttributeValue -AttributeName 'logonCount' -SearchResult $searchResult
                            'managedBy' = Get-ADDSAttributeValue -AttributeName 'managedBy' -SearchResult $searchResult
                            'memberOf' = Get-ADDSAttributeValue -AttributeName 'memberOf' -SearchResult $searchResult
                            'msDS-parentdistname' = Get-ADDSAttributeValue -AttributeName 'msDS-parentdistname' -SearchResult $searchResult
                            'msDS-PrincipalName' = Get-ADDSAttributeValue -AttributeName 'msDS-PrincipalName' -SearchResult $searchResult
                            'objectGUID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'objectSid' = Get-ADDSAttributeValue -AttributeName 'objectSid' -SearchResult $searchResult
                            'operatingSystem' = $operatingSystem
                            'operatingSystemVersion' = Get-ADDSAttributeValue -AttributeName 'operatingSystemVersion' -SearchResult $searchResult
                            'pwdLastSet' = Get-ADDSAttributeValue -AttributeName 'pwdLastSet' -SearchResult $searchResult
                            'primaryGroupID' = Get-ADDSAttributeValue -AttributeName 'primaryGroupID' -SearchResult $searchResult
                            'sAMAccountName' = Get-ADDSAttributeValue -AttributeName 'sAMAccountName' -SearchResult $searchResult
                            'serverReferenceBL' = Get-ADDSAttributeValue -AttributeName 'serverReferenceBL' -SearchResult $searchResult
                            'servicePrincipalName' = Get-ADDSAttributeValue -AttributeName 'servicePrincipalName' -SearchResult $searchResult
                            'userAccountControl' = Get-ADDSAttributeValue -AttributeName 'userAccountControl' -SearchResult $searchResult
                            'whenChanged' = Get-ADDSAttributeValue -AttributeName 'whenChanged' -SearchResult $searchResult
                            'whenCreated' = Get-ADDSAttributeValue -AttributeName 'whenCreated' -SearchResult $searchResult
                        }

                        foreach ( $jsonAttribute in $jsonAttributes ) {
                            if ( $template.$jsonAttribute.StartsWith( '{' ) -and $template.$jsonAttribute.EndsWith( '}' ) ) {
                                Write-Verbose -Message ( "The following attribute looks like it might have JSON data = {0}" -f $jsonAttribute );
                                $jsonDataValues = ConvertFrom-JsonString -Value $template.$jsonAttribute;

                                if ( $null -ne $jsonDataValues ) {
                                    Write-Verbose -Message 'Building a JSON document from the attribute value'
                                    $customPropertyName = '';
                                    $customPropertyValue = '';

                                    foreach ( $jsonDataValue in $jsonDataValues.GetEnumerator() ) {
                                        $customPropertyName = "{0}" -f $jsonDataValue.Key;
                                        $customPropertyValue = $jsonDataValue.Value;
                                        Add-Member -InputObject $template -MemberType NoteProperty -Name $customPropertyName -Value $customPropertyValue -ErrorAction SilentlyContinue;
                                    }
                                }
                            }
                        }

                        # Add a method to add a value to a multivalue attribute
                        $template | Add-Member -MemberType ScriptMethod -Name AddMultiValue {
                            Param(	
                                [Parameter( Mandatory = $true, HelpMessage = 'Please specify the attribute name.' )]
                                [String] $Name,
                                
                                [Parameter( Mandatory = $false, HelpMessage = 'Please specify the attribute name.' )]
                                [String] $Value
                            )
                            End {
                                # Declare method objects and variables
                                $valueCollection = New-Object Collections.ArrayList;
                                $valueCollection.AddRange( $this.$Name );
                                # TODO: Take from my IDPortal module and make this work, can just use the Add-ADDSMultiValueAttribute instead
                                #[Object] $setResult = Set-IDPortalAttribute -AttributeName $Name -AttributeValue $Value -ObjectID $this.ObjectID -ObjectType $this.ObjectType -Remove:$false;
                            
                                # Update the object if successful
                                #if ( $setResult.Result -eq 'Success' ) {
                                #    [Void] $valueCollection.Add( $Value );
                                #    $this.$Name = $valueCollection;
                                #}

                                # Return the method result value
                                #return $setResult.Result;
                            } # end End
                        } -Force;

                        # Add a method to clear an attribute value
                        $template | Add-Member -MemberType ScriptMethod -Name Clear {
                            Param(	
                                [Parameter( Mandatory = $true, HelpMessage = 'Please specify the attribute name.' )]
                                [String] $Name
                            )
                            End {
                                if ( $script:isReadOnly.Contains( $Name ) ) {
                                    Write-Warning -Message ( "The following attribute is read-only and cannot be cleared: {0}" -f $Name );
                                    return 'Failed to clear attribute';
                                }

                                if ( $script:isMultiValued.Contains( $Name ) ) {
                                    Write-Warning -Message ( "The following value is multi-valued and must be modified with either AddMultivalue or RemoveMultivalue: {0}" -f $Name );
                                    return 'Failed to clear attribute';
                                }

                                "Clearing...$Name"
                            } # end End
                        } -Force;

                        # Add a method to calculate if the account is enabled
                        $template | Add-Member -MemberType ScriptMethod -Name IsDisabled {
                            Param()
                            End {
                                if ( $this.userAccountControl -band 2 ) {
                                    return $true;
                                } else {
                                    return $false;
                                }
                            } # end End
                        } -Force;

                        # Add a method to add a value to a multivalue attribute
                        $template | Add-Member -MemberType ScriptMethod -Name RemoveMultiValue {
                            Param(
                                [Parameter( Mandatory = $true, HelpMessage = 'Please specify the attribute name.' )]
                                [String] $Name,
                                
                                [Parameter( Mandatory = $false, HelpMessage = 'Please specify the attribute name.' )]
                                [String] $Value
                            )
                            End {
                                # Declare method objects and variables
                                $valueCollection = New-Object Collections.ArrayList;
                                $valueCollection.AddRange( $this.$Name );
                                # TODO: Take from my IDPortal module and make this work
                                #[Object] $setResult = Set-IDPortalAttribute -AttributeName $Name -AttributeValue $Value -ObjectID $this.ObjectID -ObjectType $this.ObjectType -Remove:$false;
                            
                                # Update the object if successful
                                #if ( $setResult.Result -eq 'Success' ) {
                                #    [Void] $valueCollection.Add( $Value );
                                #    $this.$Name = $valueCollection;
                                #}

                                # Return the method result value
                                #return $setResult.Result;
                            } # end End
                        } -Force;

                        # Add a method to set an attribute value
                        $template | Add-Member -MemberType ScriptMethod -Name SetAttribute {
                            Param(	
                                [Parameter( Mandatory = $true, HelpMessage = 'Please specify the attribute name.' )]
                                [String] $Name,
                                
                                [Parameter( Mandatory = $false, HelpMessage = 'Please specify the attribute name.' )]
                                [String] $Value
                            )
                            End {
                                if ( $script:isReadOnly.Contains( $Name ) ) {
                                    Write-Warning -Message ( "The following attribute is read-only and cannot be set: {0}" -f $Name );
                                    return 'Failed';
                                }

                                if ( $script:isMultiValued.Contains( $Name ) ) {
                                    Write-Warning -Message ( "The following attribute is multi-valued and must be modified with either AddMultivalue or RemoveMultivalue: {0}" -f $Name );
                                    return 'Failed';
                                }
                                
                                if ( $script:attributeTypes.ContainsKey( $Name ) ) {
                                    "Attempting to set {0} to {1}" -f $Name, $Value;
                                    $this.$Name;
                                } else {
                                    Write-Warning -Message ( "The following attribute is not currently available in this cmdlet: {0}" -f $Name );
                                }

                            } # end End
                        } -Force;
                        
                        Write-Verbose -Message 'Add the current object to the results collection'
                        [Void] $output.Add( $template );
                    }
                }
            } else {
                Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
            }
        } catch {  } # Throw away the error because it is false anyway

        return $output;
    }   
}

<#
.SYNOPSIS
    Retrieves contact objects from Active Directory.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to access Active Directory
    user objects where the ActiveDirectory module is not available.
.PARAMETER Identity
    This is an optional parameter which specifies the name of the object to search for.
.PARAMETER LDAPFilter
    This is an optional parameter which defines and LDAP fileter string to use for the search.
    If you are unfamiliar with LDAP search strings, you can learn by doing a saved query in the
    Active Directory Users and Computers console and looking at the search string. As an additional
    option, you can simply pipe the output through a Where-Object clause to filter the results.
.PARAMETER Server
    This is an optional parameter which specifies the target Domain Controller to search.
.PARAMETER SearchBase
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER SearchScope
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the search.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a custom object that represents each returned object. If more than one object is
    returned from the cmdlet, a collection will the returned.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $adContacts = Get-ADDSContact;

    The preceding example searches for all contact objects in the current domain using the current credentials.
.EXAMPLE
    $adContacts = Get-ADDSContact -SearchBase 'OU=Accounting Team,DC=labthat,DC=com';

    The preceding example searches for all contact objects in the 'Accounting Team' OU.
.EXAMPLE
    $adContacts = Get-ADDSContact -LDAPFilter '(&(objectClass=contact)(sAMAccountName=test*))';

    The preceding example searches for all contact objects in the domain that have an account name starting with 'test'.
.EXAMPLE
    $creds = Get-Credential;
    $adContact = Get-ADDSContact -Identity 'testuser' -Server 'MYDC01' -Credential $creds;

    The preceding example searches for a contact called 'testuser' on the Domain Controller named 'MYDC01' using 
    the credentials stored in $creds.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Get-ADDSContact {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Enter the desired name to look for' )]
        [String] $Identity = '',

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the desired object type to search for' )]
        [String] $LDAPFilter = '',

        [Parameter( Position = 2, Mandatory = $false, HelpMessage = 'Enter the AD DS Domain Controller name to use' )]
        [String] $Server = '',

        [Parameter( Position = 3, Mandatory = $false, HelpMessage = 'Enter the AD DS path to start the search' )]
        [String] $SearchBase = '',

        [Parameter( Position = 4, Mandatory = $false, HelpMessage = 'Enter the AD DS path to start the search' )]
        [ValidateSet( 'Base', 'OneLevel', 'Subtree' )]
        [String] $SearchScope = 'Subtree',

        [Parameter( Position = 5, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: Get-ADDSContact';
        Write-Verbose -Message ( " -Identity = {0}" -f $Identity );
        Write-Verbose -Message ( " -LDAPFilter = {0}" -f $LDAPFilter );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -SearchBase = {0}" -f $SearchBase );
        Write-Verbose -Message ( " -SearchScope = {0}" -f $SearchScope );

        [String] $bindString = '';
        [Hashtable] $script:attributeTypes = @{
            'adminDescription' = 'SingleValueString'
            'c' = 'SingleValueString'
            'canonicalName' = 'SingleValueString'
            'cn' = 'SingleValueString'
            'co' = 'SingleValueString'
            'comment' = 'SingleValueString'
            'company' = 'SingleValueString'
            'countryCode' = 'SingleValueString'
            'department' = 'SingleValueString'
            'description' = 'SingleValueString'
            'directReports' = 'MultiValueString'
            'displayName' = 'SingleValueString'
            'distinguishedName' = 'SingleValueString'
            'division' = 'SingleValueString'
            'employeeID' = 'SingleValueString'
            'employeeNumber' = 'SingleValueString'
            'employeeType' = 'SingleValueString'
            'extensionAttribute1' = 'SingleValueString'
            'extensionAttribute2' = 'SingleValueString'
            'extensionAttribute3' = 'SingleValueString'
            'extensionAttribute4' = 'SingleValueString'
            'extensionAttribute5' = 'SingleValueString'
            'extensionAttribute6' = 'SingleValueString'
            'extensionAttribute7' = 'SingleValueString'
            'extensionAttribute8' = 'SingleValueString'
            'extensionAttribute9' = 'SingleValueString'
            'extensionAttribute10' = 'SingleValueString'
            'extensionAttribute11' = 'SingleValueString'
            'extensionAttribute12' = 'SingleValueString'
            'extensionAttribute13' = 'SingleValueString'
            'extensionAttribute14' = 'SingleValueString'
            'extensionAttribute15' = 'SingleValueString'
            'facsimileTelephoneNumber' = 'SingleValueString'
            'givenName' = 'SingleValueString'
            'info' = 'SingleValueString'
            'initials' = 'SingleValueString'
            'l' = 'SingleValueString'
            'legacyExchangeDN' = 'SingleValueString'
            'mail' = 'SingleValueString'
            'mailNickname' = 'SingleValueString'
            'manager' = 'SingleValueString'
            'mAPIRecipient' = 'Boolean'
            'memberOf' = 'MultiValueString'
            'mobile' = 'SingleValueString'
            'mS-DS-ConsistencyGuid' = 'GUID'
            'msDS-parentdistname' = 'SingleValueString'
            'msDS-PrincipalName' = 'SingleValueString'
            'msExchAssistantName' = 'SingleValueString'
            'msExchBypassModerationLink' = 'MultiValueString'
            'msExchEnableModeration' = 'Boolean'
            'msExchHideFromAddressLists' = 'Boolean'
            'msExchLitigationHoldDate' = 'DateTime'
            'msExchLitigationHoldOwner' = 'SingleValueString'
            'msExchOriginatingForest' = 'SingleValueString'
            'msExchPoliciesExcluded' = 'MultiValueString'
            'msExchPoliciesIncluded' = 'MultiValueString'
            'msExchRecipientDisplayType' = 'Int32'
            'msExchRecipientTypeDetails' = 'IADsLargeInteger'
            'msExchRemoteRecipientType' = 'IADsLargeInteger'
            'msExchResourceCapacity' = 'Int32'
            'msExchResourceDisplay' = 'SingleValueString'
            'msExchResourceMetaData' = 'MultiValueString'
            'msExchResourceSearchProperties' = 'MultiValueString'
            'msExchUsageLocation' = 'SingleValueString'
            'msExchVersion' = 'IADsLargeInteger'
            'msRTCSIP-FederationEnabled' = 'Boolean'
            'msRTCSIP-PrimaryHomeServer' ='SingleValueString'
            'msRTCSIP-PrimaryUserAddress' = 'SingleValueString'
            'msRTCSIP-UserEnabled' ='Boolean'
            'o' = 'SingleValueString'
            'objectGUID' = 'GUID'
            'pager' = 'SingleValueString'
            'physicalDeliveryOfficeName' = 'SingleValueString'
            'postalCode' = 'SingleValueString'
            'postOfficeBox' = 'SingleValueString'
            'proxyAddresses' = 'MultiValueString'
            'publicDelegates' = 'MultiValueString'
            'sn' = 'SingleValueString'
            'st' = 'SingleValueString'
            'streetAddress' = 'SingleValueString'
            'targetAddress' = 'SingleValueString'
            'telephoneAssistant' = 'SingleValueString'
            'telephoneNumber' = 'SingleValueString'
            'title' = 'SingleValueString'
            'whenChanged' = 'DateTime'
            'whenCreated' = 'DateTime'
        }

        $jsonAttributes = [Collections.ArrayList] @(
            'adminDescription',
            'comment',
            'extensionAttribute1',
            'extensionAttribute2',
            'extensionAttribute3',
            'extensionAttribute4',
            'extensionAttribute5',
            'extensionAttribute6',
            'extensionAttribute7',
            'extensionAttribute8',
            'extensionAttribute9',
            'extensionAttribute10',
            'extensionAttribute11',
            'extensionAttribute12',
            'extensionAttribute13',
            'extensionAttribute14',
            'extensionAttribute15'
        )
    }
    Process { }
    End {
        try {
            if ( $Server -eq '' ) {
                if ( $SearchBase -eq '' ) {
                    $bindString = "LDAP://{0}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name, $SearchBase;
                }
            } else {
                if ( $SearchBase -eq '' ) {
                    $bindString = "LDAP://{0}" -f $Server;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f $Server, $SearchBase;
                }
            }

            Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );

            if ( $null -eq $Credential ) {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString );
            } else {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $Credential.UserName, ( $Credential.GetNetworkCredential().Password ), [DirectoryServices.AuthenticationTypes]::Secure );
            }

            if ( $null -ne $domainRoot.distinguishedName ) {
                $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher;
                $domainSearcher.SearchRoot = $domainRoot;
                $domainSearcher.SearchScope = $SearchScope;
                $domainSearcher.PageSize = 1000;
                $domainSearcher.PropertiesToLoad.Clear();
                $domainSearcher.PropertiesToLoad.AddRange( $script:attributeTypes.Keys );

                if ( $LDAPFilter -eq '' ) {
                    if ( $Identity -eq '' ) {
                        $domainSearcher.Filter = "(&(objectCategory=person)(objectClass=contact))";
                        Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                        $searchResults = $domainSearcher.FindAll();
                    } else {
                        if ( [regex]::Match( $Identity, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                            $domainSearcher.Filter = "(distinguishedName={0})" -f $Identity;
                        } else {
                            $domainSearcher.Filter = "(&(objectCategory=person)(mail={0}))" -f $Identity;
                        }
                        
                        Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                        $searchResults = $domainSearcher.FindOne();
                    }
                } else {
                    $domainSearcher.Filter = $LDAPFilter;
                    Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                    $searchResults = $domainSearcher.FindAll();
                }

                $output = [Collections.ArrayList] @();

                if ( $searchResults.Count -gt 0 ) {
                    Write-Verbose -Message ( "`$searchResults.Count = {0}" -f $searchResults.Count );
                    foreach ( $searchResult in $searchResults ) {
                        [Object] $template = [pscustomobject][ordered] @{
                            '_bcObjectType' = 'adContact'
                            '_bcID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'adminDescription' = Get-ADDSAttributeValue -AttributeName 'adminDescription' -SearchResult $searchResult
                            'c' = Get-ADDSAttributeValue -AttributeName 'c' -SearchResult $searchResult
                            'canonicalName' = Get-ADDSAttributeValue -AttributeName 'canonicalName' -SearchResult $searchResult
                            'cn' = Get-ADDSAttributeValue -AttributeName 'cn' -SearchResult $searchResult
                            'co' = Get-ADDSAttributeValue -AttributeName 'co' -SearchResult $searchResult
                            'comment' = Get-ADDSAttributeValue -AttributeName 'comment' -SearchResult $searchResult
                            'company' = Get-ADDSAttributeValue -AttributeName 'company' -SearchResult $searchResult
                            'countryCode' = Get-ADDSAttributeValue -AttributeName 'countryCode' -SearchResult $searchResult
                            'department' = Get-ADDSAttributeValue -AttributeName 'department' -SearchResult $searchResult
                            'description' = Get-ADDSAttributeValue -AttributeName 'description' -SearchResult $searchResult
                            'directReports' = Get-ADDSAttributeValue -AttributeName 'directReports' -SearchResult $searchResult
                            'displayName' = Get-ADDSAttributeValue -AttributeName 'displayName' -SearchResult $searchResult
                            'distinguishedName' = Get-ADDSAttributeValue -AttributeName 'distinguishedName' -SearchResult $searchResult
                            'division' = Get-ADDSAttributeValue -AttributeName 'division' -SearchResult $searchResult
                            'employeeID' = Get-ADDSAttributeValue -AttributeName 'employeeID' -SearchResult $searchResult
                            'employeeNumber' = Get-ADDSAttributeValue -AttributeName 'employeeNumber' -SearchResult $searchResult
                            'employeeType' = Get-ADDSAttributeValue -AttributeName 'employeeType' -SearchResult $searchResult
                            'extensionAttribute1' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute1' -SearchResult $searchResult
                            'extensionAttribute2' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute2' -SearchResult $searchResult
                            'extensionAttribute3' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute3' -SearchResult $searchResult
                            'extensionAttribute4' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute4' -SearchResult $searchResult
                            'extensionAttribute5' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute5' -SearchResult $searchResult
                            'extensionAttribute6' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute6' -SearchResult $searchResult
                            'extensionAttribute7' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute7' -SearchResult $searchResult
                            'extensionAttribute8' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute8' -SearchResult $searchResult
                            'extensionAttribute9' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute9' -SearchResult $searchResult
                            'extensionAttribute10' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute10' -SearchResult $searchResult
                            'extensionAttribute11' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute11' -SearchResult $searchResult
                            'extensionAttribute12' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute12' -SearchResult $searchResult
                            'extensionAttribute13' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute13' -SearchResult $searchResult
                            'extensionAttribute14' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute14' -SearchResult $searchResult
                            'extensionAttribute15' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute15' -SearchResult $searchResult
                            'facsimileTelephoneNumber;' = Get-ADDSAttributeValue -AttributeName 'facsimileTelephoneNumber' -SearchResult $searchResult
                            'givenName' = Get-ADDSAttributeValue -AttributeName 'givenName' -SearchResult $searchResult
                            'info' = Get-ADDSAttributeValue -AttributeName 'info' -SearchResult $searchResult
                            'initials' = Get-ADDSAttributeValue -AttributeName 'initials' -SearchResult $searchResult
                            'l' = Get-ADDSAttributeValue -AttributeName 'l' -SearchResult $searchResult
                            'legacyExchangeDN' = Get-ADDSAttributeValue -AttributeName 'legacyExchangeDN' -SearchResult $searchResult
                            'mail' = Get-ADDSAttributeValue -AttributeName 'mail' -SearchResult $searchResult
                            'mailNickname' = Get-ADDSAttributeValue -AttributeName 'mailNickname' -SearchResult $searchResult
                            'mAPIRecipient' = Get-ADDSAttributeValue -AttributeName 'mAPIRecipient' -SearchResult $searchResult
                            'manager' = Get-ADDSAttributeValue -AttributeName 'manager' -SearchResult $searchResult
                            'memberOf' = Get-ADDSAttributeValue -AttributeName 'memberOf' -SearchResult $searchResult
                            'mobile' = Get-ADDSAttributeValue -AttributeName 'mobile' -SearchResult $searchResult
                            'ms-DS-ConsistencyGuid' = Get-ADDSAttributeValue -AttributeName 'ms-DS-ConsistencyGuid' -SearchResult $searchResult
                            'msDS-parentdistname' = Get-ADDSAttributeValue -AttributeName 'msDS-parentdistname' -SearchResult $searchResult
                            'msDS-PrincipalName' = Get-ADDSAttributeValue -AttributeName 'msDS-PrincipalName' -SearchResult $searchResult
                            'msExchAssistantName' = Get-ADDSAttributeValue -AttributeName 'msExchAssistantName' -SearchResult $searchResult
                            'msExchBypassModerationLink' = Get-ADDSAttributeValue -AttributeName 'msExchBypassModerationLink' -SearchResult $searchResult
                            'msExchEnableModeration' = Get-ADDSAttributeValue -AttributeName 'msExchEnableModeration' -SearchResult $searchResult
                            'msExchHideFromAddressLists' = Get-ADDSAttributeValue -AttributeName 'msExchHideFromAddressLists' -SearchResult $searchResult
                            'msExchLitigationHoldDate' = Get-ADDSAttributeValue -AttributeName 'msExchLitigationHoldDate' -SearchResult $searchResult
                            'msExchLitigationHoldOwner' = Get-ADDSAttributeValue -AttributeName 'msExchLitigationHoldOwner' -SearchResult $searchResult
                            'msExchOriginatingForest' = Get-ADDSAttributeValue -AttributeName 'msExchOriginatingForest' -SearchResult $searchResult
                            'msExchPoliciesExcluded' = Get-ADDSAttributeValue -AttributeName 'msExchPoliciesExcluded' -SearchResult $searchResult
                            'msExchPoliciesIncluded' = Get-ADDSAttributeValue -AttributeName 'msExchPoliciesIncluded' -SearchResult $searchResult
                            'msExchRecipientDisplayType' = Get-ADDSAttributeValue -AttributeName 'msExchRecipientDisplayType' -SearchResult $searchResult
                            'msExchRecipientTypeDetails' = Get-ADDSAttributeValue -AttributeName 'msExchRecipientTypeDetails' -SearchResult $searchResult
                            'msExchRemoteRecipientType' = Get-ADDSAttributeValue -AttributeName 'msExchRemoteRecipientType' -SearchResult $searchResult
                            'msExchResourceCapacity' = Get-ADDSAttributeValue -AttributeName 'msExchResourceCapacity' -SearchResult $searchResult
                            'msExchResourceDisplay' = Get-ADDSAttributeValue -AttributeName 'msExchResourceDisplay' -SearchResult $searchResult
                            'msExchResourceMetaData' = Get-ADDSAttributeValue -AttributeName 'msExchResourceMetaData' -SearchResult $searchResult
                            'msExchResourceSearchProperties' = Get-ADDSAttributeValue -AttributeName 'msExchResourceSearchProperties' -SearchResult $searchResult
                            'msExchUsageLocation' = Get-ADDSAttributeValue -AttributeName 'msExchUsageLocation' -SearchResult $searchResult
                            'msExchVersion' = Get-ADDSAttributeValue -AttributeName 'msExchVersion' -SearchResult $searchResult
                            'msRTCSIP-FederationEnabled' = Get-ADDSAttributeValue -AttributeName 'msRTCSIP-FederationEnabled' -SearchResult $searchResult
                            'msRTCSIP-PrimaryHomeServer' = Get-ADDSAttributeValue -AttributeName 'msRTCSIP-PrimaryHomeServer' -SearchResult $searchResult
                            'PrimaryUserAddress' = Get-ADDSAttributeValue -AttributeName 'PrimaryUserAddress' -SearchResult $searchResult
                            'msRTCSIP-UserEnabled' = Get-ADDSAttributeValue -AttributeName 'msRTCSIP-UserEnabled' -SearchResult $searchResult
                            'o' = Get-ADDSAttributeValue -AttributeName 'o' -SearchResult $searchResult
                            'objectGUID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'pager' = Get-ADDSAttributeValue -AttributeName 'pager' -SearchResult $searchResult
                            'physicalDeliveryOfficeName' = Get-ADDSAttributeValue -AttributeName 'physicalDeliveryOfficeName' -SearchResult $searchResult
                            'postalCode' = Get-ADDSAttributeValue -AttributeName 'postalCode' -SearchResult $searchResult
                            'postOfficeBox' = Get-ADDSAttributeValue -AttributeName 'postOfficeBox' -SearchResult $searchResult
                            'proxyAddresses' = Get-ADDSAttributeValue -AttributeName 'proxyAddresses' -SearchResult $searchResult
                            'publicDelegates' = Get-ADDSAttributeValue -AttributeName 'publicDelegates' -SearchResult $searchResult
                            'sn' = Get-ADDSAttributeValue -AttributeName 'sn' -SearchResult $searchResult
                            'st' = Get-ADDSAttributeValue -AttributeName 'st' -SearchResult $searchResult
                            'streetAddress' = Get-ADDSAttributeValue -AttributeName 'streetAddress' -SearchResult $searchResult
                            'targetAddress' = Get-ADDSAttributeValue -AttributeName 'targetAddress' -SearchResult $searchResult
                            'telephoneAssistant' = Get-ADDSAttributeValue -AttributeName 'telephoneAssistant' -SearchResult $searchResult
                            'telephoneNumber' = Get-ADDSAttributeValue -AttributeName 'telephoneNumber' -SearchResult $searchResult
                            'title' = Get-ADDSAttributeValue -AttributeName 'title' -SearchResult $searchResult
                            'whenChanged' = Get-ADDSAttributeValue -AttributeName 'whenChanged' -SearchResult $searchResult
                            'whenCreated' = Get-ADDSAttributeValue -AttributeName 'whenCreated' -SearchResult $searchResult
                        }

                        foreach ( $jsonAttribute in $jsonAttributes ) {
                            if ( $template.$jsonAttribute.StartsWith( '{' ) -and $template.$jsonAttribute.EndsWith( '}' ) ) {
                                Write-Verbose -Message ( "The following attribute looks like it might have JSON data = {0}" -f $jsonAttribute );
                                $jsonDataValues = ConvertFrom-JsonString -Value $template.$jsonAttribute;

                                if ( $null -ne $jsonDataValues ) {
                                    Write-Verbose -Message 'Building a JSON document from the attribute value'
                                    $customPropertyName = '';
                                    $customPropertyValue = '';

                                    foreach ( $jsonDataValue in $jsonDataValues.GetEnumerator() ) {
                                        $customPropertyName = "{0}" -f $jsonDataValue.Key;
                                        $customPropertyValue = $jsonDataValue.Value;
                                        Add-Member -InputObject $template -MemberType NoteProperty -Name $customPropertyName -Value $customPropertyValue -ErrorAction SilentlyContinue;
                                    }
                                }
                            }
                        }

                        Write-Verbose -Message 'Add the current object to the results collection'
                        [Void] $output.Add( $template );
                    }
                }
            } else {
                Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
            }
        } catch {  } # Throw away the error because it is false anyway

        return $output;
    }
}

<#
.SYNOPSIS
    Retrieves foreignSecurityPrincipals objects from Active Directory.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to access Active Directory
    foreignSecurityPrincipal objects where the ActiveDirectory module is not available.
.PARAMETER Identity
    This is an optional parameter which specifies the distinguishedName or SID to search for.
.PARAMETER LDAPFilter
    This is an optional parameter which defines and LDAP fileter string to use for the search.
    If you are unfamiliar with LDAP search strings, you can learn by doing a saved query in the
    Active Directory Users and Computers console and looking at the search string. As an additional
    option, you can simply pipe the output through a Where-Object clause to filter the results.
.PARAMETER Server
    This is an optional parameter which specifies the target Domain Controller to search.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the search.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a custom object that represents each returned object. If more than one object is
    returned from the cmdlet, a collection will the returned.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $adForeignSecurityPrincipals = Get-ADDSForeignSecurityPrincipal;

    The preceding example searches for all group objects in the current domain using the current credentials.
.EXAMPLE
    $domainControllers = Get-ADDSForeignSecurityPrincipal -LDAPFilter '(&(objectClass=foreignSecurityPrincipals)(cn=S-1-5-1111*))';

    The preceding example searches for all foreignSecurityPrincipal objects in the domain that have a name starting with 'S-1-5-1111'.
.EXAMPLE
    $creds = Get-Credential;
    $fsps = Get-ADDSForeignSecurityPrincipal -Server 'MYDC01' -Credential $creds;

    The preceding example searches for foreignSecurityPrincipals on the Domain Controller named 'MYDC01' using 
    the credentials stored in $creds.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Get-ADDSForeignSecurityPrincipal {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Enter the desired name to look for' )]
        [String] $Identity = '',

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the desired object type to search for' )]
        [String] $LDAPFilter = '',

        [Parameter( Position = 2, Mandatory = $false, HelpMessage = 'Enter the AD DS Domain Controller name to look for' )]
        [String] $Server = '',

        [Parameter( Position = 3, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: Get-ADDSForeignSecurityPrincipal';
        Write-Verbose -Message ( " -Identity = {0}" -f $Identity );
        Write-Verbose -Message ( " -LDAPFilter = {0}" -f $LDAPFilter );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );

        [String] $bindString = '';
        [Hashtable] $script:attributeTypes = @{
            'canonicalName' = 'SingleValueString'
            'cn' = 'SingleValueString'
            'distinguishedName' = 'SingleValueString'
            'msDS-parentdistname' = 'SingleValueString'
            'msDS-PrincipalName' = 'SingleValueString'
            'objectGUID' = 'GUID'
            'objectSid' = 'StringSID'
            'whenChanged' = 'DateTime'
            'whenCreated' = 'DateTime'
        }
    }
    Process { }
    End {
        try {
            if ( $Server -eq '' ) {
                $bindString = "LDAP://{0}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name;
            } else {
                $bindString = "LDAP://{0}" -f $Server;
            }

            Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );

            if ( $null -eq $Credential ) {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString );
            } else {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $Credential.UserName, ( $Credential.GetNetworkCredential().Password ), [DirectoryServices.AuthenticationTypes]::Secure );
            }

            if ( $null -ne $domainRoot.distinguishedName ) {
                $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher;
                $domainSearcher.SearchRoot = $domainRoot;
                $domainSearcher.SearchScope = 'Subtree';
                $domainSearcher.PageSize = 1000;
                $domainSearcher.PropertiesToLoad.Clear();
                $domainSearcher.PropertiesToLoad.AddRange( $script:attributeTypes.Keys );

                if ( $LDAPFilter -eq '' ) {
                    if ( $Identity -eq '' ) {
                        $domainSearcher.Filter = '(objectClass=foreignSecurityPrincipal)';
                        Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                        $searchResults = $domainSearcher.FindAll();
                    } else {
                        if ( [regex]::Match( $Identity, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                            $domainSearcher.Filter = "(distinguishedName={0})" -f $Identity;
                        } else {
                            $domainSearcher.Filter = "(&(objectClass=foreignSecurityPrincipal)(cn={0}))" -f $Identity;
                        }

                        Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                        $searchResults = $domainSearcher.FindOne();
                    }
                } else {
                    $domainSearcher.Filter = $LDAPFilter;
                    Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                    $searchResults = $domainSearcher.FindAll();
                }

                $output = [Collections.ArrayList] @();

                if ( $searchResults.Count -gt 0 ) {
                    Write-Verbose -Message ( "`$searchResults.Count = {0}" -f $searchResults.Count );
                    foreach ( $searchResult in $searchResults ) {
                        [Object] $template = [pscustomobject][ordered] @{
                            '_bcObjectType' = 'adForeignSecurityPrincipal'
                            '_bcID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'canonicalName' = Get-ADDSAttributeValue -AttributeName 'canonicalName' -SearchResult $searchResult
                            'cn' = Get-ADDSAttributeValue -AttributeName 'cn' -SearchResult $searchResult
                            'distinguishedName' = Get-ADDSAttributeValue -AttributeName 'distinguishedName' -SearchResult $searchResult
                            'msDS-parentdistname' = Get-ADDSAttributeValue -AttributeName 'msDS-parentdistname' -SearchResult $searchResult
                            'msDS-PrincipalName' = Get-ADDSAttributeValue -AttributeName 'msDS-PrincipalName' -SearchResult $searchResult
                            'objectGUID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'objectSid' = Get-ADDSAttributeValue -AttributeName 'objectSid' -SearchResult $searchResult
                            'whenChanged' = Get-ADDSAttributeValue -AttributeName 'whenChanged' -SearchResult $searchResult
                            'whenCreated' = Get-ADDSAttributeValue -AttributeName 'whenCreated' -SearchResult $searchResult
                        }

                        Write-Verbose -Message 'Add the current object to the results collection'
                        [Void] $output.Add( $template );
                    }
                }
            } else {
                Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
            }
        } catch {  } # Throw away the error because it is false anyway

        return $output;
    }   
}

<#
.SYNOPSIS
    Retrieves group objects from Active Directory.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to access Active Directory
    computer objects where the ActiveDirectory module is not available.
.PARAMETER Identity
    This is an optional parameter which specifies the name of the object to search for.
.PARAMETER LDAPFilter
    This is an optional parameter which defines and LDAP fileter string to use for the search.
    If you are unfamiliar with LDAP search strings, you can learn by doing a saved query in the
    Active Directory Users and Computers console and looking at the search string. As an additional
    option, you can simply pipe the output through a Where-Object clause to filter the results.
.PARAMETER Server
    This is an optional parameter which specifies the target Domain Controller to search.
.PARAMETER SearchBase
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER SearchScope
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the search.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a custom object that represents each returned object. If more than one object is
    returned from the cmdlet, a collection will the returned.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $adGroups = Get-ADDSGroup;

    The preceding example searches for all group objects in the current domain using the current credentials.
.EXAMPLE
    $adGroups = Get-ADDSGroup -SearchBase 'OU=Groups,DC=labthat,DC=com';

    The preceding example searches for all group objects in the 'Groups' OU.
.EXAMPLE
    $adGroups = Get-ADDSGroup -LDAPFilter '(&(objectClass=group)(cn=GRP*))';

    The preceding example searches for all group objects in the domain that have a name starting with 'GRP'.
.EXAMPLE
    $creds = Get-Credential;
    $adGroup = Get-ADDSGroup -Identity 'Domain Users' -Server 'MYDC01' -Credential $creds;

    The preceding example searches for a group called 'Domain Users' on the Domain Controller named 'MYDC01' using 
    the credentials stored in $creds.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Get-ADDSGroup {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Enter the desired name to look for' )]
        [String] $Identity = '',

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the desired object type to search for' )]
        [String] $LDAPFilter = '',

        [Parameter( Position = 2, Mandatory = $false, HelpMessage = 'Enter the AD DS Domain Controller name to look for' )]
        [String] $Server = '',

        [Parameter( Position = 3, Mandatory = $false, HelpMessage = 'Enter the AD DS path to start the search' )]
        [String] $SearchBase = '',

        [Parameter( Position = 4, Mandatory = $false, HelpMessage = 'Enter the AD DS path to start the search' )]
        [ValidateSet( 'Base', 'OneLevel', 'Subtree' )]
        [String] $SearchScope = 'Subtree',

        [Parameter( Position = 5, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: Get-ADDSGroup';
        Write-Verbose -Message ( " -Identity = {0}" -f $Identity );
        Write-Verbose -Message ( " -LDAPFilter = {0}" -f $LDAPFilter );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -SearchBase = {0}" -f $SearchBase );
        Write-Verbose -Message ( " -SearchScope = {0}" -f $SearchScope );

        [String] $bindString = '';
        [Hashtable] $script:attributeTypes = @{
            'adminCount' = 'Int32'
            'adminDescription' = 'SingleValueString'
            'canonicalName' = 'SingleValueString'
            'cn' = 'SingleValueString'
            'comment' = 'SingleValueString'
            'description' = 'SingleValueString'
            'displayName' = 'SingleValueString'
            'distinguishedName' = 'SingleValueString'
            'extensionAttribute1' = 'SingleValueString'
            'extensionAttribute2' = 'SingleValueString'
            'extensionAttribute3' = 'SingleValueString'
            'extensionAttribute4' = 'SingleValueString'
            'extensionAttribute5' = 'SingleValueString'
            'extensionAttribute6' = 'SingleValueString'
            'extensionAttribute7' = 'SingleValueString'
            'extensionAttribute8' = 'SingleValueString'
            'extensionAttribute9' = 'SingleValueString'
            'extensionAttribute10' = 'SingleValueString'
            'extensionAttribute11' = 'SingleValueString'
            'extensionAttribute12' = 'SingleValueString'
            'extensionAttribute13' = 'SingleValueString'
            'extensionAttribute14' = 'SingleValueString'
            'extensionAttribute15' = 'SingleValueString'
            'gidNumber' = 'Int32'
            'groupType' = 'Int32'
            'info' = 'SingleValueString'
            'legacyExchangeDN' = 'SingleValueString'
            'mail' = 'SingleValueString'
            'mailNickname' = 'SingleValueString'
            'managedBy' = 'SingleValueString'
            'member' = 'MultiValueString'
            'memberOf' = 'MultiValueString'
            'memberUid' = 'MultiValueString'
            'msDS-parentdistname' = 'SingleValueString'
            'msDS-PrincipalName' = 'SingleValueString'
            'msExchArchiveGUID' = 'GUID'
            'msExchArchiveName' = 'SingleValueString'
            'msExchArchiveStatus' = 'Int32'
            'msExchAssistantName' = 'SingleValueString'
            'msExchBypassModerationLink' = 'MultiValueString'
            'msExchEnableModeration' = 'Boolean'
            'msExchHideFromAddressLists' = 'Boolean'
            'msExchLitigationHoldDate' = 'DateTime'
            'msExchLitigationHoldOwner' = 'SingleValueString'
            'msExchMailboxGuid' = 'GUID'
            'msExchMasterAccountHistory' = 'MultiValueStringSid'
            'msExchMasterAccountSid' = 'StringSID'
            'msExchOriginatingForest' = 'MultiValueString'
            'msExchPoliciesExcluded' = 'MultiValueString'
            'msExchPoliciesIncluded' = 'MultiValueString'
            'msExchRecipientDisplayType' = 'Int32'
            'msExchRecipientTypeDetails' = 'IADsLargeInteger'
            'msExchRemoteRecipientType' = 'IADsLargeInteger'
            'msExchResourceCapacity' = 'Int32'
            'msExchResourceDisplay' = 'SingleValueString'
            'msExchResourceMetaData' = 'MultiValueString'
            'msExchResourceSearchProperties' = 'MultiValueString'
            'msExchVersion' = 'IADsLargeInteger'
            'msSFU30NisDomain' = 'SingleValueString'
            'objectGUID' = 'GUID'
            'objectSid' = 'StringSID'
            'primaryGroupToken' = 'Int32'
            'proxyAddresses' = 'MultiValueString'
            'publicDelegates' = 'MultiValueString'
            'sAMAccountName' = 'SingleValueString'
            'sIDHistory' = 'MultiValueStringSid'
            'targetAddress' = 'SingleValueString'
            'whenChanged' = 'DateTime'
            'whenCreated' = 'DateTime'
        }

        $jsonAttributes = [Collections.ArrayList] @(
            'adminDescription',
            'comment',
            'extensionAttribute1',
            'extensionAttribute2',
            'extensionAttribute3',
            'extensionAttribute4',
            'extensionAttribute5',
            'extensionAttribute6',
            'extensionAttribute7',
            'extensionAttribute8',
            'extensionAttribute9',
            'extensionAttribute10',
            'extensionAttribute11',
            'extensionAttribute12',
            'extensionAttribute13',
            'extensionAttribute14',
            'extensionAttribute15'
        )
    }
    Process { }
    End {
        try {
            if ( $Server -eq '' ) {
                if ( $SearchBase -eq '' ) {
                    $bindString = "LDAP://{0}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name, $SearchBase;
                }
            } else {
                if ( $SearchBase -eq '' ) {
                    $bindString = "LDAP://{0}" -f $Server;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f $Server, $SearchBase;
                }
            }

            if ( $null -eq $Credential ) {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString );
            } else {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $Credential.UserName, ( $Credential.GetNetworkCredential().Password ), [DirectoryServices.AuthenticationTypes]::Secure );
            }

            Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );

            if ( $null -ne $domainRoot.distinguishedName ) {
                $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher;
                $domainSearcher.SearchRoot = $domainRoot;
                $domainSearcher.SearchScope = $SearchScope;
                $domainSearcher.PageSize = 1000;
                $domainSearcher.PropertiesToLoad.Clear();
                $domainSearcher.PropertiesToLoad.AddRange( $script:attributeTypes.Keys );

                if ( $LDAPFilter -eq '' ) {
                    if ( $Identity -eq '' ) {
                        $domainSearcher.Filter = "(&(objectCategory=group)(sAMAccountName=*))";
                        $searchResults = $domainSearcher.FindAll();
                    } else {
                        if ( [regex]::Match( $Identity, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                            $domainSearcher.Filter = "(distinguishedName={0})" -f $Identity;
                        } else {
                            $domainSearcher.Filter = "(&(objectCategory=group)(sAMAccountName={0}))" -f $Identity;
                        }

                        Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                        $searchResults = $domainSearcher.FindOne();
                    }
                } else {
                    $domainSearcher.Filter = $LDAPFilter;
                    Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                    $searchResults = $domainSearcher.FindAll();
                }

                $output = [Collections.ArrayList] @();

                if ( $searchResults.Count -gt 0 ) {
                    Write-Verbose -Message ( "`$searchResults.Count = {0}" -f $searchResults.Count );
                    foreach ( $searchResult in $searchResults ) {
                        [Object] $template = [pscustomobject][ordered] @{
                            '_bcObjectType' = 'adGroup'
                            '_bcID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'adminCount' = Get-ADDSAttributeValue -AttributeName 'adminCount' -SearchResult $searchResult
                            'adminDescription' = Get-ADDSAttributeValue -AttributeName 'adminDescription' -SearchResult $searchResult
                            'canonicalName' = Get-ADDSAttributeValue -AttributeName 'canonicalName' -SearchResult $searchResult
                            'cn' = Get-ADDSAttributeValue -AttributeName 'cn' -SearchResult $searchResult
                            'comment' = Get-ADDSAttributeValue -AttributeName 'comment' -SearchResult $searchResult
                            'description' = Get-ADDSAttributeValue -AttributeName 'description' -SearchResult $searchResult
                            'displayName' = Get-ADDSAttributeValue -AttributeName 'displayName' -SearchResult $searchResult
                            'distinguishedName' = Get-ADDSAttributeValue -AttributeName 'distinguishedName' -SearchResult $searchResult
                            'extensionAttribute1' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute1' -SearchResult $searchResult
                            'extensionAttribute2' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute2' -SearchResult $searchResult
                            'extensionAttribute3' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute3' -SearchResult $searchResult
                            'extensionAttribute4' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute4' -SearchResult $searchResult
                            'extensionAttribute5' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute5' -SearchResult $searchResult
                            'extensionAttribute6' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute6' -SearchResult $searchResult
                            'extensionAttribute7' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute7' -SearchResult $searchResult
                            'extensionAttribute8' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute8' -SearchResult $searchResult
                            'extensionAttribute9' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute9' -SearchResult $searchResult
                            'extensionAttribute10' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute10' -SearchResult $searchResult
                            'extensionAttribute11' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute11' -SearchResult $searchResult
                            'extensionAttribute12' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute12' -SearchResult $searchResult
                            'extensionAttribute13' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute13' -SearchResult $searchResult
                            'extensionAttribute14' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute14' -SearchResult $searchResult
                            'extensionAttribute15' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute15' -SearchResult $searchResult
                            'gidNumber' = Get-ADDSAttributeValue -AttributeName 'gidNumber' -SearchResult $searchResult
                            'groupType' = Get-ADDSAttributeValue -AttributeName 'groupType' -SearchResult $searchResult
                            'info' = Get-ADDSAttributeValue -AttributeName 'info' -SearchResult $searchResult
                            'legacyExchangeDN' = Get-ADDSAttributeValue -AttributeName 'legacyExchangeDN' -SearchResult $searchResult
                            'mail' = Get-ADDSAttributeValue -AttributeName 'mail' -SearchResult $searchResult
                            'mailNickname' = Get-ADDSAttributeValue -AttributeName 'mailNickname' -SearchResult $searchResult
                            'managedBy' = Get-ADDSAttributeValue -AttributeName 'managedBy' -SearchResult $searchResult
                            'member' = Get-ADDSAttributeValue -AttributeName 'member' -SearchResult $searchResult
                            'memberOf' = Get-ADDSAttributeValue -AttributeName 'memberOf' -SearchResult $searchResult
                            'memberUid' = Get-ADDSAttributeValue -AttributeName 'memberUid' -SearchResult $searchResult
                            'ms-DS-ConsistencyGuid' = Get-ADDSAttributeValue -AttributeName 'ms-DS-ConsistencyGuid' -SearchResult $searchResult
                            'msDS-parentdistname' = Get-ADDSAttributeValue -AttributeName 'msDS-parentdistname' -SearchResult $searchResult
                            'msDS-PrincipalName' = Get-ADDSAttributeValue -AttributeName 'msDS-PrincipalName' -SearchResult $searchResult
                            'msExchArchiveGUID' = Get-ADDSAttributeValue -AttributeName 'msExchArchiveGUID' -SearchResult $searchResult
                            'msExchArchiveName' = Get-ADDSAttributeValue -AttributeName 'msExchArchiveName' -SearchResult $searchResult
                            'msExchArchiveStatus' = Get-ADDSAttributeValue -AttributeName 'msExchArchiveStatus' -SearchResult $searchResult
                            'msExchAssistantName' = Get-ADDSAttributeValue -AttributeName 'msExchAssistantName' -SearchResult $searchResult
                            'msExchBypassModerationLink' = Get-ADDSAttributeValue -AttributeName 'msExchBypassModerationLink' -SearchResult $searchResult
                            'msExchEnableModeration' = Get-ADDSAttributeValue -AttributeName 'msExchEnableModeration' -SearchResult $searchResult
                            'msExchHideFromAddressLists' = Get-ADDSAttributeValue -AttributeName 'msExchHideFromAddressLists' -SearchResult $searchResult
                            'msExchLitigationHoldDate' = Get-ADDSAttributeValue -AttributeName 'msExchLitigationHoldDate' -SearchResult $searchResult
                            'msExchLitigationHoldOwner' = Get-ADDSAttributeValue -AttributeName 'msExchLitigationHoldOwner' -SearchResult $searchResult
                            'msExchMailboxGuid' = Get-ADDSAttributeValue -AttributeName 'msExchMailboxGuid' -SearchResult $searchResult
                            'msExchMasterAccountHistory' = Get-ADDSAttributeValue -AttributeName 'msExchMasterAccountHistory' -SearchResult $searchResult
                            'msExchMasterAccountSid' = Get-ADDSAttributeValue -AttributeName 'msExchMasterAccountSid' -SearchResult $searchResult
                            'msExchOriginatingForest' = Get-ADDSAttributeValue -AttributeName 'msExchOriginatingForest' -SearchResult $searchResult
                            'msExchPoliciesExcluded' = Get-ADDSAttributeValue -AttributeName 'msExchPoliciesExcluded' -SearchResult $searchResult
                            'msExchPoliciesIncluded' = Get-ADDSAttributeValue -AttributeName 'msExchPoliciesIncluded' -SearchResult $searchResult
                            'msExchRecipientDisplayType' = Get-ADDSAttributeValue -AttributeName 'msExchRecipientDisplayType' -SearchResult $searchResult
                            'msExchRecipientTypeDetails' = Get-ADDSAttributeValue -AttributeName 'msExchRecipientTypeDetails' -SearchResult $searchResult
                            'msExchRemoteRecipientType' = Get-ADDSAttributeValue -AttributeName 'msExchRemoteRecipientType' -SearchResult $searchResult
                            'msExchResourceCapacity' = Get-ADDSAttributeValue -AttributeName 'msExchResourceCapacity' -SearchResult $searchResult
                            'msExchResourceDisplay' = Get-ADDSAttributeValue -AttributeName 'msExchResourceDisplay' -SearchResult $searchResult
                            'msExchResourceMetaData' = Get-ADDSAttributeValue -AttributeName 'msExchResourceMetaData' -SearchResult $searchResult
                            'msExchResourceSearchProperties' = Get-ADDSAttributeValue -AttributeName 'msExchResourceSearchProperties' -SearchResult $searchResult
                            'msExchVersion' = Get-ADDSAttributeValue -AttributeName 'msExchVersion' -SearchResult $searchResult
                            'msSFU30NisDomain' = Get-ADDSAttributeValue -AttributeName 'msSFU30NisDomain' -SearchResult $searchResult
                            'objectGUID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'objectSid' = Get-ADDSAttributeValue -AttributeName 'objectSid' -SearchResult $searchResult
                            'primaryGroupToken' = Get-ADDSAttributeValue -AttributeName 'primaryGroupToken' -SearchResult $searchResult
                            'proxyAddresses' = Get-ADDSAttributeValue -AttributeName 'proxyAddresses' -SearchResult $searchResult
                            'publicDelegates' = Get-ADDSAttributeValue -AttributeName 'publicDelegates' -SearchResult $searchResult
                            'sAMAccountName' = Get-ADDSAttributeValue -AttributeName 'sAMAccountName' -SearchResult $searchResult
                            'sIDHistory' = Get-ADDSAttributeValue -AttributeName 'sIDHistory' -SearchResult $searchResult
                            'targetAddress' = Get-ADDSAttributeValue -AttributeName 'targetAddress' -SearchResult $searchResult
                            'whenChanged' = Get-ADDSAttributeValue -AttributeName 'whenChanged' -SearchResult $searchResult
                            'whenCreated' = Get-ADDSAttributeValue -AttributeName 'whenCreated' -SearchResult $searchResult
                        }

                        foreach ( $jsonAttribute in $jsonAttributes ) {
                            if ( $template.$jsonAttribute.StartsWith( '{' ) -and $template.$jsonAttribute.EndsWith( '}' ) ) {
                                Write-Verbose -Message ( "The following attribute looks like it might have JSON data = {0}" -f $jsonAttribute );
                                $jsonDataValues = ConvertFrom-JsonString -Value $template.$jsonAttribute;

                                if ( $null -ne $jsonDataValues ) {
                                    Write-Verbose -Message 'Building a JSON document from the attribute value'
                                    $customPropertyName = '';
                                    $customPropertyValue = '';

                                    foreach ( $jsonDataValue in $jsonDataValues.GetEnumerator() ) {
                                        $customPropertyName = "{0}" -f $jsonDataValue.Key;
                                        $customPropertyValue = $jsonDataValue.Value;
                                        Add-Member -InputObject $template -MemberType NoteProperty -Name $customPropertyName -Value $customPropertyValue -ErrorAction SilentlyContinue;
                                    }
                                }
                            }
                        }

                        Write-Verbose -Message 'Add the current object to the results collection'
                        [Void] $output.Add( $template );
                    }
                }
            } else {
                Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
            }
        } catch {  } # Throw away the error because it is false anyway

        return $output;
    }   
}

<#
.SYNOPSIS
    Retrieves users object from Active Directory.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to access Active Directory
    user objects where the ActiveDirectory module is not available.
.PARAMETER Identity
    This is an optional parameter which specifies the name of the object to search for.
.PARAMETER LDAPFilter
    This is an optional parameter which defines and LDAP fileter string to use for the search.
    If you are unfamiliar with LDAP search strings, you can learn by doing a saved query in the
    Active Directory Users and Computers console and looking at the search string. As an additional
    option, you can simply pipe the output through a Where-Object clause to filter the results.
.PARAMETER Server
    This is an optional parameter which specifies the target Domain Controller to search.
.PARAMETER SearchBase
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER SearchScope
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the search.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether an object was located or not.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $adUsers = Get-ADDSUser;

    The preceding example searches for all user objects in the current domain using the current credentials.
.EXAMPLE
    $accountingTeam = Get-ADDSUser -SearchBase 'OU=Accounting Team,DC=labthat,DC=com';

    The preceding example searches for all user objects in the 'Accounting Team' OU.
.EXAMPLE
    $testAccounts = Get-ADDSUser -LDAPFilter '(&(objectClass=user)(sAMAccountName=test*))';

    The preceding example searches for all user objects in the domain that have an account name starting with 'test'.
.EXAMPLE
    $creds = Get-Credential;
    $testUser = Get-ADDSUser -Identity 'testuser' -Server 'MYDC01' -Credential $creds;

    The preceding example searches for a user called 'testuser' on the Domain Controller named 'MYDC01' using 
    the credentials stored in $creds.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Get-ADDSUser {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Enter the desired name to look for' )]
        [String] $Identity = '',

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the desired object type to search for' )]
        [String] $LDAPFilter = '',

        [Parameter( Position = 2, Mandatory = $false, HelpMessage = 'Enter the AD DS Domain Controller name to look for' )]
        [String] $Server = '',

        [Parameter( Position = 3, Mandatory = $false, HelpMessage = 'Enter the AD DS path to start the search' )]
        [String] $SearchBase = '',

        [Parameter( Position = 4, Mandatory = $false, HelpMessage = 'Enter the AD DS path to start the search' )]
        [ValidateSet( 'Base', 'OneLevel', 'Subtree' )]
        [String] $SearchScope = 'Subtree',

        [Parameter( Position = 5, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: Get-ADDSUser';
        Write-Verbose -Message ( " -Identity = {0}" -f $Identity );
        Write-Verbose -Message ( " -LDAPFilter = {0}" -f $LDAPFilter );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -SearchBase = {0}" -f $SearchBase );
        Write-Verbose -Message ( " -SearchScope = {0}" -f $SearchScope );

        [String] $bindString = '';
        [Hashtable] $script:attributeTypes = @{
            'accountExpires' = 'IADsLargeInteger'
            'adminCount' = 'Int32'
            'adminDescription' = 'SingleValueString'
            'badPasswordTime' = 'IADsLargeInteger'
            'badPwdCount' = 'Int32'
            'c' = 'SingleValueString'
            'canonicalName' = 'SingleValueString'
            'cn' = 'SingleValueString'
            'co' = 'SingleValueString'
            'comment' = 'SingleValueString'
            'company' = 'SingleValueString'
            'countryCode' = 'SingleValueString'
            'deliverAndRedirect' = 'Boolean'
            'department' = 'SingleValueString'
            'description' = 'SingleValueString'
            'directReports' = 'MultiValueString'
            'displayName' = 'SingleValueString'
            'distinguishedName' = 'SingleValueString'
            'division' = 'SingleValueString'
            'employeeID' = 'SingleValueString'
            'employeeNumber' = 'SingleValueString'
            'employeeType' = 'SingleValueString'
            'extensionAttribute1' = 'SingleValueString'
            'extensionAttribute2' = 'SingleValueString'
            'extensionAttribute3' = 'SingleValueString'
            'extensionAttribute4' = 'SingleValueString'
            'extensionAttribute5' = 'SingleValueString'
            'extensionAttribute6' = 'SingleValueString'
            'extensionAttribute7' = 'SingleValueString'
            'extensionAttribute8' = 'SingleValueString'
            'extensionAttribute9' = 'SingleValueString'
            'extensionAttribute10' = 'SingleValueString'
            'extensionAttribute11' = 'SingleValueString'
            'extensionAttribute12' = 'SingleValueString'
            'extensionAttribute13' = 'SingleValueString'
            'extensionAttribute14' = 'SingleValueString'
            'extensionAttribute15' = 'SingleValueString'
            'facsimileTelephoneNumber' = 'SingleValueString'
            'gidNumber' = 'Int32'
            'givenName' = 'SingleValueString'
            'homeDirectory' = 'SingleValueString'
            'homeDrive' = 'SingleValueString'
            'homeMDB' = 'SingleValueString'
            'info' = 'SingleValueString'
            'initials' = 'SingleValueString'
            'l' = 'SingleValueString'
            'lastLogonTimestamp' = 'IADsLargeInteger'
            'legacyExchangeDN' = 'SingleValueString'
            'lockoutTime' = 'IADsLargeInteger'
            'loginShell' = 'SingleValueString'
            'logonCount' = 'Int32'
            'mDBOverQuotaLimit' = 'Int32'
            'mDBStorageQuota' = 'Int32'
            'mDBUseDefaults' = 'Boolean'
            'mail' = 'SingleValueString'
            'mailNickname' = 'SingleValueString'
            'manager' = 'SingleValueString'
            'memberOf' = 'MultiValueString'
            'mobile' = 'SingleValueString'
            'ms-DS-ConsistencyGuid' = 'GUID'
            'msDS-parentdistname' = 'SingleValueString'
            'msDS-PrincipalName' = 'SingleValueString'
            'msExchArchiveGUID' = 'GUID'
            'msExchArchiveName' = 'SingleValueString'
            'msExchArchiveStatus' = 'Int32'
            'msExchAssistantName' = 'SingleValueString'
            'msExchBypassModerationLink' = 'MultiValueString'
            'msExchEnableModeration' = 'Boolean'
            'msExchHideFromAddressLists' = 'Boolean'
            'msExchHomeServerName' = 'SingleValueString'
            'msExchLitigationHoldDate' = 'DateTime'
            'msExchLitigationHoldOwner' = 'SingleValueString'
            'msExchMailboxGuid' = 'GUID'
            'msExchMasterAccountHistory' = 'MultiValueStringSid'
            'msExchMasterAccountSid' = 'StringSID'
            'msExchOriginatingForest' = 'MultiValueString'
            'msExchPoliciesExcluded' = 'MultiValueString'
            'msExchPoliciesIncluded' = 'MultiValueString'
            'msExchRecipientDisplayType' = 'Int32'
            'msExchRecipientTypeDetails' = 'IADsLargeInteger'
            'msExchRemoteRecipientType' = 'IADsLargeInteger'
            'msExchResourceCapacity' = 'Int32'
            'msExchResourceDisplay' = 'SingleValueString'
            'msExchResourceMetaData' = 'MultiValueString'
            'msExchResourceProperties' = 'MultiValueString'
            'msExchResourceSearchProperties' = 'MultiValueString'
            'msExchShadowProxyAddresses' = 'MultiValueString'
            'msExchUsageLocation' = 'SingleValueString'
            'msExchVersion' = 'IADsLargeInteger'
            'msExchWhenMailboxCreated' = 'DateTime'
            'msNPAllowDialin' = 'Boolean'
            'msRTCSIP-FederationEnabled' = 'Boolean'
            'msRTCSIP-PrimaryHomeServer' = 'SingleValueString'
            'msRTCSIP-PrimaryUserAddress' = 'SingleValueString'
            'msRTCSIP-UserEnabled' = 'Boolean'
            'msSFU30NisDomain' = 'SingleValueString'
            'o' = 'SingleValueString'
            'objectGUID' = 'GUID'
            'objectSid' = 'StringSID'
            'pager' = 'SingleValueString'
            'physicalDeliveryOfficeName' = 'SingleValueString'
            'postalCode' = 'SingleValueString'
            'postOfficeBox' = 'SingleValueString'
            'primaryGroupID' = 'Int32'
            'proxyAddresses' = 'MultiValueString'
            'publicDelegates' = 'MultiValueString'
            'pwdLastSet' = 'IADsLargeInteger'
            'sAMAccountName' = 'SingleValueString'
            'scriptPath' = 'SingleValueString'
            'servicePrincipalName' = 'MultiValueString'
            'shadowExpire' = 'Int32'
            'shadowFlag' = 'Int32'
            'shadowInactive' = 'Int32'
            'shadowLastChange' = 'Int32'
            'shadowMax' = 'Int32'
            'shadowMin' = 'Int32'
            'shadowWarning' = 'Int32'
            'showInAddressBook' = 'MultiValueString'
            'sIDHistory' = 'MultiValueStringSid'
            'sn' = 'SingleValueString'
            'st' = 'SingleValueString'
            'streetAddress' = 'SingleValueString'
            'targetAddress' = 'SingleValueString'
            'telephoneAssistant' = 'SingleValueString'
            'telephoneNumber' = 'SingleValueString'
            'textEncodedORAddress' = 'SingleValueString'
            'title' = 'SingleValueString'
            'uid' = 'SingleValueString'
            'uidNumber' = 'Int32'
            'unixHomeDirectory' = 'SingleValueString'
            'userAccountControl' = 'Int32'
            'userParameters' = 'TSEncodedBlob'
            'userPrincipalName' = 'SingleValueString'
            'userWorkstations' = 'SingleValueString'
            'whenChanged' = 'DateTime'
            'whenCreated' = 'DateTime'
            'wwWWHomePage' = 'SingleValueString'
        }

        $jsonAttributes = [Collections.ArrayList] @(
            'adminDescription',
            'comment',
            'extensionAttribute1',
            'extensionAttribute2',
            'extensionAttribute3',
            'extensionAttribute4',
            'extensionAttribute5',
            'extensionAttribute6',
            'extensionAttribute7',
            'extensionAttribute8',
            'extensionAttribute9',
            'extensionAttribute10',
            'extensionAttribute11',
            'extensionAttribute12',
            'extensionAttribute13',
            'extensionAttribute14',
            'extensionAttribute15'
        )
    }
    Process { }
    End {
        try {
            if ( $Server -eq '' ) {
                if ( $SearchBase -eq '' ) {
                    $bindString = "LDAP://{0}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name, $SearchBase;
                }
            } else {
                if ( $SearchBase -eq '' ) {
                    $bindString = "LDAP://{0}" -f $Server;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f $Server, $SearchBase;
                }
            }

            Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );

            if ( $null -eq $Credential ) {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString );
            } else {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $Credential.UserName, ( $Credential.GetNetworkCredential().Password ), [DirectoryServices.AuthenticationTypes]::Secure );
            }

            if ( $null -ne $domainRoot.distinguishedName ) {
                $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher;
                $domainSearcher.SearchRoot = $domainRoot;
                $domainSearcher.SearchScope = $SearchScope;
                $domainSearcher.PageSize = 1000;
                $domainSearcher.PropertiesToLoad.Clear();
                $domainSearcher.PropertiesToLoad.AddRange( $script:attributeTypes.Keys );

                if ( $LDAPFilter -eq '' ) {
                    if ( $Identity -eq '' ) {
                        $domainSearcher.Filter = "(&(sAMAccountType=805306368)(sAMAccountName=*))";
                        Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                        $searchResults = $domainSearcher.FindAll();
                    } else {
                        if ( [regex]::Match( $Identity, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                            $domainSearcher.Filter = "(distinguishedName={0})" -f $Identity;
                        } else {
                            $domainSearcher.Filter = "(&(sAMAccountType=805306368)(sAMAccountName={0}))" -f $Identity;
                        }

                        Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                        $searchResults = $domainSearcher.FindOne();
                    }
                } else {
                    $domainSearcher.Filter = $LDAPFilter;
                    Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                    $searchResults = $domainSearcher.FindAll();
                }

                $output = [Collections.ArrayList] @();

                if ( $searchResults.Count -gt 0 ) {
                    Write-Verbose -Message ( "`$searchResults.Count = {0}" -f $searchResults.Count );
                    foreach ( $searchResult in $searchResults )
                    {
                        [Object] $template = [pscustomobject][ordered] @{
                            '_bcObjectType' = 'adUser'
                            '_bcID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'accountExpires' = Get-ADDSAttributeValue -AttributeName 'accountExpires' -SearchResult $searchResult
                            'adminCount' = Get-ADDSAttributeValue -AttributeName 'adminCount' -SearchResult $searchResult
                            'adminDescription' = Get-ADDSAttributeValue -AttributeName 'adminDescription' -SearchResult $searchResult
                            'badPasswordTime' = Get-ADDSAttributeValue -AttributeName 'badPasswordTime' -SearchResult $searchResult
                            'badPwdCount' = Get-ADDSAttributeValue -AttributeName 'badPwdCount' -SearchResult $searchResult
                            'c' = Get-ADDSAttributeValue -AttributeName 'c' -SearchResult $searchResult
                            'canonicalName' = Get-ADDSAttributeValue -AttributeName 'canonicalName' -SearchResult $searchResult
                            'cn' = Get-ADDSAttributeValue -AttributeName 'cn' -SearchResult $searchResult
                            'co' = Get-ADDSAttributeValue -AttributeName 'co' -SearchResult $searchResult
                            'comment' = Get-ADDSAttributeValue -AttributeName 'comment' -SearchResult $searchResult
                            'company' = Get-ADDSAttributeValue -AttributeName 'company' -SearchResult $searchResult
                            'countryCode' = Get-ADDSAttributeValue -AttributeName 'countryCode' -SearchResult $searchResult
                            'department' = Get-ADDSAttributeValue -AttributeName 'department' -SearchResult $searchResult
                            'description' = Get-ADDSAttributeValue -AttributeName 'description' -SearchResult $searchResult
                            'directReports' = Get-ADDSAttributeValue -AttributeName 'directReports' -SearchResult $searchResult
                            'displayName' = Get-ADDSAttributeValue -AttributeName 'displayName' -SearchResult $searchResult
                            'distinguishedName' = Get-ADDSAttributeValue -AttributeName 'distinguishedName' -SearchResult $searchResult
                            'division' = Get-ADDSAttributeValue -AttributeName 'division' -SearchResult $searchResult
                            'employeeID' = Get-ADDSAttributeValue -AttributeName 'employeeID' -SearchResult $searchResult
                            'employeeNumber' = Get-ADDSAttributeValue -AttributeName 'employeeNumber' -SearchResult $searchResult
                            'employeeType' = Get-ADDSAttributeValue -AttributeName 'employeeType' -SearchResult $searchResult
                            'extensionAttribute1' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute1' -SearchResult $searchResult
                            'extensionAttribute2' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute2' -SearchResult $searchResult
                            'extensionAttribute3' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute3' -SearchResult $searchResult
                            'extensionAttribute4' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute4' -SearchResult $searchResult
                            'extensionAttribute5' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute5' -SearchResult $searchResult
                            'extensionAttribute6' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute6' -SearchResult $searchResult
                            'extensionAttribute7' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute7' -SearchResult $searchResult
                            'extensionAttribute8' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute8' -SearchResult $searchResult
                            'extensionAttribute9' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute9' -SearchResult $searchResult
                            'extensionAttribute10' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute10' -SearchResult $searchResult
                            'extensionAttribute11' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute11' -SearchResult $searchResult
                            'extensionAttribute12' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute12' -SearchResult $searchResult
                            'extensionAttribute13' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute13' -SearchResult $searchResult
                            'extensionAttribute14' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute14' -SearchResult $searchResult
                            'extensionAttribute15' = Get-ADDSAttributeValue -AttributeName 'extensionAttribute15' -SearchResult $searchResult
                            'facsimileTelephoneNumber;' = Get-ADDSAttributeValue -AttributeName 'facsimileTelephoneNumber' -SearchResult $searchResult
                            'gidNumber' = Get-ADDSAttributeValue -AttributeName 'gidNumber' -SearchResult $searchResult
                            'givenName' = Get-ADDSAttributeValue -AttributeName 'givenName' -SearchResult $searchResult
                            'homeDirectory' = Get-ADDSAttributeValue -AttributeName 'homeDirectory' -SearchResult $searchResult
                            'homeDrive' = Get-ADDSAttributeValue -AttributeName 'homeDrive' -SearchResult $searchResult
                            'homeMDB' = Get-ADDSAttributeValue -AttributeName 'homeMDB' -SearchResult $searchResult
                            'info' = Get-ADDSAttributeValue -AttributeName 'info' -SearchResult $searchResult
                            'initials' = Get-ADDSAttributeValue -AttributeName 'initials' -SearchResult $searchResult
                            'l' = Get-ADDSAttributeValue -AttributeName 'l' -SearchResult $searchResult
                            'lastLogonTimestamp' = Get-ADDSAttributeValue -AttributeName 'lastLogonTimestamp' -SearchResult $searchResult
                            'legacyExchangeDN' = Get-ADDSAttributeValue -AttributeName 'legacyExchangeDN' -SearchResult $searchResult
                            'lockoutTime' = Get-ADDSAttributeValue -AttributeName 'lockoutTime' -SearchResult $searchResult
                            'loginShell' = Get-ADDSAttributeValue -AttributeName 'loginShell' -SearchResult $searchResult
                            'logonCount' = Get-ADDSAttributeValue -AttributeName 'logonCount' -SearchResult $searchResult
                            'mDBOverQuotaLimit' = Get-ADDSAttributeValue -AttributeName 'mDBOverQuotaLimit' -SearchResult $searchResult
                            'mDBStorageQuota' = Get-ADDSAttributeValue -AttributeName 'mDBStorageQuota' -SearchResult $searchResult
                            'mDBUseDefaults' = Get-ADDSAttributeValue -AttributeName 'mDBUseDefaults' -SearchResult $searchResult
                            'mail' = Get-ADDSAttributeValue -AttributeName 'mail' -SearchResult $searchResult
                            'mailNickname' = Get-ADDSAttributeValue -AttributeName 'mailNickname' -SearchResult $searchResult
                            'manager' = Get-ADDSAttributeValue -AttributeName 'manager' -SearchResult $searchResult
                            'memberOf' = Get-ADDSAttributeValue -AttributeName 'memberOf' -SearchResult $searchResult
                            'mobile' = Get-ADDSAttributeValue -AttributeName 'mobile' -SearchResult $searchResult
                            'ms-DS-ConsistencyGuid' = Get-ADDSAttributeValue -AttributeName 'ms-DS-ConsistencyGuid' -SearchResult $searchResult
                            'msDS-parentdistname' = Get-ADDSAttributeValue -AttributeName 'msDS-parentdistname' -SearchResult $searchResult
                            'msDS-PrincipalName' = Get-ADDSAttributeValue -AttributeName 'msDS-PrincipalName' -SearchResult $searchResult
                            'msExchArchiveGUID' = Get-ADDSAttributeValue -AttributeName 'msExchArchiveGUID' -SearchResult $searchResult
                            'msExchArchiveName' = Get-ADDSAttributeValue -AttributeName 'msExchArchiveName' -SearchResult $searchResult
                            'msExchArchiveStatus' = Get-ADDSAttributeValue -AttributeName 'msExchArchiveStatus' -SearchResult $searchResult
                            'msExchAssistantName' = Get-ADDSAttributeValue -AttributeName 'msExchAssistantName' -SearchResult $searchResult
                            'msExchBypassModerationLink' = Get-ADDSAttributeValue -AttributeName 'msExchBypassModerationLink' -SearchResult $searchResult
                            'msExchEnableModeration' = Get-ADDSAttributeValue -AttributeName 'msExchEnableModeration' -SearchResult $searchResult
                            'msExchHideFromAddressLists' = Get-ADDSAttributeValue -AttributeName 'msExchHideFromAddressLists' -SearchResult $searchResult
                            'msExchHomeServerName' = Get-ADDSAttributeValue -AttributeName 'msExchHomeServerName' -SearchResult $searchResult
                            'msExchLitigationHoldDate' = Get-ADDSAttributeValue -AttributeName 'msExchLitigationHoldDate' -SearchResult $searchResult
                            'msExchLitigationHoldOwner' = Get-ADDSAttributeValue -AttributeName 'msExchLitigationHoldOwner' -SearchResult $searchResult
                            'msExchMailboxGuid' = Get-ADDSAttributeValue -AttributeName 'msExchMailboxGuid' -SearchResult $searchResult
                            'msExchMasterAccountSid' = Get-ADDSAttributeValue -AttributeName 'msExchMasterAccountSid' -SearchResult $searchResult
                            'msExchOriginatingForest' = Get-ADDSAttributeValue -AttributeName 'msExchOriginatingForest' -SearchResult $searchResult
                            'msExchPoliciesExcluded' = Get-ADDSAttributeValue -AttributeName 'msExchPoliciesExcluded' -SearchResult $searchResult
                            'msExchPoliciesIncluded' = Get-ADDSAttributeValue -AttributeName 'msExchPoliciesIncluded' -SearchResult $searchResult
                            'msExchRecipientDisplayType' = Get-ADDSAttributeValue -AttributeName 'msExchRecipientDisplayType' -SearchResult $searchResult
                            'msExchRecipientTypeDetails' = Get-ADDSAttributeValue -AttributeName 'msExchRecipientTypeDetails' -SearchResult $searchResult
                            'msExchRemoteRecipientType' = Get-ADDSAttributeValue -AttributeName 'msExchRemoteRecipientType' -SearchResult $searchResult
                            'msExchResourceCapacity' = Get-ADDSAttributeValue -AttributeName 'msExchResourceCapacity' -SearchResult $searchResult
                            'msExchResourceDisplay' = Get-ADDSAttributeValue -AttributeName 'msExchResourceDisplay' -SearchResult $searchResult
                            'msExchResourceMetaData' = Get-ADDSAttributeValue -AttributeName 'msExchResourceMetaData' -SearchResult $searchResult
                            'msExchResourceSearchProperties' = Get-ADDSAttributeValue -AttributeName 'msExchResourceSearchProperties' -SearchResult $searchResult
                            'msExchShadowProxyAddresses' = Get-ADDSAttributeValue -AttributeName 'msExchShadowProxyAddresses' -SearchResult $searchResult
                            'msExchUsageLocation' = Get-ADDSAttributeValue -AttributeName 'msExchUsageLocation' -SearchResult $searchResult
                            'msExchVersion' = Get-ADDSAttributeValue -AttributeName 'msExchVersion' -SearchResult $searchResult
                            'msExchWhenMailboxCreated' = Get-ADDSAttributeValue -AttributeName 'msExchWhenMailboxCreated' -SearchResult $searchResult
                            'msNPAllowDialin' = Get-ADDSAttributeValue -AttributeName 'msNPAllowDialin' -SearchResult $searchResult
                            'msRTCSIP-FederationEnabled' = Get-ADDSAttributeValue -AttributeName 'msRTCSIP-FederationEnabled' -SearchResult $searchResult
                            'msRTCSIP-PrimaryHomeServer' = Get-ADDSAttributeValue -AttributeName 'msRTCSIP-PrimaryHomeServer' -SearchResult $searchResult
                            'msRTCSIP-PrimaryUserAddress' = Get-ADDSAttributeValue -AttributeName 'msRTCSIP-PrimaryUserAddress' -SearchResult $searchResult
                            'msRTCSIP-UserEnabled' = Get-ADDSAttributeValue -AttributeName 'msRTCSIP-UserEnabled' -SearchResult $searchResult
                            'msSFU30NisDomain' = Get-ADDSAttributeValue -AttributeName 'msSFU30NisDomain' -SearchResult $searchResult
                            'o' = Get-ADDSAttributeValue -AttributeName 'o' -SearchResult $searchResult
                            'objectGUID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'objectSid' = Get-ADDSAttributeValue -AttributeName 'objectSid' -SearchResult $searchResult
                            'pager' = Get-ADDSAttributeValue -AttributeName 'pager' -SearchResult $searchResult
                            'physicalDeliveryOfficeName' = Get-ADDSAttributeValue -AttributeName 'physicalDeliveryOfficeName' -SearchResult $searchResult
                            'postalCode' = Get-ADDSAttributeValue -AttributeName 'postalCode' -SearchResult $searchResult
                            'postOfficeBox' = Get-ADDSAttributeValue -AttributeName 'postOfficeBox' -SearchResult $searchResult
                            'primaryGroupID' = Get-ADDSAttributeValue -AttributeName 'primaryGroupID' -SearchResult $searchResult
                            'proxyAddresses' = Get-ADDSAttributeValue -AttributeName 'proxyAddresses' -SearchResult $searchResult
                            'publicDelegates' = Get-ADDSAttributeValue -AttributeName 'publicDelegates' -SearchResult $searchResult
                            'pwdLastSet' = Get-ADDSAttributeValue -AttributeName 'pwdLastSet' -SearchResult $searchResult
                            'sAMAccountName' = Get-ADDSAttributeValue -AttributeName 'sAMAccountName' -SearchResult $searchResult
                            'scriptPath' = Get-ADDSAttributeValue -AttributeName 'scriptPath' -SearchResult $searchResult
                            'servicePrincipalName' = Get-ADDSAttributeValue -AttributeName 'servicePrincipalName' -SearchResult $searchResult
                            'shadowExpire' = Get-ADDSAttributeValue -AttributeName 'shadowExpire' -SearchResult $searchResult
                            'shadowFlag' = Get-ADDSAttributeValue -AttributeName 'shadowFlag' -SearchResult $searchResult
                            'shadowInactive' = Get-ADDSAttributeValue -AttributeName 'shadowInactive' -SearchResult $searchResult
                            'shadowLastChange' = Get-ADDSAttributeValue -AttributeName 'shadowLastChange' -SearchResult $searchResult
                            'shadowMax' = Get-ADDSAttributeValue -AttributeName 'shadowMax' -SearchResult $searchResult
                            'shadowMin' = Get-ADDSAttributeValue -AttributeName 'shadowMin' -SearchResult $searchResult
                            'shadowWarning' = Get-ADDSAttributeValue -AttributeName 'shadowWarning' -SearchResult $searchResult
                            'sIDHistory' = Get-ADDSAttributeValue -AttributeName 'sIDHistory' -SearchResult $searchResult
                            'sn' = Get-ADDSAttributeValue -AttributeName 'sn' -SearchResult $searchResult
                            'st' = Get-ADDSAttributeValue -AttributeName 'st' -SearchResult $searchResult
                            'streetAddress' = Get-ADDSAttributeValue -AttributeName 'streetAddress' -SearchResult $searchResult
                            'targetAddress' = Get-ADDSAttributeValue -AttributeName 'targetAddress' -SearchResult $searchResult
                            'telephoneAssistant' = Get-ADDSAttributeValue -AttributeName 'telephoneAssistant' -SearchResult $searchResult
                            'telephoneNumber' = Get-ADDSAttributeValue -AttributeName 'telephoneNumber' -SearchResult $searchResult
                            'title' = Get-ADDSAttributeValue -AttributeName 'title' -SearchResult $searchResult
                            'uid' = Get-ADDSAttributeValue -AttributeName 'uid' -SearchResult $searchResult
                            'uidNumber' = Get-ADDSAttributeValue -AttributeName 'uidNumber' -SearchResult $searchResult
                            'unixHomeDirectory' = Get-ADDSAttributeValue -AttributeName 'unixHomeDirectory' -SearchResult $searchResult
                            'userAccountControl' = Get-ADDSAttributeValue -AttributeName 'userAccountControl' -SearchResult $searchResult
                            'userParameters' = Get-ADDSAttributeValue -AttributeName 'userParameters' -SearchResult $searchResult
                            'userPrincipalName' = Get-ADDSAttributeValue -AttributeName 'userPrincipalName' -SearchResult $searchResult
                            'userWorkstations' = Get-ADDSAttributeValue -AttributeName 'userWorkstations' -SearchResult $searchResult
                            'whenChanged' = Get-ADDSAttributeValue -AttributeName 'whenChanged' -SearchResult $searchResult
                            'whenCreated' = Get-ADDSAttributeValue -AttributeName 'whenCreated' -SearchResult $searchResult
                            'wwWWHomePage' = Get-ADDSAttributeValue -AttributeName 'wwWWHomePage' -SearchResult $searchResult
                        }

                        foreach ( $jsonAttribute in $jsonAttributes ) {
                            if ( $template.$jsonAttribute.StartsWith( '{' ) -and $template.$jsonAttribute.EndsWith( '}' ) ) {
                                Write-Verbose -Message ( "The following attribute looks like it might have JSON data = {0}" -f $jsonAttribute );
                                $jsonDataValues = ConvertFrom-JsonString -Value $template.$jsonAttribute;

                                if ( $null -ne $jsonDataValues ) {
                                    Write-Verbose -Message 'Building a JSON document from the attribute value'
                                    $customPropertyName = '';
                                    $customPropertyValue = '';

                                    foreach ( $jsonDataValue in $jsonDataValues.GetEnumerator() ) {
                                        $customPropertyName = "{0}" -f $jsonDataValue.Key;
                                        $customPropertyValue = $jsonDataValue.Value;
                                        Add-Member -InputObject $template -MemberType NoteProperty -Name $customPropertyName -Value $customPropertyValue -ErrorAction SilentlyContinue;
                                    }
                                }
                            }
                        }

                        # Add a method to calculate the Microsoft Services ImmutableID
                        $template | Add-Member -MemberType ScriptMethod -Name ImmutableID {
                            Param()
                            End {
                                $immutableID = ConvertFrom-GuidToImmutableID -Value $this.objectGUID;
                                Write-Verbose -Message ( "`$immutableID = {0}" -f $immutableID );
                                return $immutableID;
                            } # end End
                        } -Force;

                        # Add a method to calculate if the account is enabled
                        $template | Add-Member -MemberType ScriptMethod -Name IsDisabled {
                            Param()
                            End {
                                if ( $this.userAccountControl -band 2 ) {
                                    return $true;
                                } else {
                                    return $false;
                                }
                            } # end End
                        } -Force;

                        Write-Verbose -Message 'Add the current object to the results collection'
                        [Void] $output.Add( $template );
                    }
                }
            } else {
                Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
            }
        } catch {  } # Throw away the error because it is false anyway

        return $output;
    }
}

<#
.SYNOPSIS
    Creates a new AD DS contact.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to create an AD DS contact without
    requiring a specific module to be installed on the system.
.PARAMETER Name
    This is a mandatory parameter which specifies the name of the new AD DS contact.
.PARAMETER Path
    This is a mandatory parameter which defines the path to the target AD DS container.
.PARAMETER Server
    This is an optional parameter which specifies the target directory server.
.PARAMETER GroupScope
    This is a mandatory parameter which defines the scope of the new AD DS group. The valid choices are currently
    limited to the following: DomainLocal, Global, and Universal
.PARAMETER GroupType
    This is a mandatory parameter which defines the type of the new AD DS group. The valid choices are currently
    limited to the following: Distribution, and Security
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the the new object creation.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether an object was created or not.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $newGroup = New-ADDSGroup -Name 'My New Group' -Path 'OU=Groups,DC=labthat,DC=com' -GroupScope Global -GroupType Security;

    The preceding example creates a Global Security group in the Groups OU of the domain.
.EXAMPLE
    $dc = 'MYDC01';
    $newGroup = New-ADDSGroup -Name 'My New Group' -Path 'OU=Groups,DC=labthat,DC=com' -GroupScope Distribution -GroupType Universal -Server $dc;

    The preceding example creates a Universal Distribution group in the Groups OU of the domain on 'MYDC01'.
.EXAMPLE
    $dc = 'MYDC01';
    $creds = Get-Credential;
    $newGroup = New-ADDSGroup -Name 'My New Group' -Path 'OU=Groups,DC=labthat,DC=com' -GroupScope DomainLocal -GroupType Security -Server $dc -Credential $creds;

    The preceding example creates a Domain Local Security group in the Groups OU of the domain on 'MYDC01' using the credentials stored in $creds.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function New-ADDSGroup {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the desired name to look for' )]
        [String] $Name,

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the AD DS Domain Controller name to look for' )]
        [String] $Server = '',

        [Parameter( Position = 2, Mandatory = $true, HelpMessage = 'Enter the desired directory path for the new group' )]
        [String] $Path,

        [Parameter( Position = 3, Mandatory = $true, HelpMessage = 'Enter the desired group scope' )]
        [ValidateSet( 'DomainLocal', 'Global', 'Universal' )]
        [String] $GroupScope,

        [Parameter( Position = 4, Mandatory = $true, HelpMessage = 'Enter the desired group type' )]
        [ValidateSet( 'Distribution', 'Security' )]
        [String] $GroupType,

        [Parameter( Position = 5, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: New-ADDSGroup';
        Write-Verbose -Message ( " -Name = {0}" -f $Name );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -Path = {0}" -f $Path );
        Write-Verbose -Message ( " -GroupScope = {0}" -f $GroupScope );
        Write-Verbose -Message ( " -GroupType = {0}" -f $GroupType );

        if ( $Server -eq '' ) {
            $bindString = "LDAP://{0}/{1}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name, $Path;
        } else {
            $bindString = "LDAP://{0}/{1}" -f $Server, $Path;
        }

        Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );
        
        $returnValue = $false;
    }
    Process { }
    End {
        $commonName = "CN={0}" -f $Name;
        Write-Verbose -Message ( "`$commonName = {0}" -f $commonName );

        if ( $null -eq $Credential ) {
            try {
                $targetContainer = New-Object -TypeName System.DirectoryServices.DirectoryEntry( $bindString );
            } catch {
                Write-Warning -Message ( "Path not found: {0}" -f $bindString );
            }
        } else {
            $userName = $Credential.UserName;
            Write-Verbose -Message ( "`$userName = {0}" -f $userName );
            
            $userPassword = $Credential.GetNetworkCredential().Password;

            try {
                $targetContainer = New-Object -TypeName System.DirectoryServices.DirectoryEntry( $bindString, $userName, $userPassword )
            } catch {
                Write-Warning -Message ( "Path not found: {0}" -f $bindString );
            }
        }

        if ( $GroupType -eq 'Security' ) {
            $calculateGroupType = 0x80000000;   
        } else {
            $calculateGroupType = 0x00000000;
        }

        switch ( $GroupScope ) {
            'DomainLocal' {
                $calculateGroupType = $calculateGroupType -bor 0x00000004;
            } 'Global' {
                $calculateGroupType = $calculateGroupType -bor 0x00000002;
            } 'Universal' {
                $calculateGroupType = $calculateGroupType -bor 0x00000008;
            } default {} # Should not happen
        }

        try {
            $newADDSGroup = $targetContainer.Create( 'Group', $commonName );
            $newADDSGroup.Put( 'sAMAccountName', $Name );
            $newADDSGroup.Put( 'groupType', $calculateGroupType );
            $newADDSGroup.SetInfo();

            $returnValue = $true;
        } catch {
            Write-Warning -Message ( "Unable to create '{0}' in the specified path '{1}'" -f $commonName, $Path );
        }

        return $returnValue;
    }
}

<#
.SYNOPSIS
    Creates a new AD DS organizational unit.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to create an AD DS OU without
    requiring a specific module to be installed on the system.
.PARAMETER Name
    This is a mandatory parameter which specifies the name of the new AD DS organizationalUnit.
.PARAMETER Path
    This is a mandatory parameter which defines the path to the target AD DS container.
.PARAMETER Server
    This is an optional parameter which specifies the target directory server.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the the new object creation.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether an object was created or not.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $newOU = New-ADDSOrganizationalUnit -Name 'Top-level' -Path 'DC=labthat,DC=com';

    The preceding example creates an organizational unit at the top of the domain.
.EXAMPLE
    $dc = 'MYDC01';
    $newOU = New-ADDSOrganizationalUnit -Name 'Top-level' -Path DC=labthat,DC=com' -Server $dc;

    The preceding example creates an organizational unit at the top of the domain on 'MYDC01'.
.EXAMPLE
    $dc = 'MYDC01';
    $creds = Get-Credential;
    $newGroup = New-ADDSOrganizationalUnit -Name 'Top-level' -Path DC=labthat,DC=com' -Server $dc -Credential $creds;

    The preceding example creates an organizational unit at the top of the domain on 'MYDC01' using credentials stored in $creds.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function New-ADDSOrganizationalUnit {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the desired name to create' )]
        [String] $Name,

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the AD DS Domain Controller name to use' )]
        [String] $Server = '',

        [Parameter( Position = 2, Mandatory = $true, HelpMessage = 'Enter the desired directory path for the new organizationalUnit' )]
        [String] $Path,

        [Parameter( Position = 3, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: New-ADDSOrganizationalUnit';
        Write-Verbose -Message ( " -Name = {0}" -f $Name );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -Path = {0}" -f $Path );

        if ( $Server -eq '' ) {
            $bindString = "LDAP://{0}/{1}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name, $Path;
        } else {
            $bindString = "LDAP://{0}/{1}" -f $Server, $Path;
        }
        
        Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );

        $returnValue = $false;
    }
    Process { }
    End {
        $commonName = "CN={0}" -f $Name;
        Write-Verbose -Message ( "`$commonName = {0}" -f $commonName );

        if ( $null -eq $Credential ) {
            try {
                $targetContainer = New-Object -TypeName System.DirectoryServices.DirectoryEntry( $bindString );
            } catch {
                Write-Warning -Message ( "Path not found: {0}" -f $bindString );
            }
        } else {
            $userName = $Credential.UserName;
            Write-Verbose -Message ( "`$userName = {0}" -f $userName );

            $userPassword = $Credential.GetNetworkCredential().Password;

            try {
                $targetContainer = New-Object -TypeName System.DirectoryServices.DirectoryEntry( $bindString, $userName, $userPassword );
            } catch {
                Write-Warning -Message ( "Path not found: {0}" -f $bindString );
            }
        }

        try {
            $newADDSGroup = $targetContainer.Create( 'OrganizationalUnit', $commonName );
            $newADDSGroup.Put( 'ou', $Name );
            $newADDSGroup.SetInfo();

            $returnValue = $true;
        } catch {
            Write-Warning -Message ( "Unable to create '{0}' in the specified path '{1}'" -f $commonName, $Path );
        }

        return $returnValue;
    }
}

<#
.SYNOPSIS
    Used to update values on an Active Directory object.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to update Active Directory
    object attributes where the ActiveDirectory module is not available or desired.
.PARAMETER DistinguishedName
    This is an mandatory parameter which specifies the exact distinguishedName of the
    target object to update.
.PARAMETER Values
    This is aa mandatory parameter which defines a hash table that contains the attribute
    value pairs to update on the target Active Directory object.
.PARAMETER Server
    This is an optional parameter which specifies the target Domain Controller to leverage
    for the object update.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the search.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether an object was updated or not.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $creds = Get-Credential;
    $dc = 'DC1';
    $dn = 'CN=John Doe (JDOE),OU=Employees,OU=Accounts,DC=company,DC=com';
    $vals = @{
        'givenName' = 'John'
        'displayName' = 'Doe, John'
        'sn' = 'Doe'
    }
    Set-ADDSAttribute -DistinguishedName $dn -Server $dc -Credential $creds -Values $vals;

    The preceding example updates the first name, display name, and last name on the object with the distinguished name of
    'CN=John Doe (JDOE),OU=Employees,OU=Accounts,DC=company,DC=com' on the     Domain Controller named 'DC1' using the 
    credentials stored in $creds.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Set-ADDSAttribute {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the object distinguished name' )]
        [String] $DistinguishedName,

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the AD DS Domain Controller name to use' )]
        [String] $Server = '',

        [Parameter( Position = 2, Mandatory = $true, HelpMessage = 'Supply a hashtable with attributes and values to update' )]
        [Hashtable] $Values,

        [Parameter( Position = 3, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: Set-ADDSAttribute';
        Write-Verbose -Message ( " -DistinguishedName = {0}" -f $DistinguishedName );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -Values = {0}" -f $Values );

        if ( $null -ne $Credential ) {
            Write-Verbose -Message ( " -Credential.UserName = {0}" -f $Credential.UserName );
        }

        [String] $bindString = '';
        [Hashtable] $Script:attributeTypes = @{
            'accountExpires' = 'IADsLargeInteger'
            'adminCount' = 'Int32'
            'adminDescription' = 'SingleValueString'
            'c' = 'SingleValueString'
            'cn' = 'SingleValueString'
            'co' = 'SingleValueString'
            'comment' = 'SingleValueString'
            'company' = 'SingleValueString'
            'countryCode' = 'SingleValueString'
            'deliverAndRedirect' = 'Boolean'
            'department' = 'SingleValueString'
            'description' = 'SingleValueString'
            'directReports' = 'MultiValueString'
            'displayName' = 'SingleValueString'
            'division' = 'SingleValueString'
            'dNSHostName' = 'SingleValueString'
            'employeeID' = 'SingleValueString'
            'employeeNumber' = 'SingleValueString'
            'employeeType' = 'SingleValueString'
            'extensionAttribute1' = 'SingleValueString'
            'extensionAttribute2' = 'SingleValueString'
            'extensionAttribute3' = 'SingleValueString'
            'extensionAttribute4' = 'SingleValueString'
            'extensionAttribute5' = 'SingleValueString'
            'extensionAttribute6' = 'SingleValueString'
            'extensionAttribute7' = 'SingleValueString'
            'extensionAttribute8' = 'SingleValueString'
            'extensionAttribute9' = 'SingleValueString'
            'extensionAttribute10' = 'SingleValueString'
            'extensionAttribute11' = 'SingleValueString'
            'extensionAttribute12' = 'SingleValueString'
            'extensionAttribute13' = 'SingleValueString'
            'extensionAttribute14' = 'SingleValueString'
            'extensionAttribute15' = 'SingleValueString'
            'facsimileTelephoneNumber' = 'SingleValueString'
            'gidNumber' = 'Int32'
            'groupType' = 'Int32'
            'givenName' = 'SingleValueString'
            'homeDirectory' = 'SingleValueString'
            'homeDrive' = 'SingleValueString'
            'homeMDB' = 'SingleValueString'
            'info' = 'SingleValueString'
            'initials' = 'SingleValueString'
            'isCriticalSystemObject' = 'Boolean'
            'l' = 'SingleValueString'
            'legacyExchangeDN' = 'SingleValueString'
            'lockoutTime' = 'IADsLargeInteger'
            'loginShell' = 'SingleValueString'
            'logonCount' = 'Int32'
            'mDBOverQuotaLimit' = 'Int32'
            'mDBStorageQuota' = 'Int32'
            'mDBUseDefaults' = 'Boolean'
            'mail' = 'SingleValueString'
            'mailNickname' = 'SingleValueString'
            'managedBy' = 'SingleValueString'
            'manager' = 'SingleValueString'
            'mobile' = 'SingleValueString'
            'ms-DS-ConsistencyGuid' = 'GUID'
            'msExchArchiveGUID' = 'GUID'
            'msExchArchiveName' = 'SingleValueString'
            'msExchArchiveStatus' = 'Int32'
            'msExchAssistantName' = 'SingleValueString'
            'msExchEnableModeration' = 'Boolean'
            'msExchHideFromAddressLists' = 'Boolean'
            'msExchHomeServerName' = 'SingleValueString'
            'msExchLitigationHoldDate' = 'DateTime'
            'msExchLitigationHoldOwner' = 'SingleValueString'
            'msExchMailboxGuid' = 'GUID'
            'msExchMasterAccountSid' = 'StringSID'
            'msExchRecipientDisplayType' = 'Int32'
            'msExchRecipientTypeDetails' = 'IADsLargeInteger'
            'msExchRemoteRecipientType' = 'IADsLargeInteger'
            'msExchResourceCapacity' = 'Int32'
            'msExchResourceDisplay' = 'SingleValueString'
            'msExchUsageLocation' = 'SingleValueString'
            'msExchVersion' = 'IADsLargeInteger'
            'msNPAllowDialin' = 'Boolean'
            'msRTCSIP-FederationEnabled' = 'Boolean'
            'msRTCSIP-PrimaryHomeServer' = 'SingleValueString'
            'msRTCSIP-PrimaryUserAddress' = 'SingleValueString'
            'msRTCSIP-UserEnabled' = 'Boolean'
            'msSFU30NisDomain' = 'SingleValueString'
            'o' = 'SingleValueString'
            'operatingSystem' = 'SingleValueString'
            'operatingSystemVersion' = 'SingleValueString'
            'pager' = 'SingleValueString'
            'physicalDeliveryOfficeName' = 'SingleValueString'
            'postalCode' = 'SingleValueString'
            'postOfficeBox' = 'SingleValueString'
            'pwdLastSet' = 'IADsLargeInteger'
            'sAMAccountName' = 'SingleValueString'
            'scriptPath' = 'SingleValueString'
            'shadowExpire' = 'Int32'
            'shadowFlag' = 'Int32'
            'shadowInactive' = 'Int32'
            'shadowLastChange' = 'Int32'
            'shadowMax' = 'Int32'
            'shadowMin' = 'Int32'
            'shadowWarning' = 'Int32'
            'sn' = 'SingleValueString'
            'st' = 'SingleValueString'
            'streetAddress' = 'SingleValueString'
            'targetAddress' = 'SingleValueString'
            'telephoneAssistant' = 'SingleValueString'
            'telephoneNumber' = 'SingleValueString'
            'title' = 'SingleValueString'
            'uid' = 'SingleValueString'
            'uidNumber' = 'Int32'
            'unixHomeDirectory' = 'SingleValueString'
            'userAccountControl' = 'Int32'
            'userPrincipalName' = 'SingleValueString'
            'userWorkstations' = 'SingleValueString'
            'wwWWHomePage' = 'SingleValueString'
        }
    }
    Process { }
    End {
        try {
            if ( [regex]::Match( $DistinguishedName, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                if ( $Server -eq '' ) {
                    $bindString = "LDAP://{0}/{1}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name, $DistinguishedName;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f $Server, $DistinguishedName;
                }
                Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );
    
                if ( $null -eq $Credential ) {
                    $de = New-Object System.DirectoryServices.DirectoryEntry( $bindString );
                } else {
                    $de = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $Credential.UserName, ( $Credential.GetNetworkCredential().Password ), [DirectoryServices.AuthenticationTypes]::Secure );
                }
    
                if ( $null -ne $de.distinguishedName ) {
                    Write-Verbose -Message 'An object was found at the specified path';

                    foreach ( $key in $Values.Keys ) {
                        $attributeType = '';
                        $attributeValue =  $null;

                        if ( $Script:attributeTypes.Contains( $key ) ) {
                            $attributeType = $Script:attributeTypes[ $key ];
                            $attributeValue = $Values[ $key ];

                            switch ( $attributeType ) {
                                'SingleValueString' {
                                    if ( [String]::IsNullOrEmpty( $attributeValue ) ) {
                                        Write-Verbose -Message ( "Clearing attribute '{0}'" -f $key );
                                        try {
                                            $de.Properties[ $key ].Clear();
                                            $de.CommitChanges();
                                        } catch {
                                            Write-Warning -Message 'Failed to set attribute value. Please check your permissions.';
                                        }
                                    } else {
                                        if ( $attributeValue.GetType().Name -eq 'String' ) {
                                            Write-Verbose -Message ( "Setting attribute '{0}' value to: {1}" -f $key, $attributeValue );

                                            if ( $key -eq 'accountExpires' ) {
                                                if ( $attributeValue -eq 'never' ) {
                                                    try {
                                                        $de.psbase.InvokeSet( $key, 9223372036854775807 );
                                                        $de.CommitChanges();
                                                    } catch {
                                                        Write-Warning -Message 'Failed to set attribute value. Please check your permissions.';
                                                    }
                                                }
                                                # Not ready for prime time
                                                # } else {
                                                #     [DateTime] $dateTime = Get-Date -Date $attributeValue;

                                                #     $iADSLargInteger = [DateTime]::FromFileTime( $SearchResult.Properties.Item( $AttributeName )[ 0 ] ).ToString();
                                                # }
                                            } else {
                                                try {
                                                    $de.psbase.InvokeSet( $key, $attributeValue );
                                                    $de.CommitChanges();
                                                } catch {
                                                    Write-Warning -Message 'Failed to set attribute value. Please check your permissions.';
                                                }
                                            }
                                        }
                                    }
                                } 'IADsLargeInteger' {
                                    switch ( $key ) {
                                        'lockoutTime' {
                                            if ( $attributeValue -eq 0 ) {
                                                Write-Verbose -Message 'Unlocking the account by setting lockoutTime to zero';
                                                $de.psbase.InvokeSet( $key, 0 );
                                                $de.CommitChanges();
                                            } else {
                                                Write-Warning -Message 'The lockoutTime value can only be set to 0 which unlocks the account';
                                            }
                                        } 'pwdLastSet' {
                                            if ( $attributeValue -eq -1 ) {
                                                Write-Verbose -Message 'Changing pwdLastSet to (none)';
                                                $de.psbase.InvokeSet( $key, 0 );
                                                $de.CommitChanges();

                                                Write-Verbose -Message 'Resetting the counter to simulate password was just changed, but the original value is maintained.';
                                                $de.psbase.InvokeSet( $key, -1 );
                                                $de.CommitChanges();
                                            } else {
                                                Write-Warning -Message 'The lockoutTime value can only be set to 0 which unlocks the account';
                                            }
                                        }
                                    }
                                } 'Int32' {
                                    if ( $attributeValue.GetType().Name -eq 'Int32' ) {
                                        Write-Verbose -Message ( "Setting attribute '{0}' value to: {1}" -f $key, $attributeValue );
                                        try {
                                            $de.psbase.InvokeSet( $key, $attributeValue );
                                            $de.CommitChanges();
                                        } catch {
                                            Write-Warning -Message 'Failed to set attribute value. Please check your permissions.';
                                        }
                                    }
                                } 'Boolean' {
                                    if ( $attributeValue.GetType().Name -eq 'Boolean' ) {
                                        Write-Verbose -Message ( "Setting attribute '{0}' value to: {1}" -f $key, $attributeValue );
                                        try {
                                            $de.psbase.InvokeSet( $key, $attributeValue );
                                            $de.CommitChanges();
                                        } catch {
                                            Write-Warning -Message 'Failed to set attribute value. Please check your permissions.';
                                        }
                                    }
                                } 'GUID' {
                                    if ( $attributeValue.GetType().Name -eq 'GUID' ) {
                                        Write-Verbose -Message ( "Setting attribute '{0}' value to: {1}" -f $key, $attributeValue );
                                        try {
                                            $de.psbase.InvokeSet( $key, $attributeValue );
                                            $de.CommitChanges();
                                        } catch {
                                            Write-Warning -Message 'Failed to set attribute value. Please check your permissions.';
                                        }
                                    }
                                }
                            }
                        } else {
                            Write-Warning -Message ( "The attribute named {0} cannot be set with this cmdlet" -f $key );
                        }
                    }
                    
                } else {
                    Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
                }
            } else {
                Write-Warning -Message ( "The following is not a proper distinguished name value: {0}" -f $DistinguishedName );
            }
        } catch { } # Throw away the error because it is false anyway
    }
}

<#
.SYNOPSIS
    Used to update JSON data in the specified string attribute on an Active Directory object.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to update Active Directory
    object attributes where the ActiveDirectory module is not available or desired.
.PARAMETER DistinguishedName
    This is an mandatory parameter which specifies the exact distinguishedName of the
    target object to update.
.PARAMETER AttributeName
    This is aa mandatory parameter which defines the AD DS attribute to update on the
    target object.
.PARAMETER Server
    This is an optional parameter which specifies the target Domain Controller to leverage
    for the object update.
.PARAMETER JsonName
    This is a mandatory parameter which specifies the Json value name to be added and/or updated
    on the target object.
.PARAMETER JsonValue
    This is a mandatory parameter which specifies the Json value to be added and/or updated
    on the target object.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the search.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether an object was updated or not.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $testUser = Get-ADDSUser -Identity 'testuser';
    Set-ADDSJsonAttribute -DistinguishedName $testUser.distinguishedName -AttributeName 'adminDescription' -JsonName 'Test' -JsonValue 'Data';

    The preceding example searches for a user called 'testuser' on the Domain Controller named 'DC1' using 
    the credentials stored in $creds. Once that object is returned, a new Json data value is added in the
    adminDescription attribute called 'Test' with a value of 'Data'.
.EXAMPLE
    $creds = Get-Credential;
    $dc = 'DC1';
    $testUser = Get-ADDSUser -Identity 'testuser' -Server $dc -Credential $creds;
    Set-ADDSJsonAttribute -DistinguishedName $testUser.distinguishedName -Server $dc -Credential $creds -AttributeName 'adminDescription' -JsonName 'Test' -JsonValue 'Data';

    The preceding example searches for a user called 'testuser' on the Domain Controller named 'DC1' using 
    the credentials stored in $creds. Once that object is returned, a new Json data value is added in the
    adminDescription attribute called 'Test' with a value of 'Data'.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Set-ADDSJsonAttribute {
    [CmdletBinding()]
    Param
    (
        [Parameter(
            Position = 0,
            Mandatory = $true,
            HelpMessage = 'Enter the desired name to look for'
        )]
        [String] $DistinguishedName,

        [Parameter(
            Position = 1,
            Mandatory = $false,
            HelpMessage = 'Enter the AD DS Domain Controller name to look for'
        )]
        [String] $Server = '',

        [Parameter(
            Position = 2,
            Mandatory = $true,
            HelpMessage = 'Enter the AD DS path to start the search'
        )]
        [String] $AttributeName,

        [Parameter(
            Position = 3,
            Mandatory = $true,
            HelpMessage = 'Enter the name of the Json value'
        )]
        [String] $JsonName,

        [Parameter(
            Position = 4,
            Mandatory = $true,
            HelpMessage = 'Enter the Json value'
        )]
        [String] $JsonValue,

        [Parameter(
            Position = 5,
            Mandatory = $false,
            HelpMessage = 'Enter a credential to perform the task'
        )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: Set-ADDSJsonAttribute';
        Write-Verbose -Message ( " -DistinguishedName = {0}" -f $DistinguishedName );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -AttributeName = {0}" -f $AttributeName );
        Write-Verbose -Message ( " -JsonName = {0}" -f $JsonName );
        Write-Verbose -Message ( " -JsonValue = {0}" -f $JsonValue );

        [String] $bindString = '';
        [String] $jsonDataString = '';
    }
    Process { }
    End {
        try {
            if ( [regex]::Match( $DistinguishedName, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                if ( $Server -eq '' ) {
                    $bindString = "LDAP://{0}/{1}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name, $DistinguishedName;
                } else {
                    $bindString = "LDAP://{0}/{1}" -f $Server, $DistinguishedName;
                }
                Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );

                if ( $null -eq $Credential ) {
                    $de = New-Object System.DirectoryServices.DirectoryEntry( $bindString );
                } else {
                    $de = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $Credential.UserName, ( $Credential.GetNetworkCredential().Password ), [DirectoryServices.AuthenticationTypes]::Secure );
                }

                if ( $null -ne $de.distinguishedName ) {
                    Write-Verbose -Message 'An object was found at the specified path';
                    if ( $de.Properties.Contains( $AttributeName ) ) {
                        $currentAttributeValue = $de.Properties.$AttributeName[ 0 ];
                        Write-Verbose -Message ( "`$currentAttributeValue = {0}" -f $currentAttributeValue );
                    }

                    if ( $null -ne $currentAttributeValue ) {
                        Write-Verbose -Message 'The target attribute has a value';
                        if ( $currentAttributeValue.StartsWith( '{' ) -and $currentAttributeValue.EndsWith( '}') ) {
                            Write-Verbose -Message 'The attribute has data that looks like it is in json format';
                            $jsonDataValues = ConvertFrom-Json -InputObject $currentAttributeValue;

                            if ( $null -ne $jsonDataValues.$JsonName ) {
                                Write-Verbose -Message ( "`$jsonDataValues.$JsonName = {0}" -f $jsonDataValues.$JsonName );
                                $jsonDataValues.$JsonName = $JsonValue;
                                $jsonDataString = ConvertTo-Json -InputObject $jsonDataValues -Compress;
                            } else {
                                Add-Member -InputObject $jsonDataValues -MemberType NoteProperty -Name $JsonName -Value $JsonValue;
                                $jsonDataString = ConvertTo-Json -InputObject $jsonDataValues -Compress;
                            }
                        } else {
                            Write-Warning -Message 'The target attribute contains incompatible Json data';
                            return $false;
                        }
                    } else {
                        [Object] $template = [pscustomobject][ordered] @{
                            $JsonName = $JsonValue
                        }
                        $jsonDataString = ConvertTo-Json -InputObject $template -Compress;
                    }

                    try {
                        $de.psbase.InvokeSet( $AttributeName, $jsonDataString );
                        $de.CommitChanges();
                    }
                    catch {
                        Write-Warning -Message 'Failed to set attribute value. Please check your permissions.';
                        return $false;
                    }
                } else {
                    Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
                    return $false;
                }

                return $true;
            } else {
                Write-Warning -Message ( "The following is not a proper distinguished name value: {0}" -f $DistinguishedName );
                return $false;
            }
        } catch {
            return $false;
        } # Throw away the error because it is false anyway
    }
}

<#
.SYNOPSIS
    Checks for an AD DS object.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to check for the existence
    of an Active Directory object without special modules.
.PARAMETER Name
    This is a mandatory parameter which specifies the name of the object to search for.
.PARAMETER ObjectType
    This is a mandatory parameter which defines the type of object to search for. The valid choices are currently
    limited to the following: Computer, Contact, Group, OU, and User
.PARAMETER ComputerName
    This is an optional parameter which specifies the target Domain Controller to search.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the search.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether an object was located or not.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $found = Test-ADDSObjectExists -Name fduncan -ObjectType User;

    The preceding example searches for a user account called 'fduncan' from the current AD DS environment.
.EXAMPLE
    $found = Test-ADDSObjectExists -Name 'Domain Users' -ObjectType Group -ComputerName 'MYDC01';

    The preceding example searches for a group called 'Domain Users' on the Domain Controller named 'MYDC01'.
.EXAMPLE
    $creds = Get-Credential;
    $found = Test-ADDSObjectExists -Name 'Domain Users' -ObjectType Group -ComputerName 'MYDC01' -Credential $creds;

    The preceding example searches for a group called 'Domain Users' on the Domain Controller named 'MYDC01' using 
    the credentials stored in $creds.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Test-ADDSObjectExists {
    Param
    (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the desired identity to look for' )]
        [String] $Identity,

        [Parameter( Position = 1, Mandatory = $true, HelpMessage = 'Enter the desired object type to search for' )]
        [ValidateSet( 'Computer', 'Contact', 'Group', 'OU', 'User' )]
        [String] $ObjectType,

        [Parameter( Position = 2, Mandatory = $false, HelpMessage = 'Enter the AD DS Domain Controller name to look for' )]
        [String] $Server = '',

        [Parameter( Position = 3, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        [String] $bindString = '';
        [Object] $domainRoot = $null;
        [Boolean] $returnValue = $false;
    }
    Process { }
    End {
        try {
            if ( $Server -eq '' ) {
                $bindString = "LDAP://{0}" -f [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name;
            } else {
                $bindString = "LDAP://{0}" -f $Server;
            }

            if ( $null -eq $Credential ) {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString );
            } else {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $Credential.UserName, ( $Credential.GetNetworkCredential().Password ), [DirectoryServices.AuthenticationTypes]::Secure );
            }

            if ( $null -ne $domainRoot.distinguishedName ) {
                $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher;
                $domainSearcher.SearchRoot = $domainRoot;

                if ( $Identity.Contains( ',DC=' ) ) {
                    $ldapFilter = "(distinguishedName={0})" -f $Identity;
                } else {
                    switch ( $ObjectType ) {
                        'Computer' {
                            $ldapFilter = "(&(sAMAccountType=805306369)(sAMAccountName={0}$))" -f $Identity;
                        } 'Contact' {
                            $ldapFilter = "(&(objectCategory=person)(objectClass=contact)(mail={0}))" -f $Identity;
                        } 'Group' {
                            $ldapFilter = "(&(objectCategory=group)(sAMAccountName={0}))" -f $Identity;
                        } 'OU' {
                            $ldapFilter = "(&(objectCategory=organizationalUnit)(ou={0}))" -f $Identity;
                        } 'User' {
                            if ( $Identity.Contains( '\' ) ) {
                                $ldapFilter = "(&(sAMAccountType=805306368)(sAMAccountName={0}))" -f $Identity.Split( '\' )[ 1 ];
                            } else {
                                $ldapFilter = "(&(sAMAccountType=805306368)(sAMAccountName={0}))" -f $Identity;
                            }
                        } default { } # Unsupported, fail gracefully and return false
                    }
                }

                $domainSearcher.Filter = $ldapFilter;
                $domainSearchResult = $domainSearcher.FindOne();

                if ( $domainSearchResult.Count -eq 1 ) {
                    $returnValue = $true;
                }
            } else {
                Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
            }
        } catch {  } # Throw away the error because it is false anyway

        return $returnValue;
    }   
}

#endregion

#region Active Directory Lightweight Directory Services Cmdlets

<#
.SYNOPSIS
    Retrieves userProxyFull object from Active Directory Lightweight Directory Services.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to access Active Directory LDS
    userProxyFull objects where the ActiveDirectory module is not available.
.PARAMETER Identity
    This is an optional parameter which specifies the name of the object to search for.
.PARAMETER LDAPFilter
    This is an optional parameter which defines and LDAP fileter string to use for the search.
    If you are unfamiliar with LDAP search strings, you can learn by doing a saved query in the
    Active Directory Users and Computers console and looking at the search string. As an additional
    option, you can simply pipe the output through a Where-Object clause to filter the results.
.PARAMETER Server
    This is an optional parameter which specifies the target Domain Controller to search.
.PARAMETER SearchBase
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER SearchScope
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the search.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether an object was located or not.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $adLDSUsers = Get-ADLDSUserProxyFull -Server LDS1 -SearchBase 'DC=Enterprise,DC=LDAP';

    The preceding example searches for all userProxyFull objects from LDS1 at path 'DC=Enterprise,DC=LDAP'
    using the current credentials.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Get-ADLDSUserProxyFull {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Enter the desired name to look for' )]
        [String] $Identity = '',

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the desired object type to search for' )]
        [String] $LDAPFilter = '',

        [Parameter( Position = 2, Mandatory = $true, HelpMessage = 'Enter the AD LDS server name to look for' )]
        [String] $Server,

        [Parameter( Position = 3, Mandatory = $true, HelpMessage = 'Enter the AD LDS path to start the search' )]
        [String] $SearchBase,

        [Parameter( Position = 4, Mandatory = $false, HelpMessage = 'Enter the AD LDS path to start the search' )]
        [ValidateSet( 'Base', 'OneLevel', 'Subtree' )]
        [String] $SearchScope = 'Subtree',

        [Parameter( Position = 5, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: Get-ADLDSUserProxyFull';
        Write-Verbose -Message ( " -Identity = {0}" -f $Identity );
        Write-Verbose -Message ( " -LDAPFilter = {0}" -f $LDAPFilter );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -SearchBase = {0}" -f $SearchBase );
        Write-Verbose -Message ( " -SearchScope = {0}" -f $SearchScope );

        [String] $bindString = '';
        [Hashtable] $script:attributeTypes = @{
            'canonicalName' = 'SingleValueString'
            'cn' = 'SingleValueString'
            'company' = 'SingleValueString'
            'department' = 'SingleValueString'
            'description' = 'SingleValueString'
            'directReports' = 'MultiValueString'
            'displayName' = 'SingleValueString'
            'distinguishedName' = 'SingleValueString'
            'division' = 'SingleValueString'
            'employeeID' = 'SingleValueString'
            'employeeNumber' = 'SingleValueString'
            'employeeType' = 'SingleValueString'
            'givenName' = 'SingleValueString'
            'l' = 'SingleValueString'
            'lastLogonTimestamp' = 'IADsLargeInteger'
            'mail' = 'SingleValueString'
            'manager' = 'SingleValueString'
            'memberOf' = 'MultiValueString'
            'mobile' = 'SingleValueString'
            'msDS-PrincipalName' = 'SingleValueString'
            'objectGUID' = 'GUID'
            'objectSid' = 'StringSID'
            'pager' = 'SingleValueString'
            'physicalDeliveryOfficeName' = 'SingleValueString'
            'postalCode' = 'SingleValueString'
            'postOfficeBox' = 'SingleValueString'
            'sn' = 'SingleValueString'
            'st' = 'SingleValueString'
            'streetAddress' = 'SingleValueString'
            'telephoneNumber' = 'SingleValueString'
            'title' = 'SingleValueString'
            'uid' = 'SingleValueString'
            'userPrincipalName' = 'SingleValueString'
            'whenChanged' = 'DateTime'
            'whenCreated' = 'DateTime'
        }
    }
    Process { }
    End {
        try {
            $bindString = "LDAP://{0}/{1}" -f $Server, $SearchBase;
            Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );

            if ( $null -eq $Credential ) {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString );
            } else {
                $domainRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $Credential.UserName, ( $Credential.GetNetworkCredential().Password ), [DirectoryServices.AuthenticationTypes]::Secure );
            }

            if ( $null -ne $domainRoot.distinguishedName ) {
                $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher;
                $domainSearcher.SearchRoot = $domainRoot;
                $domainSearcher.SearchScope = $SearchScope;
                $domainSearcher.PageSize = 1000;
                $domainSearcher.PropertiesToLoad.Clear();
                $domainSearcher.PropertiesToLoad.AddRange( $script:attributeTypes.Keys );

                if ( $Identity -eq '' ) {
                    $domainSearcher.Filter = "(&(objectCategory=person)(objectClass=userProxyFull))";
                    Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                    $searchResults = $domainSearcher.FindAll();
                } else {
                    if ( [regex]::Match( $Identity, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                        $domainSearcher.Filter = "(distinguishedName={0})" -f $Identity;
                    } else {
                        $domainSearcher.Filter = "(&(objectCategory=person)(objectClass=userProxyFull)(uid={0}))" -f $Identity;
                    }

                    Write-Verbose -Message ( "`$domainSearcher.Filter = {0}" -f $domainSearcher.Filter );
                    $searchResults = $domainSearcher.FindOne();
                }

                $output = [Collections.ArrayList] @();

                if ( $searchResults.Count -gt 0 ) {
                    Write-Verbose -Message ( "`$searchResults.Count = {0}" -f $searchResults.Count );
                    foreach ( $searchResult in $searchResults )
                    {
                        [Object] $template = [pscustomobject][ordered] @{
                            '_bcObjectType' = 'adLDSUser'
                            '_bcID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'canonicalName' = Get-ADDSAttributeValue -AttributeName 'canonicalName' -SearchResult $searchResult
                            'cn' = Get-ADDSAttributeValue -AttributeName 'cn' -SearchResult $searchResult
                            'company' = Get-ADDSAttributeValue -AttributeName 'company' -SearchResult $searchResult
                            'department' = Get-ADDSAttributeValue -AttributeName 'department' -SearchResult $searchResult
                            'description' = Get-ADDSAttributeValue -AttributeName 'description' -SearchResult $searchResult
                            'directReports' = Get-ADDSAttributeValue -AttributeName 'directReports' -SearchResult $searchResult
                            'displayName' = Get-ADDSAttributeValue -AttributeName 'displayName' -SearchResult $searchResult
                            'distinguishedName' = Get-ADDSAttributeValue -AttributeName 'distinguishedName' -SearchResult $searchResult
                            'givenName' = Get-ADDSAttributeValue -AttributeName 'givenName' -SearchResult $searchResult
                            'l' = Get-ADDSAttributeValue -AttributeName 'l' -SearchResult $searchResult
                            'lastLogonTimestamp' = Get-ADDSAttributeValue -AttributeName 'lastLogonTimestamp' -SearchResult $searchResult
                            'mail' = Get-ADDSAttributeValue -AttributeName 'mail' -SearchResult $searchResult
                            'manager' = Get-ADDSAttributeValue -AttributeName 'manager' -SearchResult $searchResult
                            'memberOf' = Get-ADDSAttributeValue -AttributeName 'memberOf' -SearchResult $searchResult
                            'mobile' = Get-ADDSAttributeValue -AttributeName 'mobile' -SearchResult $searchResult
                            'msDS-PrincipalName' = Get-ADDSAttributeValue -AttributeName 'msDS-PrincipalName' -SearchResult $searchResult
                            'objectGUID' = Get-ADDSAttributeValue -AttributeName 'objectGUID' -SearchResult $searchResult
                            'objectSid' = Get-ADDSAttributeValue -AttributeName 'objectSid' -SearchResult $searchResult
                            'pager' = Get-ADDSAttributeValue -AttributeName 'pager' -SearchResult $searchResult
                            'physicalDeliveryOfficeName' = Get-ADDSAttributeValue -AttributeName 'physicalDeliveryOfficeName' -SearchResult $searchResult
                            'postalCode' = Get-ADDSAttributeValue -AttributeName 'postalCode' -SearchResult $searchResult
                            'postOfficeBox' = Get-ADDSAttributeValue -AttributeName 'postOfficeBox' -SearchResult $searchResult
                            'sn' = Get-ADDSAttributeValue -AttributeName 'sn' -SearchResult $searchResult
                            'st' = Get-ADDSAttributeValue -AttributeName 'st' -SearchResult $searchResult
                            'streetAddress' = Get-ADDSAttributeValue -AttributeName 'streetAddress' -SearchResult $searchResult
                            'telephoneNumber' = Get-ADDSAttributeValue -AttributeName 'telephoneNumber' -SearchResult $searchResult
                            'title' = Get-ADDSAttributeValue -AttributeName 'title' -SearchResult $searchResult
                            'uid' = Get-ADDSAttributeValue -AttributeName 'uid' -SearchResult $searchResult
                            'userPrincipalName' = Get-ADDSAttributeValue -AttributeName 'userPrincipalName' -SearchResult $searchResult
                            'whenChanged' = Get-ADDSAttributeValue -AttributeName 'whenChanged' -SearchResult $searchResult
                            'whenCreated' = Get-ADDSAttributeValue -AttributeName 'whenCreated' -SearchResult $searchResult
                        }

                        Write-Verbose -Message 'Add the current object to the results collection'
                        [Void] $output.Add( $template );
                    }
                }
            } else {
                Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
            }
        } catch {  } # Throw away the error because it is false anyway

        return $output;
    }
}

<#
.SYNOPSIS
    Creates a new AD DS organizational unit.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to create an AD LDS OU without
    requiring a specific module to be installed on the system.
.PARAMETER Name
    This is a mandatory parameter which specifies the name of the new AD LDS organizational unit.
.PARAMETER Path
    This is a mandatory parameter which defines the path to the target AD DS container.
.PARAMETER Server
    This is a mandatory parameter which defines the AD LDS server.
.PARAMETER Port
    This is an optional parameter which defines the AD LDS server connection port
.PARAMETER Credential
    This is an optional parameter which defines the credential to use for the the new object creation.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether an object was created or not.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $ldsServer = 'MYLDS01';
    $newOU = New-ADLDSOrganizationalUnit -Name 'Top-level' -Path DC=labthat,DC=com' -Server $ldsServer;

    The preceding example creates an organizational unit at the top of the domain on 'MYLDS01'.
.EXAMPLE
    $ldsServer = 'MYLDS01';
    $creds = Get-Credential;
    $newOU = New-ADLDSOrganizationalUnit -Name 'Top-level' -Path DC=labthat,DC=com' -Server $ldsServer -Credential $creds;

    The preceding example creates an organizational unit at the top of the domain on 'MYLDS01' using credentials stored in $creds.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function New-ADLDSOrganizationalUnit {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the desired name to look for' )]
        [String] $Name,

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the AD LDS server name to connect to' )]
        [String] $Server = '',

        [Parameter( Position = 2, Mandatory = $false, HelpMessage = 'Enter the desired AD LDS port to connect to' )]
        [Int32] $Port = 389,

        [Parameter( Position = 3, Mandatory = $true, HelpMessage = 'Enter the desired directory path for the new group' )]
        [String] $Path,

        [Parameter( Position = 4, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: New-ADLDSOrganizationalUnit';
        Write-Verbose -Message ( " -Name = {0}" -f $Name );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -Path = {0}" -f $Path );
        Write-Verbose -Message ( " -Port = {0}" -f $Port );

        if ( $Port -eq 389 ) {
            $bindString = "LDAP://{0}/{1}" -f $Server, $Path;
        } else {
            $bindString = "LDAP://{0}/{1}:{2}" -f $Server, $Path, $Port.ToString();
        }

        Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );
        
        $returnValue = $false;
    }
    Process { }
    End {
        $commonName = "OU={0}" -f $Name;
        Write-Verbose -Message ( "`$commonName = {0}" -f $commonName );

        if ( $Credential -eq $null ) {
            try {
                $targetContainer = New-Object -TypeName System.DirectoryServices.DirectoryEntry( $bindString );
            } catch {
                Write-Warning -Message ( "Path not found: {0}" -f $bindString );
            }
        } else {
            $userName = $Credential.UserName;
            Write-Verbose -Message ( "`$userName = {0}" -f $userName );

            $userPassword = $Credential.GetNetworkCredential().Password;

            try {
                $targetContainer = New-Object -TypeName System.DirectoryServices.DirectoryEntry( $bindString, $userName, $userPassword );
            } catch {
                Write-Warning -Message ( "Path not found: {0}" -f $bindString );
            }
        }

        try {
            $newADDSGroup = $targetContainer.Create( 'OrganizationalUnit', $commonName );
            $newADDSGroup.Put( 'ou', $Name );
            $newADDSGroup.SetInfo();

            $returnValue = $true;
        } catch {
            Write-Warning -Message ( "Unable to create '{0}' in the specified path '{1}'" -f $commonName, $Path );
        }

        return $returnValue;
    }
}

<#
.SYNOPSIS
    Creates a new AD LDS user.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to create an AD LDS user without
    requiring a specific module to be installed on the system.
.PARAMETER Name
    This is a mandatory parameter which specifies the name of the new AD LDS user.
.PARAMETER Path
    This is a mandatory parameter which defines the path to the target AD LDS container.
.PARAMETER Server
    This is an mandatory parameter which defines the AD LDS server.
.PARAMETER Credential
    This cmdlet returns a boolean value indicating whether an object was created or not.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether an object was created or not.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.EXAMPLE
    $newUser = New-ADLDSUser -Name 'cisco' -Path 'OU=Application Accounts,DC=Enterprise,DC=LDAP';

    The preceding example creates an AD LDS user in the Application Accounts OU of the DC=Enterprise,DC=LDAP context.
.EXAMPLE
    $dc = 'MYDC01';
    $creds = Get-Credential;
    $newUser = New-ADLDSUser -Name 'cisco' -Path 'OU=Application Accounts,DC=Enterprise,DC=LDAP' -Credential $creds;

    The preceding example creates an AD LDS user in the Application Accounts OU of the DC=Enterprise,DC=LDAP context
    with the specified $creds.
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function New-ADLDSUser {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the desired name to create' )]
        [String] $Name,

        [Parameter( Position = 1, Mandatory = $true, HelpMessage = 'Enter the AD LDS server name to use' )]
        [String] $Server,

        [Parameter( Position = 2, Mandatory = $true, HelpMessage = 'Enter the desired directory path for the new user' )]
        [String] $Path,

        [Parameter( Position = 3, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: New-ADLDSUser';
        Write-Verbose -Message ( " -Name = {0}" -f $Name );
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -Path = {0}" -f $Path );

        $accountCreated = $false;
        $bindString = "LDAP://{0}/{1}" -f $ComputerName, $Path;
        Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );
        
        [Object] $output = [pscustomobject][ordered] @{
            'CommonName' = ''
            'DistinguishedName' =  ''
            'Password' = ''
            'Status' = ''
        }

        if ( $null -eq ( Get-Command -Name New-Password -ErrorAction SilentlyContinue ) ) {
            return $returnValue;
        } else {
            $newPassword = New-Password -Length 21;
            Write-Verbose -Message ( "`$newPassword = {0}" -f $newPassword );
            $output.Password = $newPassword;
        }
    }
    Process { }
    End {
        $commonName = "CN={0}" -f $Name.ToUpper();
        Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );
        $output.CommonName = $commonName;

        $distinguishedName = "{0},{1}" -f $commonName, $Path;
        Write-Verbose -Message ( "`$distinguishedName = {0}" -f $distinguishedName );
        $output.DistinguishedName = $distinguishedName;

        if ( $null -eq $Credential ) {
            try {
                $targetContainer = New-Object -TypeName System.DirectoryServices.DirectoryEntry( $bindString )
            } catch {
                Write-Warning -Message ( "Path not found: {0}" -f $bindString );
                $output.Status = 'Connection or path issue';
            }
        } else {
            $userName = $Credential.UserName;
            $userPassword = $Credential.GetNetworkCredential().Password;

            try {
                $targetContainer = New-Object -TypeName System.DirectoryServices.DirectoryEntry( $bindString, $userName, $userPassword )
            } catch {
                Write-Warning -Message ( "Path not found: {0}" -f $bindString );
                $output.Status = 'Connection or path issue';
            }
        }

        try {
            Write-Verbose -Message 'Attempting to create AD LDS user object';
            $newADLDSObject = $targetContainer.Create( 'User', $commonName );
            $newADLDSObject.SetInfo();
            $output.Status = 'Created';
            
            $newADLDSObject.psbase.Invoke( 'SetPassword', $newPassword );
            $newADLDSObject.CommitChanges();
            $output.Status = 'Password set';

            $accountCreated = $true;
        } catch {
            Write-Warning -Message ( "Unable to create '{0}' in the specified path '{1}'" -f $commonName, $Path );
        }

        if ( $accountCreated ) {
            Write-Verbose -Message 'Update attributes on new AD LDS user object'
            $bindString = "LDAP://{0}/{1}" -f $ComputerName, $distinguishedName;
            Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );

            if ( $null -eq $Credential ) {
                try {
                    $de = New-Object -TypeName System.DirectoryServices.DirectoryEntry( $bindString );
                } catch {
                    Write-Warning -Message ( "Path not found: {0}" -f $bindString );
                    $output.Status = 'Connection or path issue for new object';
                }
            } else {
                $userName = $Credential.UserName;
                $userPassword = $Credential.GetNetworkCredential().Password;

                try {
                    $de = New-Object -TypeName System.DirectoryServices.DirectoryEntry( $bindString, $userName, $userPassword )
                } catch {
                    Write-Warning -Message ( "Path not found: {0}" -f $bindString );
                    $output.Status = 'Connection or path issue for new object';
                }
            }

            Write-Verbose -Message 'Setting the msDS-UserAccountDisabled attribute to FALSE';
            $de.Properties['msDS-UserAccountDisabled'][ 0 ] = $false;
            $de.CommitChanges();
            $output.Status = 'Account enabled';
            $de.RefreshCache();

            Write-Verbose -Message 'Setting the msDS-UserDontExpirePassword attribute to TRUE';
            $de.psbase.InvokeSet( 'msDS-UserDontExpirePassword', $true );
            $de.CommitChanges();
            $output.Status = 'Password set to not expire';
        }

        Write-Output -InputObject $output;
    }
}

#endregion

#region Helper Cmdlets

<#
.SYNOPSIS
    Used to retrieve the file name for the file.
.DESCRIPTION

.PARAMETER Base64
    This is a mandatory parameter which includes the base64 string to be exported into a file (typically an image).
.PARAMETER Path
    This is a mandatory parameter which specifies the target file path.
.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS
    Generates a file using the base64 string data.
.EXAMPLE
    $mystring = ConvertFrom-Base64StringToFile -Base64 $gobbledgook -Path 'C:\Temp\source.png';

    This example converts a base 64 encoded string into an image file.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function ConvertFrom-Base64StringToFile {
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $true, HelpMessage = 'Specify the path to the source string' )]
        [String] $Base64,

        [Parameter( Mandatory = $true, HelpMessage = 'Specify the path to the target file' )]
        [String] $Path
    )

    Write-Verbose -Message 'Cmdlet: ConvertFrom-Base64StringToFile';
    Write-Verbose -Message ( " -Base64 = {0}" -f $Base64 );
    Write-Verbose -Message ( " -Path = {0}" -f $Path );

    [String] $parentPath = Split-Path -Path $Path -Parent;

    Write-Verbose -Message 'Check parent path to see if it exists'
    if ( Test-Path -Path $parentPath ) {
        Write-Verbose -Message 'Convert supplied string from base 64 value';
        $realValue = [Convert]::FromBase64String( $Base64 );

        Set-Content -Path $Path -Value $realValue -Encoding Byte -Force;
    }
}

function ConvertFrom-GuidToImmutableID {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, HelpMessage = 'Specify the source GUID string' )]
        [String] $Value
    )

    Write-Verbose -Message 'FUNCTION: ConvertFrom-GuidToImmutableID';
    Write-Verbose -Message ( " -Value = {0}" -f $Value );

    try {
        $objectGuid = [Guid] $Value;
        $immutableID = [Convert]::ToBase64String( $objectGuid.ToByteArray() );
    } catch {
        $immutableID = '';
    }

    return $immutableID;
}

<#
.SYNOPSIS
    Used to retrieve the base64 encoded string from the source file.
.DESCRIPTION

.PARAMETER Path
    This is a mandatory parameter which specifies the source file path.
.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS
    Returns a base 64 encoded string from the source file.
.EXAMPLE
    $mystring = ConvertFrom-FileToBase64String -Path 'C:\Temp\source.png';

    This example converts an image file to a base 64 encoded string.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function ConvertFrom-FileToBase64String {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, HelpMessage = 'Specify the path to the source file' )]
        [String] $Path
    )

    Write-Verbose -Message 'Cmdlet: ConvertFrom-FileToBase64String';
    Write-Verbose -Message ( " -Path = {0}" -f $Path );

    [String] $retValue = '';

    Write-Verbose -Message 'Test the path to see if it is valid';
    if ( Test-Path -Path $Path ) {
        Write-Verbose -Message 'Read in the file and convert it to a base 64 encoded string';
        $retValue = [Convert]::ToBase64String( ( Get-Content -Path $Path -Encoding Byte ) );
    } else {
        Write-Warning -Message ( "Cannot find file: {0}" -f $Path );
    }

    Write-Verbose -Message ( "`$retValue = {0}" -f $retValue );
    return $retValue;
}

<#
.SYNOPSIS
    This is a simple import function that pulls in a javascript object notation formatted string and returns an object.
.DESCRIPTION

.INPUTS
    None.
.OUTPUTS
    This cmdlet returns an object-based representation of the JSON data.
.EXAMPLE
    $stringWithJsonData = '{"FirstName":"John","LastName":"Doe"}'
    $jsonObject = ConvertFrom-JsonString -Value $stringWithJsonData;
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function ConvertFrom-JsonString {
    Param
    (
        [Parameter( Mandatory = $false, HelpMessage = 'Specify the data string value', Position = 0 )]
        [String] $Value = ''
    )

    [Void][Reflection.Assembly]::LoadWithPartialName( 'System.Web.Extensions' );
    $json = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer;

    if ( $Value -ne '' ) {
        try {
            $jsonData = $json.Deserialize( $Value, [Object] );
        } catch {
            Write-Warning 'Failed to deserialize the JSON data';
        } finally {
            if ( $null -ne $json ) {
                $json = $null;
            }
        }

        Write-Output -InputObject $jsonData;
    } else {
        Write-Output -InputObject $null;
    }
}

<#
.SYNOPSIS
    Used to convert invalid characters in a file path.
.DESCRIPTION

.PARAMETER Path
    This is a mandatory parameter which specifies the source file path.
.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS
    Returns a folder path with invalid characters removed.
.EXAMPLE
    $newPath = ConvertTo-ValidFileName -Path 'C:\Temp\source~with~bad~characters\somethingsilly.txt';
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function ConvertTo-ValidFileName {
    [CmdletBinding()]
    Param
    (
        [Parameter( Mandatory = $true, HelpMessage = 'Specify the name of the file to convert invalid characters from.' )]
        [String] $Path
    )

    $illegalCharacters =[Regex]::Escape( -join [IO.Path]::GetInvalidFileNameChars() );
    $regExPattern = "[$illegalCharacters]";

    $updatedPath = [Regex]::Replace( $Path, $regExPattern, '~' );

    if ( $updatedPath.Length -gt 255 ) { #bookmark Try to handle the files that exceed this length
        Write-Warning -Message ( "The following path is too long: {0}" -f $updatedPath );
        $updatedPath = $null;
    }

    return $updatedPath;
}

<#
.SYNOPSIS
    Used to convert invalid characters in a folder path.
.DESCRIPTION

.PARAMETER Path
    This is a mandatory parameter which specifies the source folder path.
.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS
    Returns a folder path with invalid characters removed.
.EXAMPLE
    $newPath = ConvertTo-ValidFolderPath -Path 'C:\Temp\source~with~bad~characters';
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function ConvertTo-ValidFolderPath {
    [CmdletBinding()]
    Param
    (
        [Parameter( Mandatory = $true, HelpMessage = 'Specify the folder path to convert invalid characters from.' )]
        [String] $Path
    )

    $illegalCharacters =[Regex]::Escape( -join [IO.Path]::GetInvalidPathChars() );
    $regExPattern = "[$illegalCharacters]";

    $updatedPath = [Regex]::Replace( $Path, $regExPattern, '' );

    if ( $updatedPath.Length -gt 255 ) { #bookmark Try to handle the folders that exceed this length
        Write-Warning -Message ( "The following path is too long: {0}" -f $updatedPath );
        
        $updatedPath = $null;
    }

    return $updatedPath;
}

<#
.SYNOPSIS
    Exports objects to files in JSON format.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to export PowerShell objects into
    JavaScript Object Notation (JSON) formatted files.
.PARAMETER InputObject
    This is a mandatory parameter which specifies the object that should be converted to JSON data.
.PARAMETER Path
    This is a mandatory parameter which defines the path to the JSON formatted export file.
.PARAMETER Compress
    This is an optional parameter which forces the JSON file to use the compressed JSON format which flattens spaces.
.PARAMETER Depth
    This is an optional parameter which defines the number of levels of child objects that will be exported.
.INPUTS
    None.
.OUTPUTS
    Export file that contains the JSON representation of the PowerShell object(s)
.EXAMPLE
    $services = Get-Service;
    Export-Json -InputObject $services -Path 'C:\temp\services.json';

    The preceding example exports the local machine services into a JSON formatted file.
.EXAMPLE
    $services = Get-Service;
    $services | Export-Json -Path 'C:\temp\services.json';

    The preceding example leverages the pipeline to export the local machine services into a JSON formatted file.
.EXAMPLE
    $services = Get-Service;
    $services | Export-Json -Path 'C:\temp\services.json' -Compress;

    The preceding example leverages the pipeline to export the local machine services into a compressed JSON formatted file.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Export-Json {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = "Specify a source object", ValueFromPipeline = $true )]
        [Object[]] $InputObject,

        [Parameter( Mandatory = $true, HelpMessage = "Specify the path to the new file" )]
        [String] $Path,

        [Parameter( Mandatory = $false, HelpMessage = "Use this switch to compress the file" )]
        [switch] $Compress,
        
        [Parameter( Mandatory = $false, HelpMessage = "How many levels of contained objects are included in the JSON representation" )]
        [Int32] $Depth = 2
    )

    Begin {
        [Boolean] $fromPipeline = $false;
        $objectCollection = @();

        if ( $InputObject.Count -eq 0 ) {
            $fromPipeline = $true;
        }

        $parentPath = Split-Path -Path $Path -Parent;
        $continueWithPipeline = $true;

        if ( Test-Path -Path $Path ) {
            [IO.File]::Delete( $Path );
        } else {
            if ( ( Test-Path -Path $parentPath ) -eq $false ) {
                Write-Warning  ( "Invalid path: {0}" -f $parentPath );
                $continueWithPipeline = $false;
            }
        }
    }
    Process {
        if ( $continueWithPipeline ) {
            if ( $fromPipeline ) {
                $objectCollection += $_;
            } else {
                foreach ( $inputItem in $InputObject ) {
                    $objectCollection += $inputItem;
                }
            }
        }
    }
    End {
        if ( $continueWithPipeline ) {
            if ( $objectCollection.Count -eq 1 ) {
                if ( $Compress ) {
                    ConvertTo-Json -InputObject $objectCollection[0] -Depth $Depth -Compress | Add-Content -Path $Path;
                } else {
                    try {
                        ConvertTo-Json -InputObject $objectCollection[0] -Depth $Depth | Add-Content -Path $Path;
                    } catch {
                        ConvertTo-Json -InputObject $objectCollection[0] -Depth $Depth -Compress | Add-Content -Path $Path;
                    }
                }
            } else {
                if ( $Compress ) {
                    ConvertTo-Json -InputObject $objectCollection -Depth $Depth -Compress | Add-Content -Path $Path;
                } else {
                    try {
                        ConvertTo-Json -InputObject $objectCollection -Depth $Depth | Add-Content -Path $Path;
                    } catch {
                        ConvertTo-Json -InputObject $objectCollection -Depth $Depth -Compress | Add-Content -Path $Path;
                    }
                }
            }
        }
    }
}

<#
.SYNOPSIS
    This cmdlet is intended to be used to download files from an FTP/sFTP location.
.DESCRIPTION

.PARAMETER Credential
    This is a mandatory parameter which specifies an FTP credential to use for logging onto the FTP/sFTP location.
.PARAMETER LocalFile
    This is a mandatory parameter which defines the full path, including file name, of the downloaded file location.
.PARAMETER RemoteFile
    This is an mandatory parameter which defines the full FTP/sFTP path, including file name, of the file to download.
.PARAMETER UseSsl
    This is an optional parameter which defines whether to use FTP (default) or sFTP.
.INPUTS
    None. This cmdlet is not intended to work with the PowerShell pipeline.
.OUTPUTS
    Downloaded file.
.EXAMPLE
    $creds = Get-Credential;
    $localFile = 'C:\Temp\iis-85.png';
    $remoteFile = 'ftp://ftp.company.com/iis-85.png';

    Get-FtpFile -Credential $creds -LocalFile $localFile -RemoteFile $remoteFile;
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Get-FtpFile {
    [CmdletBinding()]
    Param
    (
        [Parameter( Mandatory = $true, HelpMessage = 'Specify a credential to use to access the download site.' )]
        [Management.Automation.PSCredential] $Credential,

        [Parameter( Mandatory = $true, HelpMessage = 'Specify the path to the new file' )]
        [String] $LocalFile,

        [Parameter( Mandatory = $true, HelpMessage = 'Specify the remote FTP file path (example ftp://someserver.org/myfile.txt)' )]
        [String] $RemoteFile,

        [Parameter( Mandatory = $false, HelpMessage = 'Use SSL for FTP file transfer' )]
        [switch] $UseSsl = $false
    )

    [Net.NetworkCredential] $ftpCreds = New-Object Net.NetworkCredential( $Credential.UserName, $Credential.GetNetworkCredential().Password );

    $ftpRequest = [Net.FtpWebRequest]::Create( $RemoteFile );
    $ftpRequest.Credentials = $ftpCreds;
    $ftpRequest.Method = [Net.WebRequestMethods+Ftp]::DownloadFile;
    $ftpRequest.UseBinary = $true;
    $ftpRequest.KeepAlive = $false;
    $ftpRequest.EnableSsl = $UseSsl;

    $ftpResponse = $ftpRequest.GetResponse();	
    $responseStream = $ftpResponse.GetResponseStream();

    $downloadBuffer = New-Object IO.FileStream( $LocalFile, [IO.FileMode]::Create );
    [byte[]] $readBuffer = New-Object byte[] 1024;

    do {
        $readLength = $responseStream.Read( $readBuffer, 0, 1024 );
        $downloadBuffer.Write( $readBuffer, 0, $readLength );
    }
    while ( $readLength -ne 0 );

    $downloadBuffer.Close();
    $downloadBuffer.Dispose();
}

<#
.SYNOPSIS
    Imports data from an INI file.
.DESCRIPTION

.PARAMETER Path
    This is a mandatory parameter which specifies the source ini file path.
.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS
    None.
.EXAMPLE
    $ini = Get-IniFile -Path 'C:\Temp\sample-Settings.ini';

    This example reads in the sample-Settings.ini into the $ini variable.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Get-IniFile {
    [CmdletBinding()]
    Param (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the path for the ini settings file.' )]
        [String] $Path
    )

    Write-Verbose -Message 'Cmdlet: Get-IniFile';
    Write-Debug -Message ( "`$Path = {0}" -f $Path );

    [Hashtable] $iniData = @{};

    Write-Verbose -Message ( "Verify the file path: {0}" -f $Path );
    if ( Test-Path -Path $Path ) {
        Write-Verbose -Message 'Reading in the ini file data';
        $rawData = Get-Content -Path $Path | Where-Object { $_ -notmatch "^;.*$" -and $_.Trim().Length -gt 0 };

        Write-Verbose -Message 'Step through the ini file data one line at a time';
        foreach ( $line in $rawData ) {
            Write-Verbose -Message 'Reset variables to $null';

            Write-Verbose -Message 'Look for ini sections';
            if ( $line -match "^\[(.+)\]" ) {
                $section = $Matches[ 1 ];
            
                Write-Debug -Message ( "`$section = {0}" -f $section );
                if ( $iniData.ContainsKey( $section ) -eq $false ) {
                    $iniData[ $section ] = @{};
                }
            }

            Write-Verbose -Message 'Construct key value pairs and associate with the section';
            if ( $line -match "(.+?)\s*=(.*)" ) {
                Write-Verbose -Message 'Reset variables to $null';
                $keyName = $null;
                $keyValue = $null;

                $keyName, $keyValue = $Matches[ 1..2 ];
                $keyValue = $keyValue.TrimStart();
                $keyValue = $keyValue.TrimEnd();
                $keyValue = $keyValue.Replace( "`'", "" );
                $keyValue = $keyValue.Replace( "`"", "" );
                Write-Debug -Message ( "[{0}]: {1} = {2}" -f $section, $keyName, $keyValue );
                $iniData[ $section ][ $keyName ] = $keyValue;
            }
        }
    } else {
        Write-Warning -Message ( "File not found: {0}" -f $Path );
    }

    return $iniData;
}

function Get-LDAPAttributeValue {
    Param
    (
        [String] $AttributeName,

        [Object] $SearchResult
    )

    if ( $SearchResult.Properties.Contains( $AttributeName ) ) {
        $stringCollection = [Collections.ArrayList] @();

        foreach ( $stringValue in $SearchResult.Properties.Item( $AttributeName ) ) {
            [Void] $stringCollection.Add( $stringValue );
        }

        $stringCollection.Sort();

        return (,$stringCollection.ToArray());
    } else {
        return @();
    }

    #----------------------------------------------------------------------------------------------------------
    trap {
        Write-Warning -Message ( "ERROR: AttributeName={0}, Object={1}, Message={2}" -f $AttributeName, $SearchResult.Path, $_.Exception.Message );
        Continue;
    }
    #----------------------------------------------------------------------------------------------------------
}

<#
.SYNOPSIS
    Retrieves an object from an LDAP directory.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to access an LDAP directory
.PARAMETER Server
    This is a mandatory parameter which specifies the target LDAP server to search.
.PARAMETER BindDN
    This is a mandatory parameter which defines the bind account distinguished name.
.PARAMETER BindPassword
    This is a mandatory parameter which defines the bind account password.
.PARAMETER Identity
    This is an optional parameter which specifies the name of the object to search for.
.PARAMETER LDAPFilter
    This is an optional parameter which defines and LDAP fileter string to use for the search.
    If you are unfamiliar with LDAP search strings, you can learn by doing a saved query in the
    Active Directory Users and Computers console and looking at the search string. As an additional
    option, you can simply pipe the output through a Where-Object clause to filter the results.
.PARAMETER SearchBase
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER SearchScope
    This is an optional parameter which specifies the path in the structure to start a search
    from. This can be used to target a specific Organizational Unit where attributes alone are
    not sufficient.
.PARAMETER Port
    This is an optional parameter which specifies the LDAP server port to use. This defaults to 389.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a collection of objects returned from the query.
.EXAMPLE
    $dn = 'CN=John Doe,OU=People,OU=Accounts,DC=company,DC=com';
    $pwd = Read-Host 'Please supply the bind account password' -AsSecureString
    $testAccounts = Get-LDAPObject -Server LDAP1 -BindDN $dn -BindPassword $pwd -LDAPFilter '(&(objectClass=user)(sAMAccountName=test*))';

    The preceding example searches for all user objects in the domain that have a sAMAccountName starting with 'test'.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Get-LDAPObject {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the LDAP server to leverage' )]
        [String] $Server,

        [Parameter( Position = 1, Mandatory = $true, HelpMessage = 'Enter the bind account distinguished name value' )]
        [String] $BindDN,

        [Parameter( Position = 2, Mandatory = $true, HelpMessage = 'Enter the password for the bind account specified with -BindDN' )]
        [SecureString] $BindPassword,

        [Parameter( Position = 3, Mandatory = $false, HelpMessage = 'Enter the desired name to look for' )]
        [String] $Identity = '',

        [Parameter( Position = 4, Mandatory = $false, HelpMessage = 'Enter and LDAP filter to control the query output' )]
        [String] $LDAPFilter = '',

        [Parameter( Position = 5, Mandatory = $false, HelpMessage = 'Enter the LDAP path to start the search' )]
        [String] $SearchBase = '',

        [Parameter( Position = 6, Mandatory = $false, HelpMessage = 'Enter the LDAP scope for the search' )]
        [ValidateSet( 'Base', 'OneLevel', 'Subtree' )]
        [String] $SearchScope = 'Subtree',

        [Parameter( Position = 7, Mandatory = $false, HelpMessage = 'Enter the LDAP server port' )]
        [Int32] $Port = 389
    )

    Begin {
        Write-Verbose -Message 'Function: Get-LDAPObject';
        Write-Verbose -Message ( " -Server = {0}" -f $Server );
        Write-Verbose -Message ( " -BindDN = {0}" -f $BindDN );
        Write-Verbose -Message ( " -BindPassword = {0}" -f $BindPassword );
        Write-Verbose -Message ( " -LDAPFilter = {0}" -f $LDAPFilter );
        Write-Verbose -Message ( " -SearchBase = {0}" -f $SearchBase );
        Write-Verbose -Message ( " -SearchScope = {0}" -f $SearchScope );
        Write-Verbose -Message ( " -Port = {0}" -f $Port );

        [String] $bindString = '';
    }
    Process { }
    End {
        try {
            if ( $SearchBase -eq '' ) {
                $bindString = "LDAP://{0}:{1}" -f $Server, $Port;
            } else {
                $bindString = "LDAP://{0}:{1}/{2}" -f $Server, $Port, $SearchBase;
            }
            Write-Verbose -Message ( "`$bindString = {0}" -f $bindString );

            $bSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR( $BindPassword );
            $ldapBindPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto( $bSTR );
            Write-Verbose -Message ( "`$ldapBindPassword = {0}" -f $ldapBindPassword );

            $ldapRoot = New-Object System.DirectoryServices.DirectoryEntry( $bindString, $BindDN, $ldapBindPassword, [DirectoryServices.AuthenticationTypes]::None );

            if ( $null -ne $ldapRoot.distinguishedName ) {
                $ldapSearcher = New-Object System.DirectoryServices.DirectorySearcher;
                $ldapSearcher.SearchRoot = $ldapRoot;
                $ldapSearcher.SearchScope = $SearchScope;

                if ( $LDAPFilter -eq '' ) {
                    if ( $Identity -eq '' ) {
                        $ldapSearcher.Filter = "(objectClass=*)";
                        Write-Verbose -Message ( "`$ldapSearcher.Filter = {0}" -f $ldapSearcher.Filter );
                        $searchResults = $ldapSearcher.FindAll();
                    } else {
                        if ( [regex]::Match( $Identity, '(?=CN|DC|OU)(.*\n?)(?<=.)' ).Success ) {
                            $ldapSearcher.Filter = "(distinguishedName={0})" -f $Identity;
                        } else {
                            Write-Warning -Message 'Invalid LDAP filter';
                            break;
                        }

                        Write-Verbose -Message ( "`$ldapSearcher.Filter = {0}" -f $ldapSearcher.Filter );
                        $searchResults = $ldapSearcher.FindOne();
                    }
                } else {
                    $ldapSearcher.Filter = $LDAPFilter;
                    Write-Verbose -Message ( "`$ldapSearcher.Filter = {0}" -f $ldapSearcher.Filter );
                    $searchResults = $ldapSearcher.FindAll();
                }

                $output = [Collections.ArrayList] @();

                if ( $searchResults.Count -gt 0 ) {
                    Write-Verbose -Message ( "`$searchResults.Count = {0}" -f $searchResults.Count );
                    foreach ( $searchResult in $searchResults ) {
                        [Object] $template = [pscustomobject][ordered] @{};

                        foreach ( $ldapAttribute in $searchResult.Properties.PropertyNames ) {
                            $attributeValue = $null;
                            $attributeValue = Get-LDAPAttributeValue -AttributeName $ldapAttribute -SearchResult $searchResult;
                            $template | Add-Member -MemberType NoteProperty -Name $ldapAttribute -Value $attributeValue;
                        }

                        Write-Verbose -Message 'Add the current object to the results collection'
                        [Void] $output.Add( $template );
                    }
                }
            }
            else {
                Write-Warning -Message ( "Unable to connect to server using the following bind string ({0})" -f $bindString );
            }
        }
        catch {  } # Throw away the error because it is false anyway

        return $output;
    }
}

<#
.SYNOPSIS
    This cmdlet is intended to provide a consistent and friendly way to import JSON formatted files
    into PowerShell objects and/or variables.
.DESCRIPTION

.PARAMETER Path
    This is a mandatory parameter which defines the path to the JSON formatted input file.
.INPUTS
    None.
.OUTPUTS
    Input file that contains the JSON representation of data into PowerShell object(s).
.EXAMPLE
    $json = Import-Json -Path 'C:\temp\services.json';

    The preceding example imports the specified file into the $json variable.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Import-Json {
    Param
    (
        [Parameter( Mandatory = $true, HelpMessage = "Specify the path to the source file" )]
        [String] $Path
    )

    if ( Test-Path -Path $Path ) {
        $sourceFile = Get-ChildItem -Path $Path;
        [Void][Reflection.Assembly]::LoadWithPartialName( 'System.Web.Extensions' );
        $json = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer;
        $json.MaxJsonLength = $sourceFile.Length;

        $fileData = [IO.File]::ReadAllText( $sourceFile.FullName );

        try {
            $jsonData = $json.Deserialize( $fileData, [Object] );
        } catch {
            Write-Warning 'Failed to deserialize the JSON data';
        } finally {
            if ( $null -ne $json ) {
                $json = $null;
            }
        }

        Write-Output -InputObject $jsonData;
    } else {
        Write-Output -InputObject $null;
    }
}

<#
.SYNOPSIS
    This cmdlet is intended to be used to move a file from a source to destination, while making a copy of the original file.
.DESCRIPTION

.PARAMETER Path
    This is a mandatory parameter which specifies the full path to the source file.
.PARAMETER Destination
    This is a mandatory parameter which defines the full path to the new location.
.PARAMETER ArchivePath
    This is an mandatory parameter which defines the folder path where the original file should be archived to.
.PARAMETER Keep
    This is an mandatory parameter which defines how many files to keep in the archived folder.
.INPUTS
    None. This cmdlet is not intended to work with the PowerShell pipeline.
.OUTPUTS
    Moved and archived file.
.EXAMPLE

.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Move-FileAndArchive
{
    [CmdletBinding()]
    Param
    (
        [Parameter( Mandatory = $true, HelpMessage = 'Specify the path to the file to be moved' )]
        [String] $SourceFilePath,

        [Parameter( Mandatory = $true, HelpMessage = 'Specify the destination path' )]
        [String] $TargetFolder,

        [Parameter( Mandatory = $true, HelpMessage = 'Specify the archive path' )]
        [String] $ArchiveFolder,

        [Parameter( Mandatory = $false, HelpMessage = 'Define the number to keep' )]
        [Int32] $FilesToKeep = 1
    )

    # Initialize the return variable
    [String] $returnValue = '';

    # Determine if the source file exists
    if ( Test-Path -Path $SourceFilePath ) {
        # Determine if the target folder exists
        if ( Test-Path -Path $TargetFolder ) {
            # Construct the target file path
            [String] $targetFilePath = Join-Path -Path $TargetFolder -ChildPath ( Split-Path -Path $SourceFilePath -Leaf );

            # Determine if the archive folder exists
            if ( Test-Path -Path $ArchiveFolder ) {
                # Parse the file name and extension from the path
                $fileNameAndExtension = Split-Path -Path $SourceFilePath -Leaf;

                # Construct archive file name
                $archiveFileName = "{0}__{1}.{2}" -f ( $fileNameAndExtension.Split( '.' )[ 0 ] ), ( Get-Date -f "yyyy-MM-dd__HHmmss" ), ( $fileNameAndExtension.Split( '.' )[ 1 ] );

                # Construct the new archive file path
                [String] $archiveFilePath = Join-Path -Path $ArchiveFolder -ChildPath $archiveFileName;

                # Determine the number of files in the archive folder
                $archiveFileCount = ( Get-ChildItem -Path $ArchiveFolder -File ).Count;

                # Determine if old entries should be purged
                if ( $archiveFileCount -gt $FilesToKeep ) {
                    # Calculate the number that needs to be removed
                    [Int32] $numberOfExcessiveFiles = $archiveFileCount - $FilesToKeep;

                    # Determine if there are more than 1 and if so remove them
                    if ( $numberOfExcessiveFiles -gt 0 ) {
                        # Iterate through the files and remove the oldest one
                        for ( $i = 0; $i -lt $numberOfExcessiveFiles; $i++ ) {
                            # Determine the oldest file name and path
                            [String] $oldestFileName = ( Get-ChildItem -Path $ArchiveFolder -File | Sort-Object LastWriteTime )[ 0 ].FullName;

                            # Remove the file
                            try {
                                Remove-Item -Path $oldestFileName -Force;
                            } catch {
                                $returnValue = ( "Failed to delete the file ({0})" -f $oldestFileName );
                                Write-Warning -Message $returnValue;
                            }
                        }
                    }
                }

                # Copy the file to the archive folder
                try {
                    Copy-Item -Path $targetFilePath -Destination $archiveFilePath -Force;
                } catch {
                    $returnValue = ( "Failed to archive the file ({0})" -f $SourceFilePath );
                    Write-Warning -Message $returnValue;
                    return $returnValue;
                }

                # Copy the source file to the target folder
                try {
                    Copy-Item -Path $SourceFilePath -Destination $targetFilePath -Force;

                    $returnValue = 'Success';
                } catch {
                    $returnValue = ( "Failed to move the file ({0})" -f $SourceFilePath );
                    Write-Warning -Message $returnValue;
                }
            } else {
                $returnValue = ( "The archive folder ({0}) does not exist" -f $ArchiveFolder );
                Write-Warning -Message $returnValue;
            }
        } else {
            $returnValue = ( "The target folder ({0}) does not exist" -f $TargetFolder );
            Write-Warning -Message $returnValue;
        }
    } else {
        $returnValue = ( "The source file ({0}) does not exist" -f $SourceFilePath );
        Write-Warning -Message $returnValue;
    }

    # Return the result
    return $returnValue;
}

<#
.SYNOPSIS
    Creates and Event Log and/or registers the specified Event Source.
.DESCRIPTION

.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS

.PARAMETER EventLogName
    This parameter is used to define the intended Event Log name.
.PARAMETER EventLogSource
    This parameter is used to define the intended Event Log source name.
.EXAMPLE
    New-EventLogOrSource -EventLogName 'MIM Custom' -EventLogSource 'MyScriptName'
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function New-EventLogOrSource {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Enter the Event Log name.' )]
        [ValidateNotNullOrEmpty()]
        [String] $EventLogName = $Global:eventLogName,

        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Enter the Event Log source.' )]
        [ValidateNotNullOrEmpty()]
        [String] $EventLogSource = $Global:eventSource
    )

    Write-Verbose -Message 'Function: New-EventLogOrSource';
    Write-Verbose -Message ( " -EventLogName = {0}" -f $EventLogName );
    Write-Verbose -Message ( " -EventLogSource = {0}" -f $EventLogSource );

    # Initialize the return value
    [Boolean] $returnValue = $false;

    try {
        # Check to see if the log and source are already created by trying to retrieve one entry from it
        [Object] $eventLog = Get-EventLog -LogName $EventLogName -Source $EventLogSource -Newest 1 -ErrorAction SilentlyContinue;

        # If the number of returned entries is null, then create the log and source
        if ( $null -ne $eventLog ) {
            # Create the Event Log and Event Log Source
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Warning -EventId 200 -Message 'The specified event log and source already exists on this computer.';

            # Update the return value to indicate that it is available
            $returnValue = $true;
        } else {
            # Check to make sure that the account has administrative rights to create a new system Event Log
            if ( Test-IsLocalAdmin ) {
                try {
                    # Create the new Event Log
                    New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction SilentlyContinue | Out-Null;
                
                    # Write to the new log
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 100 -Message 'Successfully created a new Event Log and/or event source.';

                    # Update the return value to indicate that it is available
                    $returnValue = $true;
                } catch [System.Security.SecurityException] {
                    # Trap a security issue which would typically be caused by a non-admin
                    Write-Warning -Message $_.Exception.Message;
                }
            } else {
                Write-Warning -Message 'Access denied when attempting to create the Event Log and/or Event Source. Please run this script initially as an administrator to create the log';
            }
        }
    } catch [System.InvalidOperationException] {
        # Check for a message that the log does not exist so that it can be
        if ( $_.Exception.Message -eq "The event log '$EventLogName' on computer '.' does not exist." ) {
            try {
                # Create the new Event Log
                New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction SilentlyContinue | Out-Null;
                
                # Write to the new log
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 100 -Message "Successfully created a new Event Log and/or event source.";

                # Update the return value to indicate that it is available
                $returnValue = $true;
            } catch [System.Security.SecurityException] {
                # Trap a security issue which would typically be caused by a non-admin
                Write-Warning -Message $_.Exception.Message;
            }
        }
    }

    # Return the result of the check
    return $returnValue;
}

<#
.SYNOPSIS
    Generates a new GUID.
.DESCRIPTION

.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS

.EXAMPLE
    $newGUID = New-GUID;
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function New-GUID {
    [CmdletBinding()]
    Param()

    Write-Verbose -Message 'Cmdlet: New-GUID';

    $newGUID = [guid]::NewGuid();
    return $newGUID.ToString();
}

<#
.SYNOPSIS
    Generates a random password.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to generate a random
    password based on the passed parameters. Similar looking characters were intentionally removed.
.PARAMETER Length
    This is an optional parameter which defines the length of the new password.
.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS
    The generated new password.
.EXAMPLE
    $newPwd = New-Password -Length 21;

    The preceding example generates a 21 character complex password.
.EXAMPLE
    $newPwd = New-Password;

    The preceding example generates an 8 character complex password.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function New-Password {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Enter the desired length of the new password' )]
        [Int32] $Length = 8
    )

    Write-Verbose -Message 'Function: New-Password';
    Write-Verbose -Message ( " -Length = {0}" -f $Length );

    # Declare and initialize variables
    [Object] $characterBytes = $null;
    [String] $passwordCharacters = $null;
    [Object] $randomizer = $null;

    # Create a byte array long enough to contain the new string
    $characterBytes = New-Object "Byte[]" $Length;

    # Create a randomizer
    $randomizer = New-Object Security.Cryptography.RNGCryptoServiceProvider;
    $randomizer.GetBytes( $characterBytes );

    # Select random characters from the array of characters in the $passwordCharacters
    $passwordCharacters = '!@#$%&*.,+-_23456789ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    Write-Verbose -Message ( "`$passwordCharacters = {0}" -f $passwordCharacters );

    Write-Verbose -Message 'Step through the number of characters required one at a time';
    for( $i=0; $i -lt $Length; $i++ ) {
        # Append the newly selected character to the new value
        $result += $passwordCharacters[ $characterBytes[ $i ] % $passwordCharacters.Length ];
        Write-Verbose -Message ( "`$result = {0}" -f $result );
    }

    return $result;
}

<#
.SYNOPSIS
    Creates a zip file from a directory.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to create a zip file
    with all the files from a specified directory.
.PARAMETER Path
    This is a mandatory parameter which specifies the name of the zip file to be created.
.PARAMETER SourceFolder
    This is a mandatory parameter which defines the source folder that contains the files to be compressed.
.INPUTS
    None.
.OUTPUTS
    Zip file.
.EXAMPLE
    New-ZipFileFromDirectory -Path 'C:\Temp\my.zip' -SourceFolder 'C:\Temp\MyData'

    The preceding example creates a zip file named 'my.zip' from the contents of the 'C:\Temp\MyData' directory.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function New-ZipFileFromDirectory {
    [CmdletBinding()]
    Param (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Enter the desired zip file name' )]
        [String] $Path,

        [Parameter( Position = 1, Mandatory = $true, HelpMessage = 'Enter the source directory that contains the files to compress' )]
        [String] $SourceFolder
    )

    Write-Verbose -Message 'Function: New-ZipFileFromDirectory';
    Write-Verbose -Message ( " -Path = {0}" -f $Path );
    Write-Verbose -Message ( " -SourceFolder = {0}" -f $SourceFolder );

    Write-Verbose -Message 'Loading assembly: System.IO.Compression.FileSystem';
    Add-Type -AssemblyName System.IO.Compression.FileSystem;

    Write-Verbose -Message ( "Determine if the following file exists: {0}" -f $Path );
    if ( Test-Path -Path $Path ) {
        Write-Verbose -Message 'Remove the existing file';
        Remove-Item -Path $Path;
    }

    Write-Verbose -Message 'Call [IO.Compression.ZipFile]::CreateFromDirectory function';
    [IO.Compression.ZipFile]::CreateFromDirectory( $SourceFolder, $Path, [IO.Compression.CompressionLevel]::Optimal, $false );
}

<#
.SYNOPSIS
    Used to retrieve the file name for the file.
.DESCRIPTION

.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS
    Returns a fully qualified file path to the target file.
.EXAMPLE
    $currentFile = Request-FileName -Title 'Please select the appropriate file' -Filter 'CSV Files (*.csv)|*.csv';

    This example provides a selection dialog for CSV files and returns the result into the $currentFile variable.
.EXAMPLE
    $newFileName = Request-FileName -Title 'Please select the appropriate file' -Filter 'CSV Files (*.csv)|*.csv' -SaveAs;

    This example provides a selection dialog for a new CSV file and returns the name into the $newFileName variable.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Request-FileName {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $false, HelpMessage = 'Specify the text that will appear in the title of the dialog' )]
        [String] $Title = '',
        
        [Parameter( Mandatory = $false,
            HelpMessage = "Specify the string to use as available file filters.  The filter string 
            contains a description of the filter, followed by the vertical bar (|), and the 
            filter pattern. You are allowed to have multiple filters as long as you separate 
            each filter by a vertical bar (|).  Example filter for both CSV files and all files:
            'CSV Files (*.csv)| *.csv|All files (*.*)| *.*'"
        )]
        [String] $Filter = '',
        
        [Parameter( Mandatory = $false, HelpMessage = 'Optional switch which changes the dialog to a Save file dialog' )]
        [switch] $SaveAs
    )

    [String] $fileName = '';

    if ( [Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA' ) {
        [Object] $fileDialog = $null;
        [Void] [Reflection.Assembly]::LoadWithPartialName( 'System.Windows.Forms' );
        
        if ( $SaveAs ) {
            $fileDialog = New-Object -TypeName Windows.Forms.SaveFileDialog;
        } else {
            $fileDialog = New-Object -TypeName Windows.Forms.OpenFileDialog;
        }
        
        $fileDialog.Title = $Title;
        $fileDialog.InitialDirectory = '';
        $fileDialog.Filter = $Filter;
        [Void] $fileDialog.ShowDialog();
        $fileName = $fileDialog.FileName;
    } else {
        $fileName = Read-Host -Prompt $Title;
    }

    return $fileName;
}

<#
.SYNOPSIS
    This is used to request an existing folder path.
.DESCRIPTION

.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS
    The path of the selected folder.
.EXAMPLE
    $newFolder = Request-FolderPath;

    This allows the user to select or create and select a new folder.
.EXAMPLE
    $existingFolder = Request-FolderPath -HideNewFolderButton;

    This allows you to select an existing folder, but not to create a new one.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Request-FolderPath {
    [CmdletBinding()]
    Param
    (
        [Parameter( Mandatory = $false, HelpMessage = 'Specify the the descriptive text displayed above the tree view control in the dialog box' )]
        [String] $Description = '',
        
        [Parameter( Mandatory = $false, HelpMessage = 'Use this switch to hide the Make New Folder button from the dialog' )]
        [switch] $HideNewFolderButton
    )

    [String] $folderPath = '';
    [Object] $comObject = New-Object -ComObject Shell.Application;

    if ( $HideNewFolderButton ) {
        $folderPath = ( $comObject.BrowseForFolder( 0, $Description, 512 ) ).Self.Path;
    } else {
        $folderPath = ( $comObject.BrowseForFolder( 0, $Description, 0 ) ).Self.Path;
    }

    [Void] [Runtime.InteropServices.Marshal]::ReleaseComObject( $comObject );

    return $folderPath;
}

<#
.SYNOPSIS
    Returns a consistent response based on the option clicked on in the dialog.
.DESCRIPTION

.INPUTS
    None. You cannot pipe objects to this script.
.PARAMETER Message
    This is a mandatory parameter which specifies what should be asked for.
.PARAMETER Title
    This is a optional parameter which specifies the title.
.PARAMETER YesDescription
    This is a optional parameter which specifies the tool tip message for the 'Yes' button.
.PARAMETER NoDescription
    This is a optional parameter which specifies the tool tip message for the 'No' button.
.PARAMETER CancelDescription
    This is a optional parameter which specifies the tool tip message for the 'Cancel' button.
.PARAMETER Default
    This is a optional parameter which specifies the default choice for simply hitting Enter.
.OUTPUTS
    Returns a string that is either 'Yes', 'No', or 'Cancel'
.EXAMPLE
    $continue = Request-YesNoCancel -Message 'Do you want to continue?' -Title 'Confirm Action';
    if ( $continue -eq 'Yes' )
    {
        # Run code
    }
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Request-YesNoCancel {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $true )]
        [String] $Message,
        
        [Parameter( Mandatory = $false )]
        [String] $Title = "Please respond with a 'Yes' or 'No'",
        
        [Parameter( Mandatory = $false )]
        [String] $YesDescription = 'Select this option if you agree with the request',
        
        [Parameter( Mandatory = $false )]
        [String] $NoDescription = 'Select this option if you disagree with the request',
        
        [Parameter( Mandatory = $false )]
        [String] $CancelDescription = 'Select this option to abort the request',

        [Parameter( Mandatory = $false, HelpMessage = 'Define the default response' )]
        [ValidateSet( 'Yes', 'No','Cancel' )]
        [String] $Default = 'Yes'
    )

    [Object] $cancel = New-Object Management.Automation.Host.ChoiceDescription '&Cancel', $CancelDescription;
    [Object] $no = New-Object Management.Automation.Host.ChoiceDescription '&No', $NoDescription;
    [Int32] $result = 0;
    [Object] $yes = New-Object Management.Automation.Host.ChoiceDescription '&Yes', $YesDescription;

    $options = [Management.Automation.Host.ChoiceDescription[]] ( $yes, $no, $cancel );

    try {
        switch ( $Default ) {
            'Yes' {
                $result = $Host.UI.PromptForChoice( $Title, $Message, $options, 0 );
            }
            'No' {
                $result = $Host.UI.PromptForChoice( $Title, $Message, $options, 1 );
            }
            'Cancel' {
                $result = $Host.UI.PromptForChoice( $Title, $Message, $options, 2 );
            }
        }

        switch ( $result ) {
            0 {
                return 'Yes';
            }
            1 {
                return 'No';
            }
            2 {
                return 'Cancel';
            }
        }
    } catch [Management.Automation.Host.PromptingException] {
        return 'Cancel';
    } catch {
        return 'Cancel';
    }
}

<#
.SYNOPSIS
    Starts separate processes to efficiently complete tasks simultaneously
.DESCRIPTION
    
.PARAMETER ProcessToExecute
    This is a mandatory parameter which includes the script block to execute.
.PARAMETER TaskList
    This is a mandatory parameter.
.PARAMETER OutputCollection
    This is a mandatory parameter.
.PARAMETER MaxThreads
    This is a mandatory parameter that defines the maximum number of threads.
.PARAMETER ShowProgress
    This is an optional parameter which allows you to display the progress.
.INPUTS
    None.
.OUTPUTS

.EXAMPLE
    $adForeignSecurityPrincipals = Get-ADDSForeignSecurityPrincipal;

    The preceding example searches for all group objects in the current domain using the current credentials.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Start-ParallelTasks {
    Param
    (
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Supply the script block to execute.' )]
        [scriptblock] $ProcessToExecute,
        
        [Parameter( Position = 1, Mandatory = $true, HelpMessage = 'Supply the task list.' )]
        $TaskList,
        
        [Parameter( Position = 2, Mandatory = $true, HelpMessage = 'Supply the output collection.' )]
        $OutputCollection,
        
        [Parameter( Position = 3, Mandatory = $true, HelpMessage = 'Define the maximum number of threads.' )]
        [Int32] $MaxThreads,
        
        [Parameter( Position = 4, Mandatory = $false, HelpMessage = 'Determine if you want to show progress' )]
        [switch] $ShowProgress
    )

    $sessionState = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault();

    Write-Host "`nStarting processing of $($TaskList.Count) tasks across $MaxThreads threads";

    # Create Runspace Pool
    Write-Host "   Creating Runspace Pool..."
    $runspacePool = [RunspaceFactory]::CreateRunspacePool( 1, $MaxThreads, $sessionState, $Host );
    $runspacePool.Open();
    $runspacePool.SessionStateProxy.SetVariable;

    # Create job tracking list
    $pendingJobs = [Collections.ArrayList] @();

    # Create all of the jobs and dump them into the pool
    Write-Host "   Generating jobs and dumping them in the pool for execution..."
    foreach ( $task in $TaskList ) {
        # Specify code to execute for each job
        $job = [powershell]::Create().AddScript( $ProcessToExecute );

        # Specify arguments (the first must always be the output object, then the item from the task list) 
        [Void] $job.AddArgument( $OutputCollection ); # $OutputCollection MUST be global and synchronized
        [Void] $job.AddArgument( $task );

        # Specify runspace pool (which may start the job depending on the currently running threads)
        $job.RunspacePool = $runspacePool;

        # Add job to the job tracking list
        $jobTrackingItem = New-Object PSObject -Property @{
            Pipe = $job
            Result = $job.BeginInvoke()
        }
        [Void] $pendingJobs.Add( $jobTrackingItem );
    }

    # Monitor progress and clean up as jobs finish
    $pendingJobCount = $pendingJobs.count;
    $originalJobCount = $pendingJobCount;

    while ( $pendingJobCount -gt 0 ) {
        $currentlyCompletedJobs = ( $pendingJobs | Where-Object { $_.Result.IsCompleted -eq $true; } )

        foreach ( $completedJob in $currentlyCompletedJobs ) { # Process incremental results

            [Void] $completedJob.Pipe.EndInvoke( $completedJob.Result );
            $completedJob.Pipe.Dispose();

            # Remove completed jobs from the pending job list
            $pendingJobs.Remove( $completedJob );

            $pendingJobCount = $pendingJobs.Count;

            if ( $ShowProgress ) {
                Write-Progress -Id 1 -Activity "Executing parallel tasks" -Status "$($originalJobCount - $pendingJobCount) complete out of $originalJobCount ($($MaxThreads - $runspacePool.GetAvailableRunspaces()) threads running)" -PercentComplete ( ( ( $originalJobCount - $pendingJobCount ) / $originalJobCount )  * 100 );
            }
        }

        Start-Sleep -Seconds 1;
    } 

    if ( $ShowProgress ) {
        Write-Progress -Id 1 -Activity "Executing time consuming things" -Status "Ready" -Completed;
    }

    # Close the Runspace Pool
    Write-Host "`nAll jobs completed! Closing Runspace Pool..." -ForegroundColor Green;
    $RunspacePool.Close();
    $RunspacePool.Dispose();
}

<#
.SYNOPSIS
    This is a simple expression check to verify that a string is a properly formatted GUID.
.DESCRIPTION

.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating appropriate GUID format.
.EXAMPLE
    if ( Test-IsAGUID ) { Write-Warning -Message 'Do GUID stuff' } else { Write-Warning -Message 'No GUID stuff' }
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Test-IsAGUID {
    [CmdletBinding()]
    Param
    (
        [Parameter( Mandatory = $false, HelpMessage = "Specify the value to be tested" )]
        [String] $Value
    )

    Write-Verbose -Message 'Function: _IsAGUID';

    Write-Verbose -Message 'Check to see if the value is null or empty';
    if ( [String]::IsNullOrEmpty( $Value ) ) {
        return $false;
    } else {
        Write-Verbose -Message 'Apply a regular expression to the value to determine if the value is a GUID'
        if ( $Value -match "^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$" ) {
            return $true;
        } else {
            return $false;
        }
    }
}

<#
.SYNOPSIS
    Determines if a target system has the indicated hotfix KB article.
.DESCRIPTION
    This cmdlet is intended to be used to determine if a target system has the indicated hotfix KB article.
.PARAMETER ComputerName
    This is an optional parameter which defines the computer name to pull information from.
.PARAMETER Credential
    This is an optional parameter which specifies the credential to use to collect the information. This credential needs
    to be an administrator on the target system to report correctly.
.PARAMETER HotFixID
    This is a mandatory parameter which defines the KB article value to search the target machine for.
.INPUTS
    None. This cmdlet is not intended to work with the PowerShell pipeline.
.OUTPUTS
    None.
.EXAMPLE
    $result = Test-IsHotFixInstalled -HotFixID KB4515871;

    The preceding example checks for KB4515871 on the local computer.
.EXAMPLE
    $creds = Get-Credential;
    $targetComputer = 'Server1';
    $remoteFile = 'ftp://ftp.company.com/iis-85.png';

    Test-IsHotFixInstalled -HotFixID KB4515871 -ComputerName $targetComputer -Credential $creds;

    The preceding example checks for KB4515871 on Server1 using the passed credentials stored in $creds.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Test-IsHotFixInstalled {
    [CmdletBinding()]
    Param
    (
        [CmdletBinding()]
        [Parameter( Position = 0, Mandatory = $true, HelpMessage = 'Specify the hotfix id (i.e. KB4515871' )]
        [String] $HotFixID,

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter the computer name that you what to collect information from' )]
        [String] $ComputerName = ".",

        [Parameter( Position = 2, Mandatory = $false, HelpMessage = 'Specify a credential to use to access the target machine.' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Begin {
        Write-Verbose -Message 'Function: Test-IsHotFixInstalled';
        Write-Verbose -Message ( " -HotFixID = {0}" -f $HotFixID );
        Write-Verbose -Message ( " -ComputerName = {0}" -f $ComputerName );

        [Boolean] $output = $false;
        [String] $outputMessage = '';
    }
    Process { }
    End {
        Write-Verbose -Message 'Update local computer value based on passed information';
        if ( $ComputerName -eq '.' ) {
            $localComputer = $env:COMPUTERNAME;
        } else {
            $localComputer = $ComputerName.ToUpper();
        }
        Write-Verbose -Message ( "`$localComputer = {0}" -f $localComputer );

        Write-Verbose -Message 'Trying to ping the machine';
        if ( Test-Connection -BufferSize 32 -Count 1 -Quiet -ComputerName $localComputer ) {
            $cimOptions = New-CimSessionOption -Protocol Dcom;

            if ( $Credential ) {
                Write-Verbose -Message ( "Establishing a CIM session with the following account: {0}" -f $Credential.UserName );
                $cimSession = New-CimSession -ComputerName $localComputer -Credential $Credential -SessionOption $cimOptions -ErrorAction SilentlyContinue;
            } else {
                Write-Verbose -Message ( "Establishing a CIM session with the current account: {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME );
                $cimSession = New-CimSession -ComputerName $localComputer -SessionOption $cimOptions -ErrorAction SilentlyContinue;
            }

            if ( $null -eq $cimSession ) {
                $outputMessage = "Unable to connect to $localComputer via WMI";
            } else {
                $wmiClass = 'Win32_QuickFixEngineering';
                Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                Write-Verbose -Message "Collect WMI information from $wmiClass";
                $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass -Filter "HotFixID='$($HotFixID)'";

                if ( $null -ne $cimData ) {
                    $output = $true;
                }
            }

            if ( $null -ne $cimSession ) {
                $cimSession.Close();
                $cimSession = $null;
            }
        } else {
            $outputMessage = "Unable to ping $localComputer";
        }

        if ( $outputMessage -eq '' ) {
            return $output;
        } else {
            Write-Warning -Message $outputMessage;
            return $output;
        }
    }
}

<#
.SYNOPSIS
    Checks to see if the current user is a local administrator on the current machine.
.DESCRIPTION

.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating local administrator status.
.EXAMPLE
    if ( Test-IsLocalAdmin ) { Write-Warning -Message 'Do admin stuff' } else { Write-Warning -Message 'No admin stuff' }
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Test-IsLocalAdmin {
    if ( ( [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent() ).IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ) ) {
        return $true;
    } else {
        return $false;
    }
}

<#
.SYNOPSIS
    Checks to see if the local machine has the User Account Control enabled.
.DESCRIPTION
    This cmdlet is intended to provide a consistent and friendly way to check the local machine
    to see if the User Account Control is enabled.
.INPUTS
    None.
.OUTPUTS
    This cmdlet returns a boolean value indicating whether UAC is enabled or not.
.EXAMPLE
    if ( Test-IsUACEnabled ) { Write-Warning -Message 'This script does not work with UAC enabled!' }

    The preceding example checks for the UAC and fails with a warning message if it is enabled.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function Test-IsUACEnabled {
    [String] $registryKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System';
    [Object] $registryObject = $null;
    [Boolean] $retValue = $false;

    if ( Test-Path -Path $registryKey ) {
        $registryObject = Get-ItemProperty -Path $registryKey;

        if ( $registryObject.EnableLUA -eq 1 ) {
            $retValue = $true;
        } else {
            if ( $null -eq $registryObject.EnableLUA ) {
                $registryKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\LocalPoliciesSecurityOptions\UserAccountControl_RunAllAdministratorsInAdminApprovalMode';
        
                if ( Test-Path -Path $registryKey ) {
                    $registryObject = Get-ItemProperty -Path $registryKey;
            
                    if ( $registryObject.value -eq 1 ) {
                        $retValue = $true;
                    }
                }
            }
        }
    }

    return $retValue;
}

#endregion

# Export all the defined cmdlets for use
Export-ModuleMember -Function '*';

#region Extension Modules

# Dot Source extension Cmdlets by iterating each of the PS1 files in the Modules directory
Get-ChildItem -Path $PSScriptRoot -Filter *.ps1 | ForEach-Object {
    $commandPath = "{0}\{1}" -f $PSScriptRoot, $_.Name;

    # Load the current PS1 file
    . $commandPath;
}

#endregion