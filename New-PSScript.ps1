<#
.SYNOPSIS
    Create a new PowerShell script with some base structure.
.DESCRIPTION

.PARAMETER Path
    This is an optional parameter which specifies the target file path. If this is not specified, the script will be copied to
    the clipboard.
.PARAMETER IniSupport
    This is an optional parameter which specifies that the new script should support values from an ini file.
.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS
    None.
.EXAMPLE
    New-PSScript -Path 'C:\Temp\sample.ps1';

    A new skeleton script is created called 'sample.ps1' in the 'C:\Temp' directory.
.EXAMPLE
    New-PSScript -Path 'C:\Temp\sample.ps1' -IniSupport;

    A new skeleton script is created called 'sample.ps1' in the 'C:\Temp' directory that supports values from an ini file.
.EXAMPLE
    New-PSScript -IniSupport;

    A new skeleton script is created that supports a setting file is copied to the clipboard.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>
function New-PSScript {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Specify the path to the source file' )]
        [String] $Path = '',

        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Include this switch to create a script that supports parameters in an ini file' )]
        [switch] $IniSupport
    )

    Write-Verbose -Message 'Cmdlet: New-PSScript';
    Write-Verbose -Message ( " -Path = {0}" -f $Path );
    Write-Verbose -Message ( " -IniSupport = {0}" -f $IniSupport );

    [String] $requiredVersion = '5.1';
    Write-Verbose -Message ( "`$requiredVersion = {0}" -f $requiredVersion );
    [String] $scriptVersion = "1.0.{0}" -f ( Get-Date -Format "yyyy.MMdd" );
    Write-Verbose -Message ( "`$scriptVersion = {0}" -f $scriptVersion );

#region Here Strings

$advancedScript = @"
#Requires -Version $requiredVersion

<#
.SYNOPSIS

.DESCRIPTION

.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS

.EXAMPLE

.NOTES
    Author:
    Version: $scriptVersion
.LINK

#>

[CmdletBinding()]
Param
(
    [Parameter( Position = 0, Mandatory = `$false, HelpMessage = 'Enter the path for the ini settings file.' )]
    [String] `$IniFileName
)

#region Script Functions

Write-Verbose -Message 'Entering script function region in script';

function _GetIniFile {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = `$true, HelpMessage = 'Enter the path for the ini settings file.' )]
        [String] `$FileName
    )

    Write-Verbose -Message 'Function: _GetIniFile';
    Write-Verbose -Message ( " -FileName = {0}" -f $FileName );

    [Hashtable] `$iniData = @{};
    `$rawData = Get-Content -Path `$FileName | Where-Object { `$_ -notmatch "^;.*$" -and `$_.Trim().Length -gt 0 };

    foreach ( `$line in `$rawData ) {
        if ( `$line -match "^\[(.+)\]" ) {
            `$section = `$Matches[ 1 ];

            if ( `$iniData.ContainsKey( `$section ) -eq `$false ) {
                `$iniData[ `$section ] = @{};
            }
        }

        if ( `$line -match "(.+?)\s*=(.*)" ) {
            `$name, `$value = `$Matches[ 1..2 ];
            `$value = `$value.TrimStart();
            `$value = `$value.TrimEnd();
            `$value = `$value.Replace( "``'", "" );
            `$value = `$value.Replace( "``"", "" );
            `$iniData[ `$section ][ `$name ] = `$value;
        }
    }

    return `$iniData;
}

function _WriteScriptLog {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = `$true, HelpMessage = 'Enter the information that should be logged.' )]
        [String] `$Message
    )

    Write-Debug -Message "FUNCTION: _WriteScriptLog -Message `$Message";

    [String] `$logMessage = "[{0}]`t{1}`t{2}" -f ( Get-Date -f "yyyy-MM-dd HH:mm:ss" ), `$MyInvocation.ScriptLineNumber, `$Message;
    Write-Debug -Message ( "[INFO:{0}] `$logMessage" -f `$logMessage );

    if ( Test-Path -Path `$Script:logFile ) {
        Add-Content -Path `$Script:logFile -Value `$logMessage -Encoding Unicode;
    } else {
        `$logDefault = `@"
=============================================================
  Log file created by PSUtils::New-PSScript
=============================================================
Timestamp`tLineNumber`tMessage
"`@;
        Set-Content -Path `$Script:logFile -Value `$logDefault -Encoding Unicode;
        Add-Content -Path `$Script:logFile -Value `$logMessage -Encoding Unicode;
    }
}

#TODO: ADD YOUR FUNCTIONS HERE

#endregion

#region Script Initialization

Write-Verbose -Message 'Entering script initialization region in script';
`$Script:logFile = `$MyInvocation.MyCommand.Path.Replace( '.ps1', '-Results.log' );
Write-Debug -Message ( "[INFO] `$Script:logFile = {0}" -f `$Script:logFile );

`$iniDefault = `@"
;=============================================================
;  Settings file created by PSUtils::New-PSScript
;=============================================================
[Variables]
;   Add all persistent or environment specific variables to be used for controlling script execution without parameters.
;
;   If the following variable is defined, by simply removing the initial ';', you can access the value in the script
;   by using the following:
;
;   `$ini.Variables.Sample
;
;   The returned data will contain everything to the right of the equal sign, which in this case is empty.
;
Sample=

[Usage]
Sample=This is a description of the variable that you will be able to see directly in PowerShell.

"`@;

Write-Verbose -Message 'Checking for parameter -IniFileName';
if ( `$IniFileName ) {
    Write-Verbose -Message ( "Checking for the following settings file: {0}" -f `$IniFileName );
    if ( Test-Path -Path `$IniFileName ) {
        Write-Verbose -Message 'Reading in the settings file';
        `$ini = _GetIniFile -FileName `$IniFileName;
    } else {
        Write-Verbose -Message 'There was an issue reading in the settings file at the specified location';
        Write-Warning -Message 'The specified INI file does not exist, please verify the information and run again.';
        break;
    }
} else {
    `$IniFileName = `$MyInvocation.MyCommand.Path.Replace( '.ps1', '-Settings.ini' );
    Write-Verbose -Message ( "Calculated settings file path: {0}" -f `$IniFileName );

    Write-Verbose -Message 'Check for an existing settings file';
    if ( Test-Path -Path `$IniFileName ) {
        Write-Verbose -Message 'Reading in the settings file';
        `$ini = _GetIniFile -FileName `$IniFileName;
    } else {
        Write-Verbose -Message 'Create the settings file and add the [Variables] section at the top';
        try {
            [IO.File]::OpenWrite( `$IniFileName ).Close();
        } catch {
            Write-Warning -Message ( "Failed to create file, possible permissions issue writing file: {0}" -f `$IniFileName );
            break;
        }
        Add-Content -Path `$IniFileName -Value `$iniDefault;
        Start-Process -FilePath `$IniFileName;
        Write-Warning -Message 'Please supply the appropriate values and run the script again.';
        break;
    }
}

Write-Verbose -Message 'Reading variables from the settings file';
`$ini.Variables.GetEnumerator() | ForEach-Object {
    Write-Debug -Message ( "[INFO] {0} = {1}" -f `$_.Name, `$_.Value );
}

#endregion

#region Main

<#
Script Usage Guidance

This script was created in an effort to standardize logging and accepting parameters from an ini file.

The following logging options and use cases are available within this script:
    _WriteScriptLog:
        This function can be used to write specific data to the results log. This can be used in conjunction with the Debug option below to add more rich data to the log.
        Example:

    Debug:
        This logging type should be leveraged for detailed programmatic information to the screen and log.
        Example:
        `$sampleVar = 'stuff';
        Write-Debug -Message ( "[Line:{0}] `$sampleVar = {1}" -f ( _GetCurrentLine ), `$sampleVar );

        This type of logging can be enabled in several ways. You can either add the -Debug switch to the script or update the `$DebugPreference variable.

    Verbose:
        This logging type should be leveraged to provide general information to the user.

#>


#TODO: ADD YOUR CODE HERE


#endregion

"@;

$basicScript = @"
#Requires -Version $requiredVersion

<#
.SYNOPSIS

.DESCRIPTION

.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS

.EXAMPLE

.NOTES
    Author:
    Version: $scriptVersion
.LINK

#>

[CmdletBinding()]
Param
(
    # TODO: Add script parameters here like the example commented below
    #[Parameter( Position = 0, Mandatory = `$true, HelpMessage = 'Enter the information that should be logged.' )]
    #[String] `$Message
)

#region Script Functions

function _GetCurrentLine {
    return `$MyInvocation.ScriptLineNumber;
}

function _WriteScriptLog {
    [CmdletBinding()]
    Param
    (
        [Parameter( Position = 0, Mandatory = `$true, HelpMessage = 'Enter the information that should be logged.' )]
        [String] `$Message
    )

    Write-Debug -Message "FUNCTION: _WriteScriptLog -Message `$Message";

    [String] `$logMessage = "[{0}]`t{1}`t{2}" -f ( Get-Date -f "yyyy-MM-dd HH:mm:ss" ), `$MyInvocation.ScriptLineNumber, `$Message;
    Write-Debug -Message ( "[Line:{0}] `$logMessage = {1}" -f ( _GetCurrentLine ), `$logMessage );

    if ( Test-Path -Path `$Script:logFile ) {
        Add-Content -Path `$Script:logFile -Value `$logMessage -Encoding Unicode;
    } else {
        `$logDefault = `@"
=============================================================
  Log file created by PSUtils::New-PSScript
=============================================================
Timestamp`tLineNumber`tMessage
"`@;
        Set-Content -Path `$Script:logFile -Value `$logDefault -Encoding Unicode;
        Add-Content -Path `$Script:logFile -Value `$logMessage -Encoding Unicode;
    }
}

#endregion

#region Script Initialization

`$Script:logFile = `$MyInvocation.MyCommand.Path.Replace( '.ps1', '-Results.log' );
Write-Debug -Message ( "[Line:{0}] `$Script:logFile = {1}" -f ( _GetCurrentLine ), `$Script:logFile );

#endregion

#region Main

<#
Script Usage Guidance

This script was created in an effort to standardize logging and accepting parameters from an ini file.

The following logging options and use cases are available within this script:
    _WriteScriptLog:
        This function can be used to write specific data to the results log. This can be used in conjunction with the Debug option below to add more rich data to the log.
        Example:

    Debug:
        This logging type should be leveraged for detailed programmatic information to the screen and log.
        Example:
        `$sampleVar = 'stuff';
        Write-Debug -Message ( "[Line:{0}] `$sampleVar = {1}" -f ( _GetCurrentLine ), `$sampleVar );

        This type of logging can be enabled in several ways. You can either add the -Debug switch to the script or update the `$DebugPreference variable.

    Verbose:
        This logging type should be leveraged to provide general information to the user.

#>


#TODO: ADD YOUR CODE HERE


#endregion

"@;

#endregion

    # Determine the type of script based on the IniSupport switch
    if ( $IniSupport ) {
        $newScript = $advancedScript;
    } else {
        $newScript = $basicScript;
    }

    if ( $Path -eq '' ) {
        $newScript | clip.exe;
        Write-Warning -Message 'Since no path was provided, the script body has been copied to the clipboard.'
    } else {
        if ( Test-Path -Path $Path -PathType Container ) {
            Write-Warning -Message 'Please specify a valid path and file name (i.e. C:\Temp\newscript.ps1)';
        } else {
            if ( Test-Path -Path $Path ) {
                Write-Warning -Message ( "The following file already exists ({0})" -f $Path );
            } else {
                Set-Content -Path $Path -Value $newScript;
            }
        }
    }
}

Export-ModuleMember -Function New-PSScript;