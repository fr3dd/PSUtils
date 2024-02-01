function Test-Extension {
    [CmdletBinding()]
    Param
    (
        [Parameter( Mandatory = $false, HelpMessage = "Specify the value to be tested" )]
        [String] $Value
    )

    Write-Verbose -Message 'Function: Test-Extension';
    Write-Host ( "Now that you called this cmdlet, make your own!" );
}

Export-ModuleMember -Function Test-Extension;