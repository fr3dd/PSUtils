<#
.SYNOPSIS
    This cmdlet will report interesting details about a local or remote machine.
.DESCRIPTION

.PARAMETER ComputerName
    This is an optional parameter which defines the computer name to pull information from.
.PARAMETER Credential
    This is an optional parameter which defines the credential to be used for pulling the information.
.INPUTS
    None. You cannot pipe objects to this script.
.OUTPUTS
    [Object] This command will return an object with information about the specified computer.
.EXAMPLE
    $localMachine = Get-WindowsSystemDetails;

    The preceding example exports information from the local computer.
.EXAMPLE
    $remoteMachine = Get-WindowsSystemDetails -ComputerName SERVER1

    The preceding example exports information from the computer named SERVER1.
.EXAMPLE
    $creds = Get-Credential;
    $remoteMachine = Get-WindowsSystemDetails -ComputerName SERVER2 -Credential $creds;

    The preceding example exports information from the computer named SERVER2 using the
    the account information stored in $creds.
.NOTES
    Author: fr3dd
    Version: 1.0.0
.LINK
    https://github.com/fr3dd/PSUtils.git
#>

#region API definitions

$typeDefinition = @'
using System;
namespace PowerShell.UserRights
{
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Principal;
    using LSA_HANDLE = IntPtr;

    public enum Rights
    {
        SeTrustedCredManAccessPrivilege,      // Access Credential Manager as a trusted caller
        SeNetworkLogonRight,                  // Access this computer from the network
        SeTcbPrivilege,                       // Act as part of the operating system
        SeMachineAccountPrivilege,            // Add workstations to domain
        SeIncreaseQuotaPrivilege,             // Adjust memory quotas for a process
        SeInteractiveLogonRight,              // Allow log on locally
        SeRemoteInteractiveLogonRight,        // Allow log on through Remote Desktop Services
        SeBackupPrivilege,                    // Back up files and directories
        SeChangeNotifyPrivilege,              // Bypass traverse checking
        SeSystemtimePrivilege,                // Change the system time
        SeTimeZonePrivilege,                  // Change the time zone
        SeCreatePagefilePrivilege,            // Create a pagefile
        SeCreateTokenPrivilege,               // Create a token object
        SeCreateGlobalPrivilege,              // Create global objects
        SeCreatePermanentPrivilege,           // Create permanent shared objects
        SeCreateSymbolicLinkPrivilege,        // Create symbolic links
        SeDebugPrivilege,                     // Debug programs
        SeDenyNetworkLogonRight,              // Deny access this computer from the network
        SeDenyBatchLogonRight,                // Deny log on as a batch job
        SeDenyServiceLogonRight,              // Deny log on as a service
        SeDenyInteractiveLogonRight,          // Deny log on locally
        SeDenyRemoteInteractiveLogonRight,    // Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege,          // Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege,            // Force shutdown from a remote system
        SeAuditPrivilege,                     // Generate security audits
        SeImpersonatePrivilege,               // Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege,        // Increase a process working set
        SeIncreaseBasePriorityPrivilege,      // Increase scheduling priority
        SeLoadDriverPrivilege,                // Load and unload device drivers
        SeLockMemoryPrivilege,                // Lock pages in memory
        SeBatchLogonRight,                    // Log on as a batch job
        SeServiceLogonRight,                  // Log on as a service
        SeSecurityPrivilege,                  // Manage auditing and security log
        SeRelabelPrivilege,                   // Modify an object label
        SeSystemEnvironmentPrivilege,         // Modify firmware environment values
        SeManageVolumePrivilege,              // Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege,      // Profile single process
        SeSystemProfilePrivilege,             // Profile system performance
        SeUnsolicitedInputPrivilege,          // "Read unsolicited input from a terminal device"
        SeUndockPrivilege,                    // Remove computer from docking station
        SeAssignPrimaryTokenPrivilege,        // Replace a process level token
        SeRestorePrivilege,                   // Restore files and directories
        SeShutdownPrivilege,                  // Shut down the system
        SeSyncAgentPrivilege,                 // Synchronize directory service data
        SeTakeOwnershipPrivilege              // Take ownership of files or other objects
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_ENUMERATION_INFORMATION
    {
        internal IntPtr PSid;
    }

    internal sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaAddAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaRemoveAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            out IntPtr /*LSA_UNICODE_STRING[]*/ UserRights,
            out ulong CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out ulong CountReturned
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);
    }

    internal sealed class Sid : IDisposable
    {
        public IntPtr pSid = IntPtr.Zero;
        public SecurityIdentifier sid = null;

        public Sid(string account)
        {
            try { sid = new SecurityIdentifier(account); }
            catch { sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier)); }
            Byte[] buffer = new Byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);

            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }

        public void Dispose()
        {
            if (pSid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSid);
                pSid = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Sid() { Dispose(); }
    }

    public sealed class LsaWrapper : IDisposable
    {
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a;

        IntPtr lsaHandle;

        public LsaWrapper() : this(null) { } // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public Rights[] EnumerateAccountPrivileges(string account)
        {
            uint ret = 0;
            ulong count = 0;
            IntPtr privileges = IntPtr.Zero;
            Rights[] rights = null;

            using (Sid sid = new Sid(account))
            {
                ret = Win32Sec.LsaEnumerateAccountRights(lsaHandle, sid.pSid, out privileges, out count);
            }
            if (ret == 0)
            {
                rights = new Rights[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_UNICODE_STRING str = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        IntPtr.Add(privileges, i * Marshal.SizeOf(typeof(LSA_UNICODE_STRING))),
                        typeof(LSA_UNICODE_STRING));
                    rights[i] = (Rights)Enum.Parse(typeof(Rights), str.Buffer);
                }
                Win32Sec.LsaFreeMemory(privileges);
                return rights;
            }
            if (ret == STATUS_OBJECT_NAME_NOT_FOUND) return null;  // No privileges assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public string[] EnumerateAccountsWithUserRight(Rights privilege)
        {
            uint ret = 0;
            ulong count = 0;
            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = InitLsaString(privilege.ToString());
            IntPtr buffer = IntPtr.Zero;
            string[] accounts = null;

            ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, rights, out buffer, out count);
            if (ret == 0)
            {
                accounts = new string[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_ENUMERATION_INFORMATION LsaInfo = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, i * Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION))),
                        typeof(LSA_ENUMERATION_INFORMATION));

                    try {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).Translate(typeof(NTAccount)).ToString();
                    } catch (System.Security.Principal.IdentityNotMappedException) {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString();
                    }
                }
                Win32Sec.LsaFreeMemory(buffer);
                return accounts;
            }
            if (ret == STATUS_NO_MORE_ENTRIES) return null;  // No accounts assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper() { Dispose(); }

        // helper functions:
        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe) throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }

}
'@;

if ( $PSEdition -ne 'Core' ) {
    if ( -not ( [System.Management.Automation.PSTypeName]'PowerShell.UserRights.Rights' ).Type ) {
        Add-Type $typeDefinition -ErrorAction SilentlyContinue;
    }
}

#endregion

function Get-WindowsSystemDetails {
    [CmdletBinding()]
    Param
    (
        [CmdletBinding()]
        [Parameter( Position = 0, Mandatory = $false, HelpMessage = 'Enter the computer name that you what to collect information from' )]
        [String] $ComputerName = ".",

        [Parameter( Position = 1, Mandatory = $false, HelpMessage = 'Enter a credential to perform the task' )]
        [Management.Automation.PSCredential] $Credential = $null
    )

    Write-Verbose -Message 'Cmdlet: Get-WindowsSystemDetails';
    Write-Verbose -Message ( " -ComputerName = {0}" -f $ComputerName );
    Write-Verbose -Message ( " -Credential = {0}" -f $Credential );

    [Boolean] $collectOptionalFeatures = $false;
    [Boolean] $collectServerFeatures = $false;
    [Boolean] $collectTasks = $false;
    [Boolean] $collectUserProfiles = $false;

    [Object] $errorOutput = [pscustomobject][ordered] @{
        Message = ''
    }

    [Object] $output = [pscustomobject][ordered] @{
        '_bcObjectType' = 'wmiComputer'
        '_bcID' = ''
        BootupState = ''
        Certificates = [Collections.ArrayList] @()
        ComputerName = ''
        Disks = [Collections.ArrayList] @()
        DomainName = ''
        DomainRole = ''
        DNSHostName = ''
        EnvironmentVariables = [ordered] @{}
        Groups = [ordered] @{}
        HostsFile = [Collections.ArrayList] @()
        InstalledFeatures = [Collections.ArrayList] @()
        InstalledRoles = [Collections.ArrayList] @()
        IsDomainController = $false
        IsDomainMember = $false
        IsPDCEmulator = $false
        IsVirtual = $false
        IsWorkgroupMember = $false
        LastBootUpTime = ''
        LogicalProcessors = 1
        Manufacturer = ''
        Memory = 0
        MissingSubnets = [Collections.ArrayList] @()
        Model = ''
        NetworkAdapters = [Collections.ArrayList] @()
        OperatingSystem = ''
        OperatingSystemArchitecture = ''
        OperatingSystemLanguage = 1033
        OperatingSystemServicePack = ''
        OperatingSystemSKU = ''
        OperatingSystemVersion = ''
        PhysicalProcessors = 1
        Printers = [Collections.ArrayList] @()
        SerialNumber = ''
        Services = [Collections.ArrayList] @()
        Shares = [Collections.ArrayList] @()
        Software = [Collections.ArrayList] @()
        SystemDirectory = ''
        SystemType = ''
        TCPPorts = [Collections.ArrayList] @()
        TimeDaylightInEffect = $false
        TimeSyncSource = ''
        TimeSyncType = ''
        TimeZone = ''
        UserProfiles = [Collections.ArrayList] @()
        UserRights = [ordered] @{}
        Users = [Collections.ArrayList] @()
        WindowsDirectory = ''
        WorkgroupName = ''
    }

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
            Write-Warning -Message "Unable to connect to $localComputer via WMI";

            $errorOutput.Message = 'WMIError';
            $output = $errorOutput;
        } else {
            $wmiClass = 'Win32_ComputerSystem';
            Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
            Write-Verbose -Message "Collect WMI information from $wmiClass";
            $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

            if ( $null -ne $cimData ) {
                $output.BootupState = $cimData.BootupState;
                Write-Verbose -Message ( "`$output.BootupState = {0}" -f $output.BootupState );

                $output._bcID = $cimData.Name;
                Write-Verbose -Message ( "`$output.ComputerName = {0}" -f $output.ComputerName );

                $output.ComputerName = $cimData.Name;
                Write-Verbose -Message ( "`$output.ComputerName = {0}" -f $output.ComputerName );

                Write-Verbose -Message 'Check for machine name match';
                if ( $localComputer -ne $cimData.Name ) {
                    Write-Verbose -Message ( "{0} <> {1}" -f $localComputer, $cimData.Name );
                    Write-Verbose -Message 'Checking NetBIOS name in case this is the Fully-Qualified Domain Name';
                    if ( $localComputer.Contains( '.' ) ) {
                        $netBIOSName = $localComputer.Split( '.' )[ 0 ];
                        Write-Verbose -Message ( "`$netBIOSName = {0}" -f $netBIOSName );

                        Write-Verbose -Message 'Check for machine name match';
                        if ( $netBIOSName -ne $cimData.Name ) {
                            Write-Verbose -Message ( "Provided name ({0}) does not match target machine name of ({1})" -f $netBIOSName, $cimData.Name );
                        } else {
                            Write-Verbose -Message ( "{0} = {1}" -f $netBIOSName, $cimData.Name );
                        }
                    } else {
                        Write-Verbose -Message ( "Provided name ({0}) does not match target machine name of ({1})" -f $localComputer, $cimData.Name );
                    }
                }

                $output.LogicalProcessors = $cimData.NumberOfLogicalProcessors;
                Write-Verbose -Message ( "`$output.LogicalProcessors = {0}" -f $output.LogicalProcessors );

                $output.PhysicalProcessors = $cimData.NumberOfProcessors;
                Write-Verbose -Message ( "`$output.PhysicalProcessors = {0}" -f $output.PhysicalProcessors );

                $output.TimeDaylightInEffect = $cimData.DaylightInEffect;
                Write-Verbose -Message ( "`$output.TimeDaylightInEffect = {0}" -f $output.TimeDaylightInEffect );

                $output.Manufacturer = $cimData.Manufacturer;
                Write-Verbose -Message ( "`$output.Manufacturer = {0}" -f $output.Manufacturer );

                $output.Memory = "{0} GB" -f [Math]::Round( $cimData.TotalPhysicalMemory / 1GB );
                Write-Verbose -Message ( "`$output.Memory = {0}" -f $output.Memory );

                $output.Model = $cimData.Model;
                Write-Verbose -Message ( "`$output.Model = {0}" -f $output.Model );

                if ( $output.Model -like '*Virtual*' ) {
                    $output.IsVirtual = $true;
                } elseif ( $output.Model -like '*VMware*' ) {
                    $output.IsVirtual = $true;
                } elseif ( $output.Model -like '*Microsoft*' ) {
                    $output.IsVirtual = $true;
                } elseif ( $output.Model -like '*Xen*' ) {
                    $output.IsVirtual = $true;
                } elseif ( $output.Model -like '*A M I*' ) {
                    $output.IsVirtual = $true;
                } else {
                    $output.IsVirtual = $false;
                }
                Write-Verbose -Message ( "`$output.IsVirtual = {0}" -f $output.IsVirtual );

                $output.SystemType = $cimData.SystemType;
                Write-Verbose -Message ( "`$output.SystemType = {0}" -f $output.SystemType );

                if ( $cimData.PartOfDomain ) {
                    $output.DomainName = $cimData.Domain;
                    Write-Verbose -Message ( "`$output.DomainName = {0}" -f $output.DomainName );

                    $output.DNSHostName = [String]::Format( "{0}.{1}", $cimData.Caption.ToLower(), $output.DomainName );
                    Write-Verbose -Message ( "`$output.DNSHostName = {0}" -f $output.DNSHostName );

                    $output.IsDomainMember = $true;
                    Write-Verbose -Message ( "`$output.IsDomainMember = {0}" -f $output.IsDomainMember );

                    $output.IsWorkgroupMember = $false;
                    Write-Verbose -Message ( "`$output.IsWorkgroupMember = {0}" -f $output.IsWorkgroupMember );

                    switch ( $cimData.DomainRole ) {
                        0 {
                            $output.DomainRole = 'Stadard Workstation';
                            $output.IsDomainController = $false;
                            $output.IsPDCEmulator = $false;
                        }
                        1 {
                            $output.DomainRole = 'Member Workstation';
                            $output.IsDomainController = $false;
                            $output.IsPDCEmulator = $false;
                        }
                        2 {
                            $output.DomainRole = 'Standard Server';
                            $output.IsDomainController = $false;
                            $output.IsPDCEmulator = $false;
                        }
                        3 {
                            $output.DomainRole = 'Member Server';
                            $output.IsDomainController = $false;
                            $output.IsPDCEmulator = $false;
                        }
                        4 {
                            $output.DomainRole = 'Domain Controller';
                            $output.IsDomainController = $true;
                            $output.IsPDCEmulator = $false;
                        }
                        5 {
                            $output.DomainRole = 'Domain Controller';
                            $output.IsDomainController = $true;
                            $output.IsPDCEmulator = $true;
                        }
                    }

                    Write-Verbose -Message ( "`$output.DomainRole = {0}" -f $output.DomainRole );
                    Write-Verbose -Message ( "`$output.IsDomainController = {0}" -f $output.IsDomainController );
                    Write-Verbose -Message ( "`$output.IsPDCEmulator = {0}" -f $output.IsPDCEmulator );
                    #bookmark Missing Subnet Information
                    if ( $output.IsDomainController ) {
                        Write-Verbose -Message 'Attempt to access netlogon file on DC to determine missing subnets';
                        Write-Verbose -Message 'Creating a PSDrive to reference the hosts file directory';
                        $remoteUNCPath = "\\{0}\admin$\debug" -f $localComputer;
                        Write-Verbose -Message ( "`$remoteUNCPath = {0}" -f $remoteUNCPath );

                        if ( $Credential ) {
                            $remoteDrive = New-PSDrive -Name 'remoteDrive' -PSProvider FileSystem -Root $remoteUNCPath -Credential $Credential -ErrorAction SilentlyContinue;
                        } else {
                            $remoteDrive = New-PSDrive -Name 'remoteDrive' -PSProvider FileSystem -Root $remoteUNCPath -ErrorAction SilentlyContinue;
                        }

                        if ( $null -ne $remoteDrive) {
                            [String] $netlogonPath = "remoteDrive:\netlogon.log" -f $remoteUNCPath;
                            Write-Verbose -Message ( "`$netlogonPath = {0}" -f $netlogonPath );

                            if ( Test-Path -Path $netlogonPath ) {
                                [Array] $netlogon = Get-Content -Path $netlogonPath -Tail 500 | Select-String 'NO_CLIENT_SITE:';
                                $missingSubnets = [Collections.ArrayList] @();

                                if ( $null -ne $netlogon ) {
                                    foreach ( $netlogonEntry in $netlogon ) {
                                        [String[]] $lineData = $netlogonEntry.ToString().Split(' ');

                                        [String] $machineName = $lineData[ $lineData.Count - 2 ];
                                        Write-Verbose -Message ( "`$machineName = {0}" -f $machineName );

                                        [String] $ipAddress = "{0}.0/24" -f $lineData[ $lineData.Count - 1 ].Substring( 0, $lineData[ $lineData.Count - 1 ].LastIndexOf( '.' ) );
                                        Write-Verbose -Message ( "`$ipAddress = {0}" -f $ipAddress );

                                        if ( -not $missingSubnets.Contains( $ipAddress ) ) {
                                            [Void] $missingSubnets.Add( $ipAddress );
                                        }
                                    }
                                }
                            }

                            Write-Verbose -Message 'Remove the PSDrive';
                            if ( Get-PSDrive -Name 'remoteDrive' ) {
                                Remove-PSDrive -Name 'remoteDrive';
                            }
                        }

                        $output.MissingSubnets = $missingSubnets;
                    }
                } else {
                    $output.DNSHostName = $cimData.Name.ToLower();
                    $output.IsDomainMember = $false;
                    $output.IsWorkgroupMember = $true;
                    $output.WorkgroupName = $cimData.Workgroup;
                }
                #bookmark Collect disk information
                try {
                    $wmiClass = 'Win32_LogicalDisk';
                    Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                    Write-Verbose -Message "Collect WMI information from $wmiClass";
                    $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

                    $logicalDisk = [ordered] @{
                        0 = 'Unknown'
                        1 = 'No root directory'
                        2 = 'Removable disk'
                        3 = 'Local disk'
                        4 = 'Network drive'
                        5 = 'Compact disc'
                        6 = 'RAM disk'
                    }

                    if ( $null -ne $cimData ) {
                        foreach ( $item in $cimData ) {
                            $freeSpace = "{0} GB" -f [Math]::Round( $item.FreeSpace / 1GB );
                            Write-Verbose -Message ( "`$freeSpace = {0}" -f $freeSpace );

                            $capacity = "{0} GB" -f [Math]::Round( $item.Size / 1GB );
                            Write-Verbose -Message ( "`$capacity = {0}" -f $capacity );

                            [Int32] $driveType = [Convert]::ToInt32( $item.DriveType );
                            Write-Verbose -Message ( "`$driveType = {0}" -f $driveType );

                            $childObject = [pscustomobject][ordered] @{
                                DeviceID = $item.DeviceID
                                DriveType = $logicalDisk[ $driveType ]
                                Capacity = $capacity
                                FreeSpace = $freeSpace
                                VolumeName = $item.VolumeName
                            }

                            [Void] $output.Disks.Add( $childObject );
                        }

                        $childObject = $null;
                    }
                } catch {
                    Write-Verbose -Message 'Logical disk information could not be collected';
                }
                #bookmark Collect environment variable information
                try {
                    $wmiClass = 'Win32_Environment';
                    Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                    Write-Verbose -Message "Collect WMI information from $wmiClass";
                    $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

                    if ( $null -ne $cimData ) {
                        foreach ( $item in $cimData ) {
                            Write-Verbose -Message 'Collect only system-level environment variables';
                            if ( $item.UserName -eq '<SYSTEM>' ) {
                                [String] $environmentVariable = $item.Name;
                                [String] $environmentVariableValue = $item.VariableValue;
                                [Void] $output.EnvironmentVariables.Add( $environmentVariable, $environmentVariableValue );
                            }
                        }
                    }
                } catch {
                    Write-Verbose -Message 'Environment information could not be collected';
                }
                #bookmark Collect operating system information
                try {
                    $wmiClass = 'Win32_OperatingSystem';
                    Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                    Write-Verbose -Message "Collect WMI information from $wmiClass";
                    $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

                    if ( $null -ne $cimData ) {
                        $output.OperatingSystem = $cimData.Name.Split( '|' )[ 0 ];
                        Write-Verbose -Message ( "`$output.OperatingSystem = {0}" -f $output.OperatingSystem );

                        switch ( $output.OperatingSystem ) {
                            { $_ -like '*Windows 7*' } {
                                $collectOptionalFeatures = $true;
                                $collectTasks = $true;
                                $collectUserProfiles = $true;
                                $oemServices = @(
                                    'ActiveX Installer (AxInstSV)',
                                    'Adaptive Brightness',
                                    'Application Experience',
                                    'Application Identity',
                                    'Application Information',
                                    'Application Layer Gateway Service',
                                    'Application Management',
                                    'Background Intelligent Transfer Service',
                                    'Base Filtering Engine',
                                    'BitLocker Drive Encryption Service',
                                    'Block Level Backup Engine Service',
                                    'Bluetooth Support Service',
                                    'BranchCache',
                                    'Certificate Propagation',
                                    'CNG Key Isolation',
                                    'COM+ Event System',
                                    'COM+ System Application',
                                    'Computer Browser',
                                    'Credential Manager',
                                    'Cryptographic Services',
                                    'DCOM Server Process Launcher',
                                    'Desktop Window Manager Session Manager',
                                    'DHCP Client',
                                    'Diagnostic Policy Service',
                                    'Diagnostic Service Host',
                                    'Diagnostic System Host',
                                    'Disk Defragmenter',
                                    'Distributed Link Tracking Client',
                                    'Distributed Transaction Coordinator',
                                    'DNS Client',
                                    'Encrypting File System (EFS)',
                                    'Extensible Authentication Protocol',
                                    'Fax',
                                    'Function Discovery Provider Host',
                                    'Function Discovery Resource Publication',
                                    'Group Policy Client',
                                    'Health Key and Certificate Management',
                                    'HomeGroup Provider',
                                    'Human Interface Device Access',
                                    'Hyper-V Data Exchange Service',
                                    'Hyper-V Guest Shutdown Service',
                                    'Hyper-V Heartbeat Service',
                                    'Hyper-V Time Synchronization Service',
                                    'Hyper-V Volume Shadow Copy Requestor',
                                    'IKE and AuthIP IPsec Keying Modules',
                                    'Interactive Services Detection',
                                    'Internet Connection Sharing (ICS)',
                                    'IP Helper',
                                    'IPsec Policy Agent',
                                    'KtmRm for Distributed Transaction Coordinator',
                                    'Link-Layer Topology Discovery Mapper',
                                    'Media Center Extender Service',
                                    'Microsoft .NET Framework NGEN v2.0.50727_X86',
                                    'Microsoft iSCSI Initiator Service',
                                    'Microsoft Software Shadow Copy Provider',
                                    'Multimedia Class Scheduler',
                                    'Net.Tcp Port Sharing Service',
                                    'Netlogon',
                                    'Network Access Protection Agent',
                                    'Network Connections',
                                    'Network List Service',
                                    'Network Location Awareness',
                                    'Network Store Interface Service',
                                    'Offline Files',
                                    'Parental Controls',
                                    'Peer Name Resolution Protocol',
                                    'Peer Networking Grouping',
                                    'Peer Networking Identity Manager',
                                    'Performance Logs & Alerts',
                                    'Plug and Play',
                                    'PnP-X IP Bus Enumerator',
                                    'PNRP Machine Name Publication Service',
                                    'Portable Device Enumerator Service',
                                    'Power',
                                    'Print Spooler',
                                    'Problem Reports and Solutions Control Panel Support',
                                    'Program Compatibility Assistant Service',
                                    'Protected Storage',
                                    'Quality Windows Audio Video Experience',
                                    'Remote Access Auto Connection Manager',
                                    'Remote Access Connection Manager',
                                    'Remote Desktop Configuration',
                                    'Remote Desktop Services',
                                    'Remote Desktop Services UserMode Port Redirector',
                                    'Remote Procedure Call (RPC)',
                                    'Remote Procedure Call (RPC) Locator',
                                    'Remote Registry',
                                    'Routing and Remote Access',
                                    'RPC Endpoint Mapper',
                                    'Secondary Logon',
                                    'Secure Socket Tunneling Protocol Service',
                                    'Security Accounts Manager',
                                    'Security Center',
                                    'Server',
                                    'Shell Hardware Detection',
                                    'Smart Card',
                                    'Smart Card Removal Policy',
                                    'SNMP Trap',
                                    'Software Protection',
                                    'SPP Notification Service',
                                    'SSDP Discovery',
                                    'Storage Service',
                                    'Superfetch',
                                    'System Event Notification Service',
                                    'Tablet PC Input Service',
                                    'Task Scheduler',
                                    'TCP/IP NetBIOS Helper',
                                    'Telephony',
                                    'Themes',
                                    'Thread Ordering Server',
                                    'TPM Base Services',
                                    'UPnP Device Host',
                                    'User Profile Service',
                                    'Virtual Disk',
                                    'Volume Shadow Copy',
                                    'WebClient',
                                    'Windows Audio',
                                    'Windows Audio Endpoint Builder',
                                    'Windows Backup',
                                    'Windows Biometric Service',
                                    'Windows CardSpace',
                                    'Windows Color System',
                                    'Windows Connect Now - Config Registrar',
                                    'Windows Defender',
                                    'Windows Driver Foundation - User-mode Driver Framework',
                                    'Windows Error Reporting Service',
                                    'Windows Event Collector',
                                    'Windows Event Log',
                                    'Windows Firewall',
                                    'Windows Font Cache Service',
                                    'Windows Image Acquisition (WIA)',
                                    'Windows Installer',
                                    'Windows Management Instrumentation',
                                    'Windows Media Center Receiver Service',
                                    'Windows Media Center Scheduler Service',
                                    'Windows Media Player Network Sharing Service',
                                    'Windows Modules Installer',
                                    'Windows Presentation Foundation Font Cache 3.0.0.0',
                                    'Windows Remote Management (WS-Management)',
                                    'Windows Search',
                                    'Windows Time',
                                    'Windows Update',
                                    'WinHTTP Web Proxy Auto-Discovery Service',
                                    'Wired AutoConfig',
                                    'WLAN AutoConfig',
                                    'WMI Performance Adapter',
                                    'Workstation',
                                    'WWAN AutoConfig'
                                );
                            }
                            { $_ -like '*Windows 8*' } {
                                $collectOptionalFeatures = $true;
                                $collectTasks = $true;
                                $collectUserProfiles = $true;
                                $oemServices = @(
                                    'ActiveX Installer (AxInstSV)',
                                    'Application Experience',
                                    'Application Identity',
                                    'Application Information',
                                    'Application Layer Gateway Service',
                                    'Application Management',
                                    'Background Intelligent Transfer Service',
                                    'Background Tasks Infrastructure Service',
                                    'Base Filtering Engine',
                                    'BitLocker Drive Encryption Service',
                                    'Block Level Backup Engine Service',
                                    'Bluetooth Support Service',
                                    'BranchCache',
                                    'Certificate Propagation',
                                    'CNG Key Isolation',
                                    'COM+ Event System',
                                    'COM+ System Application',
                                    'Computer Browser',
                                    'Credential Manager',
                                    'Cryptographic Services',
                                    'DCOM Server Process Launcher',
                                    'Device Association Service',
                                    'Device Install Service',
                                    'Device Setup Manager',
                                    'DHCP Client',
                                    'Diagnostic Policy Service',
                                    'Diagnostic Service Host',
                                    'Diagnostic System Host',
                                    'Distributed Link Tracking Client',
                                    'Distributed Transaction Coordinator',
                                    'DNS Client',
                                    'Encrypting File System (EFS)',
                                    'Extensible Authentication Protocol',
                                    'Family Safety',
                                    'Fax',
                                    'File History Service',
                                    'Function Discovery Provider Host',
                                    'Function Discovery Resource Publication',
                                    'Group Policy Client',
                                    'Health Key and Certificate Management',
                                    'HomeGroup Provider',
                                    'Human Interface Device Access',
                                    'Hyper-V Data Exchange Service',
                                    'Hyper-V Guest Shutdown Service',
                                    'Hyper-V Heartbeat Service',
                                    'Hyper-V Remote Desktop Virtualization Service',
                                    'Hyper-V Time Synchronization Service',
                                    'Hyper-V Volume Shadow Copy Requestor',
                                    'IKE and AuthIP IPsec Keying Modules',
                                    'Interactive Services Detection',
                                    'Internet Connection Sharing (ICS)',
                                    'IP Helper',
                                    'IPsec Policy Agent',
                                    'KtmRm for Distributed Transaction Coordinator',
                                    'Link-Layer Topology Discovery Mapper',
                                    'Local Session Manager',
                                    'Microsoft Account Sign-in Assistant',
                                    'Microsoft iSCSI Initiator Service',
                                    'Microsoft Software Shadow Copy Provider',
                                    'Multimedia Class Scheduler',
                                    'Net.Tcp Port Sharing Service',
                                    'Netlogon',
                                    'Network Access Protection Agent',
                                    'Network Connected Devices Auto-Setup',
                                    'Network Connections',
                                    'Network Connectivity Assistant',
                                    'Network List Service',
                                    'Network Location Awareness',
                                    'Network Store Interface Service',
                                    'Offline Files',
                                    'Optimize drives',
                                    'Peer Name Resolution Protocol',
                                    'Peer Networking Grouping',
                                    'Peer Networking Identity Manager',
                                    'Performance Counter DLL Host',
                                    'Performance Logs & Alerts',
                                    'Plug and Play',
                                    'PNRP Machine Name Publication Service',
                                    'Portable Device Enumerator Service',
                                    'Power',
                                    'Print Spooler',
                                    'Printer Extensions and Notifications',
                                    'Problem Reports and Solutions Control Panel Support',
                                    'Program Compatibility Assistant Service',
                                    'Quality Windows Audio Video Experience',
                                    'Remote Access Auto Connection Manager',
                                    'Remote Access Connection Manager',
                                    'Remote Desktop Configuration',
                                    'Remote Desktop Services',
                                    'Remote Desktop Services UserMode Port Redirector',
                                    'Remote Procedure Call (RPC)',
                                    'Remote Procedure Call (RPC) Locator',
                                    'Remote Registry',
                                    'Routing and Remote Access',
                                    'RPC Endpoint Mapper',
                                    'Secondary Logon',
                                    'Secure Socket Tunneling Protocol Service',
                                    'Security Accounts Manager',
                                    'Security Center',
                                    'Sensor Monitoring Service',
                                    'Server',
                                    'Shell Hardware Detection',
                                    'Smart Card',
                                    'Smart Card Removal Policy',
                                    'SNMP Trap',
                                    'Software Protection',
                                    'Spot Verifier',
                                    'SSDP Discovery',
                                    'Still Image Acquisition Events',
                                    'Storage Service',
                                    'Superfetch',
                                    'System Event Notification Service',
                                    'System Events Broker',
                                    'Task Scheduler',
                                    'TCP/IP NetBIOS Helper',
                                    'Telephony',
                                    'Themes',
                                    'Thread Ordering Server',
                                    'Time Broker',
                                    'Touch Keyboard and Handwriting Panel Service',
                                    'UPnP Device Host',
                                    'User Profile Service',
                                    'Virtual Disk',
                                    'Volume Shadow Copy',
                                    'WebClient',
                                    'Windows All-User Install Agent',
                                    'Windows Audio',
                                    'Windows Audio Endpoint Builder',
                                    'Windows Backup',
                                    'Windows Biometric Service',
                                    'Windows Color System',
                                    'Windows Connect Now - Config Registrar',
                                    'Windows Connection Manager',
                                    'Windows Defender Service',
                                    'Windows Driver Foundation - User-mode Driver Framework',
                                    'Windows Error Reporting Service',
                                    'Windows Event Collector',
                                    'Windows Event Log',
                                    'Windows Firewall',
                                    'Windows Font Cache Service',
                                    'Windows Image Acquisition (WIA)',
                                    'Windows Installer',
                                    'Windows Licensing Monitoring Service',
                                    'Windows Management Instrumentation',
                                    'Windows Media Player Network Sharing Service',
                                    'Windows Modules Installer',
                                    'Windows Remote Management (WS-Management)',
                                    'Windows Search',
                                    'Windows Store Service (WSService)',
                                    'Windows Time',
                                    'Windows Update',
                                    'WinHTTP Web Proxy Auto-Discovery Service',
                                    'Wired AutoConfig',
                                    'WLAN AutoConfig',
                                    'WMI Performance Adapter',
                                    'Workstation',
                                    'WWAN AutoConfig'
                                );
                            }
                            { $_ -like '*Windows 10*' } {
                                $collectOptionalFeatures = $true;
                                $collectTasks = $true;
                                $collectUserProfiles = $true;
                                $oemServices = @(
                                    'ActiveX Installer (AxInstSV)',
                                    'AllJoyn Router Service',
                                    'App Readiness',
                                    'Application Identity',
                                    'Application Information',
                                    'Application Layer Gateway Service',
                                    'Application Management',
                                    'AppX Deployment Service (AppXSVC)',
                                    'Auto Time Zone Updater',
                                    'Background Intelligent Transfer Service',
                                    'Background Tasks Infrastructure Service',
                                    'Base Filtering Engine',
                                    'BitLocker Drive Encryption Service',
                                    'Block Level Backup Engine Service',
                                    'Bluetooth Handsfree Service',
                                    'Bluetooth Support Service',
                                    'BranchCache',
                                    'CDPUserSvc_aa384',
                                    'Certificate Propagation',
                                    'Client License Service (ClipSVC)',
                                    'CNG Key Isolation',
                                    'COM+ Event System',
                                    'COM+ System Application',
                                    'Computer Browser',
                                    'Connected Devices Platform Service',
                                    'Connected User Experiences and Telemetry',
                                    'Contact Data_aa384',
                                    'CoreMessaging',
                                    'Credential Manager',
                                    'Cryptographic Services',
                                    'Data Sharing Service',
                                    'DataCollectionPublishingService',
                                    'DCOM Server Process Launcher',
                                    'Delivery Optimization',
                                    'Device Association Service',
                                    'Device Install Service',
                                    'Device Management Enrollment Service',
                                    'Device Setup Manager',
                                    'DevQuery Background Discovery Broker',
                                    'DHCP Client',
                                    'Diagnostic Policy Service',
                                    'Diagnostic Service Host',
                                    'Diagnostic System Host',
                                    'Distributed Link Tracking Client',
                                    'Distributed Transaction Coordinator',
                                    'dmwappushsvc',
                                    'DNS Client',
                                    'Downloaded Maps Manager',
                                    'Embedded Mode',
                                    'Encrypting File System (EFS)',
                                    'Enterprise App Management Service',
                                    'Extensible Authentication Protocol',
                                    'Fax',
                                    'File History Service',
                                    'Function Discovery Provider Host',
                                    'Function Discovery Resource Publication',
                                    'Geolocation Service',
                                    'Group Policy Client',
                                    'HomeGroup Provider',
                                    'Human Interface Device Service',
                                    'HV Host Service',
                                    'Hyper-V Data Exchange Service',
                                    'Hyper-V Guest Service Interface',
                                    'Hyper-V Guest Shutdown Service',
                                    'Hyper-V Heartbeat Service',
                                    'Hyper-V PowerShell Direct Service',
                                    'Hyper-V Remote Desktop Virtualization Service',
                                    'Hyper-V Time Synchronization Service',
                                    'Hyper-V Volume Shadow Copy Requestor',
                                    'IKE and AuthIP IPsec Keying Modules',
                                    'Infrared monitor service',
                                    'Interactive Services Detection',
                                    'Internet Connection Sharing (ICS)',
                                    'IP Helper',
                                    'IPsec Policy Agent',
                                    'KtmRm for Distributed Transaction Coordinator',
                                    'Link-Layer Topology Discovery Mapper',
                                    'Local Session Manager',
                                    'MessagingService_aa384',
                                    'Microsoft (R) Diagnostics Hub Standard Collector Service',
                                    'Microsoft Account Sign-in Assistant',
                                    'Microsoft App-V Client',
                                    'Microsoft iSCSI Initiator Service',
                                    'Microsoft Passport',
                                    'Microsoft Passport Container',
                                    'Microsoft Software Shadow Copy Provider',
                                    'Microsoft Storage Spaces SMP',
                                    'Microsoft Windows SMS Router Service.',
                                    'Net.Tcp Port Sharing Service',
                                    'Netlogon',
                                    'Network Connected Devices Auto-Setup',
                                    'Network Connection Broker',
                                    'Network Connections',
                                    'Network Connectivity Assistant',
                                    'Network List Service',
                                    'Network Location Awareness',
                                    'Network Setup Service',
                                    'Network Store Interface Service',
                                    'Offline Files',
                                    'Optimize drives',
                                    'Peer Name Resolution Protocol',
                                    'Peer Networking Grouping',
                                    'Peer Networking Identity Manager',
                                    'Performance Counter DLL Host',
                                    'Performance Logs & Alerts',
                                    'Phone Service',
                                    'Plug and Play',
                                    'PNRP Machine Name Publication Service',
                                    'Portable Device Enumerator Service',
                                    'Power',
                                    'Print Spooler',
                                    'Printer Extensions and Notifications',
                                    'Problem Reports and Solutions Control Panel Support',
                                    'Program Compatibility Assistant Service',
                                    'Quality Windows Audio Video Experience',
                                    'Radio Management Service',
                                    'Remote Access Auto Connection Manager',
                                    'Remote Access Connection Manager',
                                    'Remote Desktop Configuration',
                                    'Remote Desktop Services',
                                    'Remote Desktop Services UserMode Port Redirector',
                                    'Remote Procedure Call (RPC)',
                                    'Remote Procedure Call (RPC) Locator',
                                    'Remote Registry',
                                    'Retail Demo Service',
                                    'Routing and Remote Access',
                                    'RPC Endpoint Mapper',
                                    'Secondary Logon',
                                    'Secure Socket Tunneling Protocol Service',
                                    'Security Accounts Manager',
                                    'Security Center',
                                    'Sensor Data Service',
                                    'Sensor Monitoring Service',
                                    'Sensor Service',
                                    'Server',
                                    'Shared PC Account Manager',
                                    'Shell Hardware Detection',
                                    'Smart Card',
                                    'Smart Card Device Enumeration Service',
                                    'Smart Card Removal Policy',
                                    'SNMP Trap',
                                    'Software Protection',
                                    'Spot Verifier',
                                    'SSDP Discovery',
                                    'State Repository Service',
                                    'Still Image Acquisition Events',
                                    'Storage Service',
                                    'Storage Tiers Management',
                                    'Superfetch',
                                    'Sync Host_aa384',
                                    'System Event Notification Service',
                                    'System Events Broker',
                                    'Task Scheduler',
                                    'TCP/IP NetBIOS Helper',
                                    'Telephony',
                                    'Themes',
                                    'Tile Data model server',
                                    'Time Broker',
                                    'Touch Keyboard and Handwriting Panel Service',
                                    'Update Orchestrator Service for Windows Update',
                                    'UPnP Device Host',
                                    'User Data Access_aa384',
                                    'User Data Storage_aa384',
                                    'User Experience Virtualization Service',
                                    'User Manager',
                                    'User Profile Service',
                                    'Virtual Disk',
                                    'Volume Shadow Copy',
                                    'WalletService',
                                    'WebClient',
                                    'Windows Audio',
                                    'Windows Audio Endpoint Builder',
                                    'Windows Backup',
                                    'Windows Biometric Service',
                                    'Windows Camera Frame Server',
                                    'Windows Connect Now - Config Registrar',
                                    'Windows Connection Manager',
                                    'Windows Defender Advanced Threat Protection Service',
                                    'Windows Defender Network Inspection Service',
                                    'Windows Defender Service',
                                    'Windows Driver Foundation - User-mode Driver Framework',
                                    'Windows Encryption Provider Host Service',
                                    'Windows Error Reporting Service',
                                    'Windows Event Collector',
                                    'Windows Event Log',
                                    'Windows Firewall',
                                    'Windows Font Cache Service',
                                    'Windows Image Acquisition (WIA)',
                                    'Windows Insider Service',
                                    'Windows Installer',
                                    'Windows License Manager Service',
                                    'Windows Licensing Monitoring Service',
                                    'Windows Management Instrumentation',
                                    'Windows Media Player Network Sharing Service',
                                    'Windows Mobile Hotspot Service',
                                    'Windows Modules Installer',
                                    'Windows Push Notifications System Service',
                                    'Windows Push Notifications User Service_aa384',
                                    'Windows Remote Management (WS-Management)',
                                    'Windows Search',
                                    'Windows Time',
                                    'Windows Update',
                                    'WinHTTP Web Proxy Auto-Discovery Service',
                                    'Wired AutoConfig',
                                    'WLAN AutoConfig',
                                    'WMI Performance Adapter',
                                    'Work Folders',
                                    'Workstation',
                                    'WWAN AutoConfig',
                                    'Xbox Live Auth Manager',
                                    'Xbox Live Game Save',
                                    'Xbox Live Networking Service'
                                );
                            }
                            { $_ -like '*Windows Server 2003*' } {
                                $oemServices = @(
                                    '.NET Runtime Optimization Service v2.0.50727_X86',
                                    'Alerter',
                                    'Application Experience Lookup Service',
                                    'Application Layer Gateway Service',
                                    'Application Management',
                                    'ASP.NET State Service',
                                    'Automatic Updates',
                                    'Background Intelligent Transfer Service',
                                    'ClipBook',
                                    'COM+ Event System',
                                    'COM+ System Application',
                                    'Computer Browser',
                                    'Cryptographic Services',
                                    'DCOM Server Process Launcher',
                                    'DHCP Client',
                                    'Distributed File System',
                                    'Distributed Link Tracking Client',
                                    'Distributed Link Tracking Server',
                                    'Distributed Transaction Coordinator',
                                    'DNS Client',
                                    'Error Reporting Service',
                                    'Event Log',
                                    'File Replication',
                                    'Help and Support',
                                    'HTTP SSL',
                                    'Human Interface Device Access',
                                    'IMAPI CD-Burning COM Service',
                                    'Indexing Service',
                                    'Intersite Messaging',
                                    'IPSEC Services',
                                    'Kerberos Key Distribution Center',
                                    'License Logging',
                                    'Logical Disk Manager Administrative Service',
                                    'Logical Disk Manager',
                                    'Messenger',
                                    'Microsoft Software Shadow Copy Provider',
                                    'Net Logon',
                                    'Net.Tcp Port Sharing Service',
                                    'NetMeeting Remote Desktop Sharing',
                                    'Network Connections',
                                    'Network DDE DSDM',
                                    'Network DDE',
                                    'Network Location Awareness (NLA)',
                                    'Network Provisioning Service',
                                    'NT LM Security Support Provider',
                                    'Performance Logs and Alerts',
                                    'Plug and Play',
                                    'Portable Media Serial Number Service',
                                    'Print Spooler',
                                    'Protected Storage',
                                    'Remote Access Auto Connection Manager',
                                    'Remote Access Connection Manager',
                                    'Remote Desktop Help Session Manager',
                                    'Remote Procedure Call (RPC) Locator',
                                    'Remote Procedure Call (RPC)',
                                    'Remote Registry',
                                    'Removable Storage',
                                    'Resultant Set of Policy Provider',
                                    'Routing and Remote Access',
                                    'Secondary Logon',
                                    'Security Accounts Manager',
                                    'Server',
                                    'Shell Hardware Detection',
                                    'Smart Card',
                                    'Special Administration Console Helper',
                                    'System Event Notification',
                                    'Task Scheduler',
                                    'TCP/IP NetBIOS Helper',
                                    'Telephony',
                                    'Telnet',
                                    'Terminal Services Session Directory',
                                    'Terminal Services',
                                    'Themes',
                                    'Uninterruptible Power Supply',
                                    'Virtual Disk Service',
                                    'Volume Shadow Copy',
                                    'WebClient',
                                    'Windows Audio',
                                    'Windows CardSpace',
                                    'Windows Firewall/Internet Connection Sharing (ICS)',
                                    'Windows Image Acquisition (WIA)',
                                    'Windows Installer',
                                    'Windows Management Instrumentation Driver Extensions',
                                    'Windows Management Instrumentation',
                                    'Windows Presentation Foundation Font Cache 3.0.0.0',
                                    'Windows Time',
                                    'Windows User Mode Driver Framework',
                                    'WinHTTP Web Proxy Auto-Discovery Service',
                                    'Wireless Configuration',
                                    'WMI Performance Adapter',
                                    'Workstation'
                                );
                            }
                            { $_ -like '*Windows Server 2008*' } {
                                $collectServerFeatures = $true;
                                $collectTasks = $true;
                                $collectUserProfiles = $true;
                                $oemServices = @(
                                    'Application Experience',
                                    'Application Information',
                                    'Application Layer Gateway Service',
                                    'Application Management',
                                    'Background Intelligent Transfer Service',
                                    'Base Filtering Engine',
                                    'Certificate Propagation',
                                    'CNG Key Isolation',
                                    'COM+ Event System',
                                    'COM+ System Application',
                                    'Computer Browser',
                                    'Cryptographic Services',
                                    'DCOM Server Process Launcher',
                                    'Desktop Window Manager Session Manager',
                                    'DHCP Client',
                                    'Diagnostic Policy Service',
                                    'Diagnostic Service Host',
                                    'Diagnostic System Host',
                                    'Distributed Link Tracking Client',
                                    'Distributed Transaction Coordinator',
                                    'DNS Client',
                                    'Extensible Authentication Protocol',
                                    'Function Discovery Provider Host',
                                    'Function Discovery Resource Publication',
                                    'Group Policy Client',
                                    'Health Key and Certificate Management',
                                    'Human Interface Device Access',
                                    'IKE and AuthIP IPsec Keying Modules',
                                    'Interactive Services Detection',
                                    'Internet Connection Sharing (ICS)',
                                    'IP Helper',
                                    'IPsec Policy Agent',
                                    'KtmRm for Distributed Transaction Coordinator',
                                    'Link-Layer Topology Discovery Mapper',
                                    'Microsoft .NET Framework NGEN v2.0.50727_X86',
                                    'Microsoft Fibre Channel Platform Registration Service',
                                    'Microsoft iSCSI Initiator Service',
                                    'Microsoft Software Shadow Copy Provider',
                                    'Multimedia Class Scheduler',
                                    'Netlogon',
                                    'Network Access Protection Agent',
                                    'Network Connections',
                                    'Network List Service',
                                    'Network Location Awareness',
                                    'Network Store Interface Service',
                                    'Offline Files',
                                    'Performance Logs & Alerts',
                                    'Plug and Play',
                                    'PnP-X IP Bus Enumerator',
                                    'Portable Device Enumerator Service',
                                    'Print Spooler',
                                    'Problem Reports and Solutions Control Panel Support',
                                    'Protected Storage',
                                    'Remote Access Auto Connection Manager',
                                    'Remote Access Connection Manager',
                                    'Remote Procedure Call (RPC) Locator',
                                    'Remote Procedure Call (RPC)',
                                    'Remote Registry',
                                    'Resultant Set of Policy Provider',
                                    'Routing and Remote Access',
                                    'Secondary Logon',
                                    'Secure Socket Tunneling Protocol Service',
                                    'Security Accounts Manager',
                                    'Server',
                                    'Shell Hardware Detection',
                                    'SL UI Notification Service',
                                    'Smart Card Removal Policy',
                                    'Smart Card',
                                    'SNMP Trap',
                                    'Software Licensing',
                                    'Special Administration Console Helper',
                                    'SSDP Discovery',
                                    'Superfetch',
                                    'System Event Notification Service',
                                    'Task Scheduler',
                                    'TCP/IP NetBIOS Helper',
                                    'Telephony',
                                    'Terminal Services Configuration',
                                    'Terminal Services UserMode Port Redirector',
                                    'Terminal Services',
                                    'Themes',
                                    'Thread Ordering Server',
                                    'TPM Base Services',
                                    'UPnP Device Host',
                                    'User Profile Service',
                                    'Virtual Disk',
                                    'Volume Shadow Copy',
                                    'Windows Audio Endpoint Builder',
                                    'Windows Audio',
                                    'Windows Color System',
                                    'Windows Driver Foundation - User-mode Driver Framework',
                                    'Windows Error Reporting Service',
                                    'Windows Event Collector',
                                    'Windows Event Log',
                                    'Windows Firewall',
                                    'Windows Installer',
                                    'Windows Management Instrumentation',
                                    'Windows Modules Installer',
                                    'Windows Remote Management (WS-Management)',
                                    'Windows Time',
                                    'Windows Update',
                                    'WinHTTP Web Proxy Auto-Discovery Service',
                                    'Wired AutoConfig',
                                    'WMI Performance Adapter',
                                    'Workstation'
                                );
                            }
                            { $_ -like '*Windows Server 2012*' } {
                                $collectServerFeatures = $true;
                                $collectTasks = $true;
                                $collectUserProfiles = $true;
                                $oemServices = @(
                                    'Application Experience',
                                    'Application Identity',
                                    'Application Information',
                                    'Application Layer Gateway Service',
                                    'Application Management',
                                    'Background Intelligent Transfer Service',
                                    'Background Tasks Infrastructure Service',
                                    'Base Filtering Engine',
                                    'Certificate Propagation',
                                    'CNG Key Isolation',
                                    'COM+ Event System',
                                    'COM+ System Application',
                                    'Computer Browser',
                                    'Credential Manager',
                                    'Cryptographic Services',
                                    'DCOM Server Process Launcher',
                                    'Device Association Service',
                                    'Device Install Service',
                                    'Device Setup Manager',
                                    'DHCP Client',
                                    'Diagnostic Policy Service',
                                    'Diagnostic Service Host',
                                    'Diagnostic System Host',
                                    'Distributed Link Tracking Client',
                                    'Distributed Transaction Coordinator',
                                    'DNS Client',
                                    'Encrypting File System (EFS)',
                                    'Extensible Authentication Protocol',
                                    'Function Discovery Provider Host',
                                    'Function Discovery Resource Publication',
                                    'Group Policy Client',
                                    'Health Key and Certificate Management',
                                    'Human Interface Device Access',
                                    'IKE and AuthIP IPsec Keying Modules',
                                    'Interactive Services Detection',
                                    'Internet Connection Sharing (ICS)',
                                    'IP Helper',
                                    'IPsec Policy Agent',
                                    'KDC Proxy Server service (KPS)',
                                    'KtmRm for Distributed Transaction Coordinator',
                                    'Link-Layer Topology Discovery Mapper',
                                    'Local Session Manager',
                                    'Microsoft iSCSI Initiator Service',
                                    'Microsoft Software Shadow Copy Provider',
                                    'Multimedia Class Scheduler',
                                    'Net.Tcp Port Sharing Service',
                                    'Netlogon',
                                    'Network Access Protection Agent',
                                    'Network Connections',
                                    'Network Connectivity Assistant',
                                    'Network List Service',
                                    'Network Location Awareness',
                                    'Network Store Interface Service',
                                    'Optimize drives',
                                    'Performance Counter DLL Host',
                                    'Performance Logs & Alerts',
                                    'Plug and Play',
                                    'Portable Device Enumerator Service',
                                    'Power',
                                    'Print Spooler',
                                    'Printer Extensions and Notifications',
                                    'Problem Reports and Solutions Control Panel Support',
                                    'Remote Access Auto Connection Manager',
                                    'Remote Access Connection Manager',
                                    'Remote Desktop Configuration',
                                    'Remote Desktop Services UserMode Port Redirector',
                                    'Remote Desktop Services',
                                    'Remote Procedure Call (RPC) Locator',
                                    'Remote Procedure Call (RPC)',
                                    'Remote Registry',
                                    'Resultant Set of Policy Provider',
                                    'Routing and Remote Access',
                                    'RPC Endpoint Mapper',
                                    'Secondary Logon',
                                    'Secure Socket Tunneling Protocol Service',
                                    'Security Accounts Manager',
                                    'Server',
                                    'Shell Hardware Detection',
                                    'Smart Card Removal Policy',
                                    'Smart Card',
                                    'SNMP Trap',
                                    'Software Protection',
                                    'Special Administration Console Helper',
                                    'Spot Verifier',
                                    'SSDP Discovery',
                                    'Superfetch',
                                    'System Event Notification Service',
                                    'Task Scheduler',
                                    'TCP/IP NetBIOS Helper',
                                    'Telephony',
                                    'Themes',
                                    'Thread Ordering Server',
                                    'UPnP Device Host',
                                    'User Access Logging Service',
                                    'User Profile Service',
                                    'Virtual Disk',
                                    'Volume Shadow Copy',
                                    'Windows All-User Install Agent',
                                    'Windows Audio Endpoint Builder',
                                    'Windows Audio',
                                    'Windows Color System',
                                    'Windows Driver Foundation - User-mode Driver Framework',
                                    'Windows Error Reporting Service',
                                    'Windows Event Collector',
                                    'Windows Event Log',
                                    'Windows Firewall',
                                    'Windows Font Cache Service',
                                    'Windows Installer',
                                    'Windows Licensing Monitoring Service',
                                    'Windows Management Instrumentation',
                                    'Windows Modules Installer',
                                    'Windows Remote Management (WS-Management)',
                                    'Windows Store Service (WSService)',
                                    'Windows Time',
                                    'Windows Update',
                                    'WinHTTP Web Proxy Auto-Discovery Service',
                                    'Wired AutoConfig',
                                    'WMI Performance Adapter',
                                    'Workstation'
                                );
                            }
                            { $_ -like '*Windows Server 2016*' } {
                                $collectServerFeatures = $true;
                                $collectTasks = $true;
                                $collectUserProfiles = $true;
                                $oemServices = @(
                                    'ActiveX Installer (AxInstSV)',
                                    'AllJoyn Router Service',
                                    'App Readiness',
                                    'Application Identity',
                                    'Application Information',
                                    'Application Layer Gateway Service',
                                    'Application Management',
                                    'AppX Deployment Service (AppXSVC)',
                                    'Auto Time Zone Updater',
                                    'Background Intelligent Transfer Service',
                                    'Background Tasks Infrastructure Service',
                                    'Base Filtering Engine',
                                    'Bluetooth Support Service',
                                    'CDPUserSvc_2b9a9',
                                    'Certificate Propagation',
                                    'Client License Service (ClipSVC)',
                                    'CNG Key Isolation',
                                    'COM+ Event System',
                                    'COM+ System Application',
                                    'Computer Browser',
                                    'Connected Devices Platform Service',
                                    'Connected User Experiences and Telemetry',
                                    'Contact Data_2b9a9',
                                    'CoreMessaging',
                                    'Credential Manager',
                                    'Cryptographic Services',
                                    'Data Sharing Service',
                                    'DataCollectionPublishingService',
                                    'DCOM Server Process Launcher',
                                    'Device Association Service',
                                    'Device Install Service',
                                    'Device Management Enrollment Service',
                                    'Device Setup Manager',
                                    'DevQuery Background Discovery Broker',
                                    'DHCP Client',
                                    'Diagnostic Policy Service',
                                    'Diagnostic Service Host',
                                    'Diagnostic System Host',
                                    'Distributed Link Tracking Client',
                                    'Distributed Transaction Coordinator',
                                    'dmwappushsvc',
                                    'DNS Client',
                                    'Downloaded Maps Manager',
                                    'Embedded Mode',
                                    'Encrypting File System (EFS)',
                                    'Enterprise App Management Service',
                                    'Extensible Authentication Protocol',
                                    'Function Discovery Provider Host',
                                    'Function Discovery Resource Publication',
                                    'Geolocation Service',
                                    'Group Policy Client',
                                    'Human Interface Device Service',
                                    'HV Host Service',
                                    'IKE and AuthIP IPsec Keying Modules',
                                    'Interactive Services Detection',
                                    'Internet Connection Sharing (ICS)',
                                    'IP Helper',
                                    'IPsec Policy Agent',
                                    'KDC Proxy Server service (KPS)',
                                    'KtmRm for Distributed Transaction Coordinator',
                                    'Link-Layer Topology Discovery Mapper',
                                    'Local Session Manager',
                                    'Microsoft (R) Diagnostics Hub Standard Collector Service',
                                    'Microsoft Account Sign-in Assistant',
                                    'Microsoft App-V Client',
                                    'Microsoft iSCSI Initiator Service',
                                    'Microsoft Passport Container',
                                    'Microsoft Passport',
                                    'Microsoft Software Shadow Copy Provider',
                                    'Microsoft Storage Spaces SMP',
                                    'Net.Tcp Port Sharing Service',
                                    'Netlogon',
                                    'Network Connection Broker',
                                    'Network Connections',
                                    'Network Connectivity Assistant',
                                    'Network List Service',
                                    'Network Location Awareness',
                                    'Network Setup Service',
                                    'Network Store Interface Service',
                                    'Offline Files',
                                    'Optimize drives',
                                    'Performance Counter DLL Host',
                                    'Performance Logs & Alerts',
                                    'Phone Service',
                                    'Plug and Play',
                                    'Portable Device Enumerator Service',
                                    'Power',
                                    'Print Spooler',
                                    'Printer Extensions and Notifications',
                                    'Problem Reports and Solutions Control Panel Support',
                                    'Program Compatibility Assistant Service',
                                    'Quality Windows Audio Video Experience',
                                    'Radio Management Service',
                                    'Remote Access Auto Connection Manager',
                                    'Remote Access Connection Manager',
                                    'Remote Desktop Configuration',
                                    'Remote Desktop Services UserMode Port Redirector',
                                    'Remote Desktop Services',
                                    'Remote Procedure Call (RPC) Locator',
                                    'Remote Procedure Call (RPC)',
                                    'Remote Registry',
                                    'Resultant Set of Policy Provider',
                                    'Routing and Remote Access',
                                    'RPC Endpoint Mapper',
                                    'Secondary Logon',
                                    'Secure Socket Tunneling Protocol Service',
                                    'Security Accounts Manager',
                                    'Sensor Data Service',
                                    'Sensor Monitoring Service',
                                    'Sensor Service',
                                    'Server',
                                    'Shell Hardware Detection',
                                    'Smart Card Device Enumeration Service',
                                    'Smart Card Removal Policy',
                                    'Smart Card',
                                    'SNMP Trap',
                                    'Software Protection',
                                    'Special Administration Console Helper',
                                    'Spot Verifier',
                                    'SSDP Discovery',
                                    'State Repository Service',
                                    'Still Image Acquisition Events',
                                    'Storage Service',
                                    'Storage Tiers Management',
                                    'Superfetch',
                                    'Sync Host_2b9a9',
                                    'System Event Notification Service',
                                    'System Events Broker',
                                    'Task Scheduler',
                                    'TCP/IP NetBIOS Helper',
                                    'Telephony',
                                    'Themes',
                                    'Tile Data model server',
                                    'Time Broker',
                                    'Touch Keyboard and Handwriting Panel Service',
                                    'Update Orchestrator Service for Windows Update',
                                    'UPnP Device Host',
                                    'User Access Logging Service',
                                    'User Data Access_2b9a9',
                                    'User Data Storage_2b9a9',
                                    'User Experience Virtualization Service',
                                    'User Manager',
                                    'User Profile Service',
                                    'Virtual Disk',
                                    'Volume Shadow Copy',
                                    'WalletService',
                                    'Windows Audio Endpoint Builder',
                                    'Windows Audio',
                                    'Windows Biometric Service',
                                    'Windows Camera Frame Server',
                                    'Windows Connection Manager',
                                    'Windows Defender Network Inspection Service',
                                    'Windows Defender Service',
                                    'Windows Driver Foundation - User-mode Driver Framework',
                                    'Windows Encryption Provider Host Service',
                                    'Windows Error Reporting Service',
                                    'Windows Event Collector',
                                    'Windows Event Log',
                                    'Windows Firewall',
                                    'Windows Font Cache Service',
                                    'Windows Image Acquisition (WIA)',
                                    'Windows Insider Service',
                                    'Windows Installer',
                                    'Windows License Manager Service',
                                    'Windows Licensing Monitoring Service',
                                    'Windows Management Instrumentation',
                                    'Windows Mobile Hotspot Service',
                                    'Windows Modules Installer',
                                    'Windows Push Notifications System Service',
                                    'Windows Push Notifications User Service_2b9a9',
                                    'Windows Remote Management (WS-Management)',
                                    'Windows Search',
                                    'Windows Time',
                                    'Windows Update',
                                    'WinHTTP Web Proxy Auto-Discovery Service',
                                    'Wired AutoConfig',
                                    'WMI Performance Adapter',
                                    'Workstation',
                                    'Xbox Live Auth Manager',
                                    'Xbox Live Game Save'
                                );
                            }
                            { $_ -like '*Windows Server 2019*' } {
                                $collectServerFeatures = $true;
                                $collectTasks = $true;
                                $collectUserProfiles = $true;
                                $oemServices = @(
                                    'ActiveX Installer (AxInstSV)',
                                    'AllJoyn Router Service',
                                    'App Readiness',
                                    'Application Identity',
                                    'Application Information',
                                    'Application Layer Gateway Service',
                                    'Application Management',
                                    'AppX Deployment Service (AppXSVC)',
                                    'Auto Time Zone Updater',
                                    'AVCTP service',
                                    'Background Intelligent Transfer Service',
                                    'Background Tasks Infrastructure Service',
                                    'Base Filtering Engine',
                                    'Bluetooth Audio Gateway Service',
                                    'Bluetooth Support Service',
                                    'Capability Access Manager Service',
                                    'CaptureService_f56f2',
                                    'Certificate Propagation',
                                    'Client License Service (ClipSVC)',
                                    'Clipboard User Service_f56f2',
                                    'CNG Key Isolation',
                                    'COM+ Event System',
                                    'COM+ System Application',
                                    'Connected Devices Platform Service',
                                    'Connected Devices Platform User Service_f56f2',
                                    'Connected User Experiences and Telemetry',
                                    'ConsentUX_f56f2',
                                    'Contact Data_f56f2',
                                    'CoreMessaging',
                                    'Credential Manager',
                                    'Cryptographic Services',
                                    'Data Sharing Service',
                                    'DataCollectionPublishingService',
                                    'DCOM Server Process Launcher',
                                    'Delivery Optimization',
                                    'Device Association Service',
                                    'Device Install Service',
                                    'Device Management Enrollment Service',
                                    'Device Management Wireless Application Protocol (WAP) Push message Routing Service',
                                    'Device Setup Manager',
                                    'DevicePicker_f56f2',
                                    'DevicesFlow_f56f2',
                                    'DevQuery Background Discovery Broker',
                                    'DHCP Client',
                                    'Diagnostic Policy Service',
                                    'Diagnostic Service Host',
                                    'Diagnostic System Host',
                                    'Distributed Link Tracking Client',
                                    'Distributed Transaction Coordinator',
                                    'DNS Client',
                                    'Downloaded Maps Manager',
                                    'Embedded Mode',
                                    'Encrypting File System (EFS)',
                                    'Enterprise App Management Service',
                                    'Extensible Authentication Protocol',
                                    'Function Discovery Provider Host',
                                    'Function Discovery Resource Publication',
                                    'Geolocation Service',
                                    'GraphicsPerfSvc',
                                    'Group Policy Client',
                                    'Human Interface Device Service',
                                    'HV Host Service',
                                    'IKE and AuthIP IPsec Keying Modules',
                                    'Internet Connection Sharing (ICS)',
                                    'IP Helper',
                                    'IPsec Policy Agent',
                                    'KDC Proxy Server service (KPS)',
                                    'KtmRm for Distributed Transaction Coordinator',
                                    'Link-Layer Topology Discovery Mapper',
                                    'Local Session Manager',
                                    'Microsoft (R) Diagnostics Hub Standard Collector Service',
                                    'Microsoft Account Sign-in Assistant',
                                    'Microsoft App-V Client',
                                    'Microsoft iSCSI Initiator Service',
                                    'Microsoft Passport',
                                    'Microsoft Passport Container',
                                    'Microsoft Software Shadow Copy Provider',
                                    'Microsoft Storage Spaces SMP',
                                    'Microsoft Store Install Service',
                                    'Net.Tcp Port Sharing Service',
                                    'Netlogon',
                                    'Network Connection Broker',
                                    'Network Connections',
                                    'Network Connectivity Assistant',
                                    'Network List Service',
                                    'Network Location Awareness',
                                    'Network Setup Service',
                                    'Network Store Interface Service',
                                    'Offline Files',
                                    'OpenSSH Authentication Agent',
                                    'Optimize drives',
                                    'Payments and NFC/SE Manager',
                                    'Performance Counter DLL Host',
                                    'Performance Logs & Alerts',
                                    'Phone Service',
                                    'Plug and Play',
                                    'Portable Device Enumerator Service',
                                    'Power',
                                    'Print Spooler',
                                    'Printer Extensions and Notifications',
                                    'PrintWorkflow_f56f2',
                                    'Problem Reports and Solutions Control Panel Support',
                                    'Program Compatibility Assistant Service',
                                    'Quality Windows Audio Video Experience',
                                    'Radio Management Service',
                                    'Remote Access Auto Connection Manager',
                                    'Remote Access Connection Manager',
                                    'Remote Desktop Configuration',
                                    'Remote Desktop Services',
                                    'Remote Desktop Services UserMode Port Redirector',
                                    'Remote Procedure Call (RPC)',
                                    'Remote Procedure Call (RPC) Locator',
                                    'Remote Registry',
                                    'Resultant Set of Policy Provider',
                                    'Routing and Remote Access',
                                    'RPC Endpoint Mapper',
                                    'Secondary Logon',
                                    'Secure Socket Tunneling Protocol Service',
                                    'Security Accounts Manager',
                                    'Sensor Data Service',
                                    'Sensor Monitoring Service',
                                    'Sensor Service',
                                    'Server',
                                    'Shared PC Account Manager',
                                    'Shell Hardware Detection',
                                    'Smart Card',
                                    'Smart Card Device Enumeration Service',
                                    'Smart Card Removal Policy',
                                    'SNMP Trap',
                                    'Software Protection',
                                    'Special Administration Console Helper',
                                    'Spot Verifier',
                                    'SSDP Discovery',
                                    'State Repository Service',
                                    'Still Image Acquisition Events',
                                    'Storage Service',
                                    'Storage Tiers Management',
                                    'SysMain',
                                    'System Event Notification Service',
                                    'System Events Broker',
                                    'System Guard Runtime Monitor Broker',
                                    'Task Scheduler',
                                    'TCP/IP NetBIOS Helper',
                                    'Telephony',
                                    'Themes',
                                    'Time Broker',
                                    'Touch Keyboard and Handwriting Panel Service',
                                    'Update Orchestrator Service',
                                    'UPnP Device Host',
                                    'User Access Logging Service',
                                    'User Data Access_f56f2',
                                    'User Data Storage_f56f2',
                                    'User Experience Virtualization Service',
                                    'User Manager',
                                    'User Profile Service',
                                    'Virtual Disk',
                                    'Volume Shadow Copy',
                                    'WalletService',
                                    'WarpJITSvc',
                                    'Web Account Manager',
                                    'Windows Audio',
                                    'Windows Audio Endpoint Builder',
                                    'Windows Biometric Service',
                                    'Windows Camera Frame Server',
                                    'Windows Connection Manager',
                                    'Windows Defender Advanced Threat Protection Service',
                                    'Windows Defender Antivirus Network Inspection Service',
                                    'Windows Defender Antivirus Service',
                                    'Windows Defender Firewall',
                                    'Windows Encryption Provider Host Service',
                                    'Windows Error Reporting Service',
                                    'Windows Event Collector',
                                    'Windows Event Log',
                                    'Windows Font Cache Service',
                                    'Windows Image Acquisition (WIA)',
                                    'Windows Insider Service',
                                    'Windows Installer',
                                    'Windows License Manager Service',
                                    'Windows Licensing Monitoring Service',
                                    'Windows Management Instrumentation',
                                    'Windows Media Player Network Sharing Service',
                                    'Windows Mobile Hotspot Service',
                                    'Windows Modules Installer',
                                    'Windows Push Notifications System Service',
                                    'Windows Push Notifications User Service_f56f2',
                                    'Windows PushToInstall Service',
                                    'Windows Remote Management (WS-Management)',
                                    'Windows Search',
                                    'Windows Security Service',
                                    'Windows Time',
                                    'Windows Update',
                                    'Windows Update Medic Service',
                                    'WinHTTP Web Proxy Auto-Discovery Service',
                                    'Wired AutoConfig',
                                    'WMI Performance Adapter',
                                    'Workstation'
                                );
                            }
                            default {
                                $collectServerFeatures = $false;
                                $collectTasks = $false;
                                $collectUserProfiles = $false;
                                $oemServices = $null;
                            }
                        }

                        Write-Verbose -Message ( "`$collectTasks = {0}" -f $collectTasks );

                        $operatingSystemSKU = @{
                            0 = 'Undefined'
                            1 = 'Ultimate Edition'
                            2 = 'Home Basic Edition'
                            3 = 'Home Premium Edition'
                            4 = 'Enterprise Edition'
                            5 = 'Home Basic N Edition'
                            6 = 'Business Edition'
                            7 = 'Standard Server Edition'
                            8 = 'Datacenter Server Edition'
                            9 = 'Small Business Server Edition'
                            10 = 'Enterprise Server Edition'
                            11 = 'Starter Edition'
                            12 = 'Datacenter Server Core Edition'
                            13 = 'Standard Server Core Edition'
                            14 = 'Enterprise Server Core Edition'
                            15 = 'Enterprise Server IA64 Edition'
                            16 = 'Business N Edition'
                            17 = 'Web Server Edition'
                            18 = 'Cluster Server Edition'
                            19 = 'Home Server Edition'
                            20 = 'Storage Express Server Edition'
                            21 = 'Storage Standard Server Edition'
                            22 = 'Storage Workgroup Server Edition'
                            23 = 'Storage Enterprise Server Edition'
                            24 = 'Server For Small Business Edition'
                            25 = 'Small Business Server Premium Edition'
                            26 = '(unknown)'
                        }

                        $output.LastBootUpTime = Get-Date -Date $cimData.LastBootUpTime -Format u;
                        Write-Verbose -Message ( "`$output.LastBootUpTime = {0}" -f $output.LastBootUpTime );

                        $output.OperatingSystemArchitecture = $cimData.OSArchitecture;
                        Write-Verbose -Message ( "`$output.OperatingSystemArchitecture = {0}" -f $output.OperatingSystemArchitecture );

                        $output.OperatingSystemLanguage = $cimData.OSLanguage;
                        Write-Verbose -Message ( "`$output.OperatingSystemLanguage = {0}" -f $output.OperatingSystemLanguage );

                        [Int32] $OSsku = $cimData.OperatingSystemSKU;
                        $output.OperatingSystemSKU = $operatingSystemSKU[ $OSsku ];
                        Write-Verbose -Message ( "`$output.OperatingSystemSKU = {0}" -f $output.OperatingSystemSKU );

                        $output.OperatingSystemServicePack = $cimData.ServicePackMajorVersion;
                        Write-Verbose -Message ( "`$output.OperatingSystemServicePack = {0}" -f $output.OperatingSystemServicePack );

                        $output.OperatingSystemVersion = $cimData.Version;
                        Write-Verbose -Message ( "`$output.OperatingSystemVersion = {0}" -f $output.OperatingSystemVersion );

                        $output.SerialNumber = $cimData.SerialNumber;
                        Write-Verbose -Message ( "`$output.SerialNumber = {0}" -f $output.SerialNumber );

                        $output.SystemDirectory = $cimData.SystemDirectory;
                        Write-Verbose -Message ( "`$output.SystemDirectory = {0}" -f $output.SystemDirectory );

                        $output.WindowsDirectory = $cimData.WindowsDirectory;
                        Write-Verbose -Message ( "`$output.WindowsDirectory = {0}" -f $output.WindowsDirectory );

                        Write-Verbose -Message 'Reading the local hosts file';
                        if ( $output.OperatingSystem.WindowsDirectory -ne '' ) {
                            $remoteUNCPath = "\\{0}\{1}\system32\drivers\etc" -f $localComputer, ( $output.WindowsDirectory.Replace( ':', '$' ) );
                            Write-Verbose -Message ( "`$remoteUNCPath = {0}" -f $remoteUNCPath );

                            Write-Verbose -Message 'Creating a PSDrive to reference the hosts file directory';
                            if ( $Credential ) {
                                $remoteDrive = New-PSDrive -Name 'remoteDrive' -PSProvider FileSystem -Root $remoteUNCPath -Credential $Credential -ErrorAction SilentlyContinue;
                            } else {
                                $remoteDrive = New-PSDrive -Name 'remoteDrive' -PSProvider FileSystem -Root $remoteUNCPath -ErrorAction SilentlyContinue;
                            }

                            if ( $null -ne $remoteDrive ) {
                                Write-Verbose -Message 'Look for a hosts file on the PSDrive';
                                if ( Test-Path -Path "remoteDrive:\hosts" ) {
                                    Write-Verbose -Message 'Read in the contents of the local hosts file';
                                    $hostsData = Get-Content -Path "remoteDrive:\hosts";

                                    Write-Verbose -Message 'Iterate through the file one line at a time';
                                    for( $i = 0; $i -lt $hostsData.Count; $i++ ) {
                                        $lineData = $hostsData[ $i ];

                                        if ( $lineData -ne '' ) {
                                            if ( $lineData.Substring( 0, 1 ) -match '\d+' ) {
                                                if ( $lineData.Contains( "`t" ) ) {
                                                    $parts = $lineData.Split( "`t" );
                                                    $ipAddress = $parts[ 0 ];
                                                    Write-Verbose -Message ( "`$ipAddress = {0}" -f $ipAddress );

                                                    $hostName = $parts[ $parts.Count - 1 ].Trim();
                                                    Write-Verbose -Message ( "`$hostName = {0}" -f $hostName );
                                                } else {
                                                    $parts = $lineData.Split( ' ' );
                                                    $ipAddress = $parts[ 0 ];
                                                    Write-Verbose -Message ( "`$ipAddress = {0}" -f $ipAddress );

                                                    $hostName = $parts[ $parts.Count - 1 ].Trim();
                                                    Write-Verbose -Message ( "`$hostName = {0}" -f $hostName );
                                                }
                                            } else {
                                                continue;
                                            }

                                            [Object] $childObject = [pscustomobject][ordered] @{
                                                HostName = $hostName
                                                IPAddress = $ipAddress
                                            }

                                            [Void] $output.HostsFile.Add( $childObject );
                                        }
                                    }
                                }
                            }

                            Write-Verbose -Message 'Remove the PSDrive';
                            if ( Get-PSDrive -Name 'remoteDrive' -ErrorAction SilentlyContinue ) {
                                Remove-PSDrive -Name 'remoteDrive';
                            }
                        }
                    }
                } catch {
                    Write-Verbose -Message 'Operating system information could not be collected';
                }
                #bookmark Collect local group membership information
                try {
                    if ( $output.IsDomainController -eq $false ) {
                        $wmiClass = 'Win32_GroupUser';
                        Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                        Write-Verbose -Message "Collect WMI information from $wmiClass";
                        $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

                        if ( $null -ne $cimData ) {
                            foreach ( $item in $cimData ) {
                                $groupName = '';
                                $groupMember = '';

                                $groupName = $item.GroupComponent.Name;
                                Write-Verbose -Message ( "`$groupName = {0}" -f $groupName );

                                $groupMember = "{0}\{1}" -f $item.PartComponent.Domain, $item.PartComponent.Name;
                                Write-Verbose -Message ( "`$groupMember = {0}" -f $groupMember );

                                if ( $output.Groups.Contains( $groupName ) ) {
                                    Write-Verbose -Message ( "Add {0} as a member to the {1} local group" -f $groupMember, $groupName );
                                    [Void] $output.Groups[ $groupName ].Add( $groupMember );
                                } else {
                                    Write-Verbose -Message ( "Add a local group named {0}" -f $groupName );
                                    [Void] $output.Groups.Add( $groupName, [Collections.ArrayList]@() );

                                    Write-Verbose -Message ( "Add {0} as a member to the {1} local group" -f $groupMember, $groupName );
                                    [Void] $output.Groups[ $groupName ].Add( $groupMember );
                                }
                            }
                        }

                        # Collect local user information
                        Write-Verbose -Message 'Collect local users';

                        $wmiClass = 'Win32_UserAccount';
                        Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                        Write-Verbose -Message "Collect WMI information from $wmiClass";
                        $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

                        if ( $null -ne $cimData ) {
                            foreach ( $item in $cimData ) {
                                if ( $localComputer.Contains( '.' ) ) {
                                    if ( $item.Domain -eq ( $localComputer.Split( '.' )[ 0 ].ToUpper() ) ) {
                                        $localUser = "{0}\{1}" -f $item.Domain, $item.Name;
                                        Write-Verbose -Message ( "`$localUser = {0}" -f $localUser );

                                        [Void] $output.Users.Add( $localUser );
                                    }
                                } else {
                                    if ( $item.Domain -eq $localComputer.ToUpper() ) {
                                        $localUser = "{0}\{1}" -f $item.Domain, $item.Name;
                                        Write-Verbose -Message ( "`$localUser = {0}" -f $localUser );

                                        [Void] $output.Users.Add( $localUser );
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    Write-Verbose -Message 'Local group and user information could not be collected';
                }

                #bookmark Collect network adapter information
                try {
                    $wmiClass = 'Win32_NetworkAdapterConfiguration';
                    Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                    Write-Verbose -Message "Collect WMI information from $wmiClass";
                    $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass -Filter "MACAddress IS NOT NULL";

                    if ( $null -ne $cimData ) {
                        foreach ( $item in $cimData ) {
                            if ( $null -ne $item.DHCPLeaseExpires ) {
                                $dhcpLeaseExpires = Get-Date -Date $item.DHCPLeaseExpires -Format u;
                            } else {
                                $dhcpLeaseExpires = $null;
                            }

                            if ( $null -ne $item.DHCPLeaseObtained ) {
                                $dhcpLeaseObtained = Get-Date -Date $item.DHCPLeaseObtained -Format u;
                            } else {
                                $dhcpLeaseObtained = $null;
                            }

                            $winsServers = [Collections.ArrayList] @();

                            if ( $null -ne $item.WINSPrimaryServer ) {
                                $winsServers.Add( $item.WINSPrimaryServer );
                            }

                            if ( $null -ne $item.WINSSecondaryServer ) {
                                $winsServers.Add( $item.WINSSecondaryServer );
                            }

                            if ( $item.DefaultIPGateway.Count -eq 0 ) {
                                $defaultGateway = '';
                            } else {
                                $defaultGateway = $item.DefaultIPGateway[ 0 ];
                            }

                            [Object] $childObject = [pscustomobject][ordered] @{
                                DefaultGateway = $defaultGateway
                                Description = $item.Description
                                DHCPEnabled = $item.DHCPEnabled
                                DHCPLeaseExpires = $dhcpLeaseExpires
                                DHCPLeaseObtained = $dhcpLeaseObtained
                                DHCPServer = $item.DHCPServer
                                DNSServers = $item.DNSServerSearchOrder
                                DNSSuffixSearchOrder = $item.DNSDomainSuffixSearchOrder
                                IPAddresses = $item.IPAddress
                                IPSubnets = $item.IPSubnet
                                MACAddress = $item.MACAddress
                                WINSServers = $winsServers.ToArray()
                            }

                            [Void] $output.NetworkAdapters.Add( $childObject );
                        }

                        $childObject = $null;
                    }
                } catch {
                    Write-Verbose -Message 'Network adapter information could not be collected';
                }
                #bookmark Collect TCP port information
                try {
                    $portRange = @{
                        20 = 'FTP'
                        21 = 'FTP'
                        22 = 'SSH'
                        23 = 'Telnet'
                        25 = 'SMTP'
                        50 = 'IPSec'
                        51 = 'IPSec'
                        53 = 'DNS'
                        80 = 'HTTP'
                        88 = 'Kerberos'
                        110 = 'POP3'
                        135 = 'RPC'
                        139 = 'NetBIOS'
                        143 = 'IMAP'
                        389 = 'LDAP'
                        443 = 'HTTPS'
                        445 = 'SMB'
                        464 = 'Kerberos'
                        465 = 'SMTP over SSL'
                        500 = 'ISAKMP'
                        514 = 'syslog'
                        515 = 'LPD/LPR'
                        587 = 'SMTP'
                        636 = 'LDAP over SSL'
                        989 = 'FTP over SSL'
                        990 = 'FTP over SSL'
                        993 = 'IMAP over SSL'
                        995 = 'POP3 over SSL'
                        1433 = 'SQL server'
                        1434 = 'SQL server'
                        2179 =  'Hyper-V VM console'
                        2701 = 'SCCM remote control'
                        3050 = 'Interbase DB'
                        3268 = 'Global Catalog'
                        3269 = 'Global Catalog over SSL'
                        3306 = 'MySQL'
                        3343 = 'ClusSvc'
                        3389 = 'RDP'
                        5222 = 'XMPP/Jabber'
                        5223 = 'XMPP/Jabber'
                        5432 = 'PostgreSQL'
                        5500 = 'VNC Server'
                        5722 = 'DFSR'
                        5725 = 'FIM/MIM Service'
                        5985 = 'WinRM'
                        5986 = 'WinRM SSL'
                        6129 = 'DameWare'
                        8080 = 'HTTP Proxy'
                        9080 = 'WebDAV'
                        27017 = 'MongoDB'
                        27018 = 'MongoDB-shardsvr'
                        27109 = 'MongoDB-configsvr'
                    };

                    $timeout = 5;

                    foreach ( $port in $portRange.Keys ) {
                        $socket = New-Object System.Net.Sockets.TcpClient;

                        $connect = $socket.BeginConnect( $ComputerName, $port, $null, $null );

                        $tryConnect = Measure-Command { $connect.AsyncWaitHandle.WaitOne( $timeout, $true ) } | ForEach-Object totalmilliseconds;

                        $tryConnect | Out-Null;

                        if ( $socket.Connected ) {
                            [String] $data = '';
                            $data = "{0} ({1})" -f $portRange[ $port ], $port;
                            [Void] $output.TCPPorts.Add( $data );
                            $socket.Close();
                            $socket.Dispose();
                            $socket = $null;
                        }
                    }
                } catch { }

                $output.TCPPorts.Sort();

                #bookmark Collect printer information
                try {
                    $wmiClass = 'Win32_Printer';
                    Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                    Write-Verbose -Message "Collect WMI information from $wmiClass";
                    $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass -ErrorAction SilentlyContinue;

                    if ( $null -ne $cimData ) {
                        foreach ( $item in $cimData ) {
                            [Object] $childObject = [pscustomobject][ordered] @{
                                DriverName = $item.DriverName
                                Name = $item.Name
                                PortName = $item.PortName
                            }

                            [Void] $output.Printers.Add( $childObject );
                        }

                        $childObject = $null;
                    }
                } catch {
                    Write-Verbose -Message 'Printer information could not be collected';
                }
                #bookmark Collect installed component information from desktops
                try {
                    if ( $collectOptionalFeatures ) {
                        $wmiClass = 'Win32_OptionalFeature';
                        Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                        Write-Verbose -Message "Collect WMI information from $wmiClass";
                        $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

                        if ( $null -ne $cimData ) {
                            foreach ( $item in $cimData ) {
                                [Void] $output.InstalledFeatures.Add( $item.Name );
                            }
                        }

                        $output.InstalledFeatures.Sort();
                    }
                } catch {
                    Write-Verbose -Message 'Installed component information could not be collected';
                }
                #bookmark Collect installed component information
                try {
                    if ( $collectServerFeatures ) {
                        # Reference to IDs here https://docs.microsoft.com/en-us/windows/desktop/wmisdk/win32-serverfeature
                        $wmiClass = 'Win32_ServerFeature';
                        Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                        Write-Verbose -Message "Collect WMI information from $wmiClass";
                        $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

                        $roleIDs = [Collections.ArrayList] @(
                            1, # Application Server
                            2, # Web Server (IIS)
                            3, # Streaming Media Services
                            5, # Fax Server
                            6, # File and iSCSI Services
                            7, # Print and Document Services
                            8, # Active Directory Federation Services
                            9, # Active Directory Lightweight Directory Services
                            10, # Active Directory Domain Services
                            11, # UDDI Services
                            12, # DHCP Server
                            13, # DNS Server
                            14, # Network Policy and Access Services
                            16, # Active Directory Certificate Services
                            17, # Active Directory Rights Management Services
                            18, # Remote Desktop Services
                            19, # Windows Deployment Services
                            20, # Hyper-V
                            21, # Windows Server Update Services
                            468, # Remote Access
                            481, # File and Storage Services
                            485, # Windows Server Essentials Experience
                            255 # File Server
                        )

                        if ( $null -ne $cimData ) {
                            foreach ( $item in $cimData ) {
                                if ( $roleIDs.Contains( [Convert]::ToInt32( $item.ID ) ) ) {
                                    [Object] $childObject = [pscustomobject][ordered] @{
                                        ID = $item.ID
                                        Name = $item.Name
                                        RoleComponents = [Collections.ArrayList] @()
                                    }

                                    foreach ( $internalItem in $cimData ) {
                                        if ( [Convert]::ToInt32( $internalItem.ParentID ) -eq $childObject.ID ) {
                                            [Void] $childObject.RoleComponents.Add( $internalItem.Name );
                                        }
                                    }

                                    $childObject.RoleComponents.Sort();

                                    [Void] $output.InstalledRoles.Add( $childObject );
                                } else {
                                    if ( [Convert]::ToInt32( $item.ParentID ) -eq 0 ) {
                                        [Void] $output.InstalledFeatures.Add( $item.Name );
                                    }
                                }
                            }
                        }

                        $output.InstalledFeatures.Sort();
                    }
                } catch {
                    Write-Verbose -Message 'Installed component information could not be collected';
                }
                #bookmark Collect services information
                try {
                    $wmiClass = 'Win32_Service';
                    Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                    Write-Verbose -Message "Collect WMI information from $wmiClass";
                    $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

                    $commonServiceStartAs = [Collections.ArrayList] @(
                        'LOCALSYSTEM',
                        'NT AUTHORITY\LOCALSERVICE',
                        'NT AUTHORITY\NETWORKSERVICE',
                        'NT AUTHORITY\SYSTEM'
                    )

                    if ( $null -ne $cimData ) {
                        foreach ( $item in $cimData ) {
                            [Object] $childObject = [pscustomobject][ordered] @{
                                Caption = $item.Caption
                                Name = $item.Name
                                IsAccountDependent = $false
                                IsOEMService = $true
                                PathName = $item.PathName
                                StartName = $item.StartName
                                StartMode = $item.StartMode
                                State = $item.State
                            }

                            if ( $commonServiceStartAs.Contains( ( $item.StartName.ToUpper() ) ) -eq $false ) {
                                $childObject.IsAccountDependent = $true;
                            }

                            if ( $null -ne $oemServices ) {
                                if ( $oemServices.Contains( $item.Caption ) -eq $false ) {
                                    $childObject.IsOEMService = $false;
                                }
                            }

                             [Void] $output.Services.Add( $childObject );
                        }

                        $childObject = $null;
                    }
                } catch {
                    Write-Verbose -Message 'Services information could not be collected';
                }
                #bookmark Collect share information
                try {
                    $wmiClass = 'Win32_Share';
                    Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                    Write-Verbose -Message "Collect WMI information from $wmiClass";
                    $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

                    if ( $null -ne $cimData ) {
                        foreach ( $item in $cimData ) {
                            [Object] $childObject = [pscustomobject][ordered] @{
                                Description = $item.Description
                                Name = $item.Name
                                Path = $item.Path
                                ShareType = ''
                            }

                            switch ( $item.Type ) {
                                0 {
                                    $childObject.ShareType = 'Disk Drive';
                                }
                                1 {
                                    $childObject.ShareType = 'Print Queue';
                                }
                                2 {
                                    $childObject.ShareType = 'Device';
                                }
                                3 {
                                    $childObject.ShareType = 'IPC';
                                }
                                2147483648 {
                                    $childObject.ShareType = 'Disk Drive Admin';
                                }
                                2147483649 {
                                    $childObject.ShareType = 'Print Queue Admin';
                                }
                                2147483650 {
                                    $childObject.ShareType = 'Device Admin';
                                }
                                2147483651 {
                                    $childObject.ShareType = 'IPC Admin';
                                }
                                default {
                                    $childObject.ShareType = 'Unknown (Undocumented)';
                                }
                            }

                            [Void] $output.Shares.Add( $childObject );
                        }

                        $childObject = $null;
                    }
                } catch {
                    Write-Verbose -Message 'Share information could not be collected';
                }
                #bookmark Software Information
                if ( $PSEdition -ne 'Core' ) {
                    $HKLM = [UInt32] "0x80000002";
                    # Connect to the registry provider
                    if ( $null -eq $Credential ) {
                        $regProv = Get-WmiObject -List 'StdRegProv' -Namespace 'root\default' -ComputerName $localComputer -ErrorAction SilentlyContinue;
                    } else {
                        $regProv = Get-WmiObject -List 'StdRegProv' -Namespace 'root\default' -ComputerName $localComputer -Credential $Credential -ErrorAction SilentlyContinue;
                    }
                    # Collect software information
                    $installKeys = @( 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' );

                    try {
                        Write-Verbose -Message 'Collect software information from the registry';
                        foreach ( $registryKey in $installKeys ) {
                            $keys = $regProv.EnumKey( $HKLM, $registryKey );

                            foreach ( $key in $keys.sNames ) {
                                $displayName = '';
                                $displayVersion = '';
                                $installPath = '';
                                $publisher = '';

                                $relativePath = Join-Path $registryKey $key;
                                $installPath = $regProv.GetStringValue( $HKLM, $relativePath, 'InstallLocation' ).sValue;

                                if ( $null -eq $installPath ) { continue; }
                                if ( $installPath.Length -eq 0 ) { continue; }

                                $displayName = $regProv.GetStringValue( $HKLM, $relativePath, 'DisplayName' ).sValue;
                                $displayVersion = $regProv.GetStringValue( $HKLM, $relativePath, 'DisplayVersion' ).sValue;
                                $publisher = $regProv.GetStringValue( $HKLM, $relativePath, 'Publisher' ).sValue;

                                [Object] $childObject = [pscustomobject][ordered] @{
                                    'DisplayName' = $displayName
                                    'Version' = $displayVersion
                                    'InstallPath' = $installPath
                                    'Publisher' = $publisher
                                }

                                [Void] $output.Software.Add( $childObject );
                            }
                        }

                        $childObject = $null;
                    } catch {
                        Write-Verbose -Message 'Software information could not be collected';
                    }
                    #bookmark Collect time server information
                    try {
                        $registryKey = 'SYSTEM\CurrentControlSet\Services\W32Time\Parameters';

                        $output.TimeSyncType = $regProv.GetStringValue( $HKLM, $registryKey, 'Type' ).sValue;
                        Write-Verbose -Message ( "`$output.TimeSyncType = {0}" -f $output.TimeSyncType );

                        if ( $output.TimeSyncType -eq 'NT5DS' ) {
                            if ( $false -eq $output.IsPDCEmulator ) {
                                if ( $output.IsDomainMember ) {
                                    $output.TimeSyncSource = 'Domain';
                                } else {
                                    $output.TimeSyncSource = $regProv.GetStringValue( $HKLM, $registryKey, 'NtpServer' ).sValue;
                                }
                            }
                        } else {
                            $output.TimeSyncSource = $regProv.GetStringValue( $HKLM, $registryKey, 'NtpServer' ).sValue;
                        }

                        Write-Verbose -Message ( "`$output.TimeSyncSource = {0}" -f $output.TimeSyncSource );
                    } catch {
                        Write-Verbose -Message 'Time server information could not be collected';
                    }
                }
                # Collecting time zone information
                try {
                    $wmiClass = 'Win32_TimeZone';
                    Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                    Write-Verbose -Message "Collect WMI information from $wmiClass";
                    $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

                    if ( $null -ne $cimData ) {
                        $output.TimeZone = $cimData.Caption;
                        Write-Verbose -Message ( "`$output.TimeZone = {0}" -f $output.TimeZone );
                    }
                } catch {
                    Write-Verbose -Message 'Time zone information could not be collected';
                }
                #bookmark Collect certificate information
                if ( $null -eq $Credential ) {
                    try {
                        Write-Verbose -Message 'Collect certificate information';
                        # Collect personal store certificates
                        Write-Verbose -Message 'Collecting personal certificates for the machine';
                        $storeName = "\\{0}\My" -f $localComputer;
                        Write-Verbose -Message ( "`$storeName = {0}" -f $storeName );
                        $certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store( $storeName, [Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine );
                        $certStore.Open( [Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly );

                        foreach ( $certificate in $certStore.Certificates ) {
                            $keyUsages = ( $certificate.Extensions.KeyUsages -replace ' ', '' ) -split ',';

                            $notAfter = Get-Date -Date $certificate.NotAfter -Format u;
                            $notBefore = Get-Date -Date $certificate.NotBefore -Format u;

                            [Object] $childObject = [pscustomobject][ordered] @{
                                'FriendlyName' = $certificate.FriendlyName
                                'Issuer' = $certificate.Issuer
                                'KeyUsages' = $keyUsages
                                'NotAfter' = $notAfter
                                'NotBefore' = $notBefore
                                'Store' = 'Personal'
                                'Subject' = $certificate.Subject
                                'Thumbprint' = $certificate.Thumbprint
                            }

                            [Void] $output.Certificates.Add( $childObject );
                        }

                        $childObject = $null;
                    } catch {
                        Write-Verbose -Message 'Certificate information could not be collected';
                    }
                }
                #bookmark Collect user profile information
                if ( $collectUserProfiles ) {
                    try {
                        $wmiClass = 'Win32_UserProfile';
                        Write-Verbose -Message ( "`$wmiClass = {0}" -f $wmiClass );
                        Write-Verbose -Message "Collect WMI information from $wmiClass";
                        $cimData = Get-CimInstance -CimSession $cimSession -ClassName $wmiClass;

                        if ( $null -ne $cimData ) {
                            $userProfiles = $cimData | Where-Object { $_.SID.Length -gt 8 };

                            foreach ( $userProfile in $userProfiles ) {
                                if ( $null -eq $userProfile.LastUseTime ) {
                                    $lastUseTime = $null;
                                } else {
                                    $lastUseTime = Get-Date -Date $userProfile.LastUseTime -Format u -ErrorAction SilentlyContinue;
                                }

                                [Object] $childObject = [pscustomobject][ordered] @{
                                    LastUseTime = $lastUseTime
                                    LocalPath = $userProfile.LocalPath
                                    SID = $userProfile.SID
                                }

                                [Void] $output.UserProfiles.Add( $childObject );
                            }

                            $childObject = $null;
                        }
                    } catch {
                        Write-Verbose -Message 'User profile information could not be collected';
                    }
                }
                #bookmark Collect User Rights Assignments
                if ( $PSEdition -ne 'Core' ) {
                    try {
                        $lsa = New-Object PowerShell.UserRights.LsaWrapper( $localComputer );

                        $userRights = [ordered] @{
                            SeAuditPrivilege = 'Generate security audits'
                            SeAssignPrimaryTokenPrivilege = 'Replace a process level token'
                            SeBatchLogonRight = 'Log on as a batch job'
                            SeBackupPrivilege = 'Back up files and directories'
                            SeChangeNotifyPrivilege = 'Bypass traverse checking'
                            SeCreateGlobalPrivilege = 'Create global objects'
                            SeCreatePagefilePrivilege = 'Create a pagefile'
                            SeCreatePermanentPrivilege = 'Create permanent shared objects'
                            SeCreateSymbolicLinkPrivilege = 'Create symbolic links'
                            SeCreateTokenPrivilege = 'Create a token object'
                            SeDebugPrivilege = 'Debug programs'
                            SeDenyBatchLogonRight = 'Deny log on as a batch job'
                            SeDenyInteractiveLogonRight = 'Deny log on locally'
                            SeDenyNetworkLogonRight = 'Deny access this computer from the network'
                            SeDenyServiceLogonRight = 'Deny log on as a service'
                            SeDenyRemoteInteractiveLogonRight = 'Deny log on through Remote Desktop Services'
                            SeEnableDelegationPrivilege = 'Enable computer and user accounts to be trusted for delegation'
                            SeInteractiveLogonRight = 'Allow log on locally'
                            SeIncreaseBasePriorityPrivilege = 'Increase scheduling priority'
                            SeIncreaseQuotaPrivilege = 'Adjust memory quotas for a process'
                            SeIncreaseWorkingSetPrivilege = 'Increase a process working set'
                            SeImpersonatePrivilege = 'Impersonate a client after authentication'
                            SeLoadDriverPrivilege = 'Load and unload device drivers'
                            SeLockMemoryPrivilege = 'Lock pages in memory'
                            SeMachineAccountPrivilege = 'Add workstations to domain'
                            SeManageVolumePrivilege = 'Perform volume maintenance tasks'
                            SeNetworkLogonRight = 'Access this computer from the network'
                            SeProfileSingleProcessPrivilege = 'Profile single process'
                            SeRelabelPrivilege = 'Modify an object label'
                            SeRemoteInteractiveLogonRight = 'Allow log on through Remote Desktop Services'
                            SeRemoteShutdownPrivilege = 'Force shutdown from a remote system'
                            SeRestorePrivilege = 'Restore files and directories'
                            SeSecurityPrivilege = 'Manage auditing and security log'
                            SeServiceLogonRight = 'Log on as a service'
                            SeShutdownPrivilege = 'Shut down the system'
                            SeSyncAgentPrivilege = 'Synchronize directory service data'
                            SeSystemEnvironmentPrivilege = 'Modify firmware environment values'
                            SeSystemProfilePrivilege = 'Profile system performance'
                            SeSystemtimePrivilege = 'Change the system time'
                            SeTakeOwnershipPrivilege = 'Take ownership of files or other objects'
                            SeTcbPrivilege = 'Act as part of the operating system'
                            SeTimeZonePrivilege = 'Change the time zone'
                            SeTrustedCredManAccessPrivilege = 'Access Credential Manager as a trusted caller'
                            SeUndockPrivilege = 'Remove computer from docking station'
                            SeUnsolicitedInputPrivilege = 'Read unsolicited input from a terminal device'
                        }

                        foreach ( $userRight in $userRights.Keys.GetEnumerator() ) {
                            try {
                                $assignedPrincipals = $lsa.EnumerateAccountsWithUserRight( $userRight );
                                $output.UserRights.Add( $userRight, $assignedPrincipals );
                            } catch {
                                $output.UserRights.Add( $userRight, $null );
                            }
                        }

                        $lsa = $null;
                    } catch {
                        Write-Verbose -Message 'User rights assignments information could not be collected';
                    }
                } else {
                    Write-Verbose -Message 'User rights assignments information cannot be collected using PowerShell Core';
                }

                if ( $null -ne $cimSession ) {
                    $cimSession.Close();
                    $cimSession = $null;
                }
            } else {
                $output = $null;
            }
        }
    } else {
        Write-Warning -Message "Unable to ping $localComputer";
        $errorOutput.Message = 'PingError';
        $output = $errorOutput;
    }

    Write-Output -InputObject $output;
}

Export-ModuleMember -Function Get-WindowsSystemDetails;