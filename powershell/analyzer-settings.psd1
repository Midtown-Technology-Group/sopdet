@{
    # Enforces PowerShell 3.0 compatibility for the endpoint collector so it can
    # run on Windows 7 / Server 2008 R2 (WMF 3+) through Windows 11.
    #
    # TargetVersions  -> syntax primitives (no '??', '?:', classes, ...)
    # TargetProfiles  -> commands present in Windows 8/2012 (PS 3.0),
    #                    Windows 8.1/2012 R2 (PS 4.0), Windows Server 2016 (PS 5.1)
    # IgnoreCommands  -> optional, runtime-guarded commands (Get-Command / try-catch
    #                    with fallbacks); they do not break the 3.0 floor
    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('3.0', '4.0', '5.1')
        }
        PSUseCompatibleCommands = @{
            Enable         = $true
            TargetProfiles = @(
                'win-8_x64_6.2.9200.0_3.0_x64_4.0.30319.42000_framework',
                'win-8_x64_6.3.9600.0_4.0_x64_4.0.30319.42000_framework',
                'win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework'
            )
            IgnoreCommands = @('Get-LocalUser', 'Get-MpComputerStatus')
        }
    }
}
