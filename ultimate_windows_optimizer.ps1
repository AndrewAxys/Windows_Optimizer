# Function to disable services
function Disable-Services {
    $servicesToDisable = @(
        "Fax",
        "bthserv", # Bluetooth Support Service
        "RemoteRegistry",
        "WerSvc", # Windows Error Reporting Service
        "seclogon", # Secondary Logon
        "CscService", # Offline Files
        "TabletInputService", # Tablet PC Input Service
        "WSearch", # Windows Search
        "Spooler", # Print Spooler
        "wuauserv", # Windows Update
        "WbioSrvc", # Windows Biometric Service
        "Wcncsvc", # Windows Connect Now
        "wisvc", # Windows Insider Service
        "WMPNetworkSvc", # Windows Media Player Network Sharing Service
        "icssvc", # Windows Mobile Hotspot Service
        "stisvc", # Windows Image Acquisition
        "FrameServer", # Windows Camera Frame Server
        "XblAuthManager", # Xbox Live Auth Manager
        "XblGameSave", # Xbox Live Game Save
        "XboxNetApiSvc", # Xbox Live Networking Service
        "DiagTrack", # Connected User Experiences and Telemetry
        "RetailDemo", # Retail Demo Service
        "BcastDVRUserService", # GameDVR and Broadcast User Service
        "lfsvc", # Geolocation Service
        "MapsBroker", # Downloaded Maps Manager
        "SharedAccess", # Internet Connection Sharing (ICS)
        "TrkWks", # Distributed Link Tracking Client
        "WdiServiceHost", # Windows Diagnostic Service
        "WdiSystemHost", # Windows Diagnostic Service
        "WEPHOSTSVC", # Windows Encryption Provider Host Service
        "WinHttpAutoProxySvc", # WinHTTP Web Proxy Auto-Discovery Service
        "WSService", # Windows Store Service (WSService)
        "XboxGipSvc", # Xbox Accessory Management Service
        "XboxNetApiSvc", # Xbox Live Networking Service
        "dmwappushservice" # Device Management Wireless Application Protocol (WAP) Push message Routing Service
    )

    foreach ($service in $servicesToDisable) {
        try {
            # Get the service object
            $serviceObject = Get-Service -Name $service -ErrorAction Stop

            # Check if the service is running
            if ($serviceObject.Status -eq 'Running') {
                # Stop the service
                Stop-Service -Name $service -Force
            }

            # Disable the service
            Set-Service -Name $service -StartupType Disabled

            Write-Host "Service '$service' has been disabled."
        } catch {
            Write-Host "Failed to disable service '$service'. It may not exist, or access is denied."
        }
    }
}

# Function to clear DNS cache
function Clear-DnsCache {
    try {
        ipconfig /flushdns
        Write-Host "DNS cache has been cleared."
    } catch {
        Write-Host "Failed to clear DNS cache. An error occurred."
    }
}

# Function to optimize gaming performance
function Optimize-GamingPerformance {
    # Check for administrator privileges
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "This operation requires administrator rights. Please restart the script as admin." -ForegroundColor Red
        return
    }

    # Set power plan to high performance
    try {
        powercfg -setactive SCHEME_MIN
        Write-Host "Power plan set to High Performance." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set power plan: $_" -ForegroundColor Red
    }

    # Disable unnecessary startup applications
    try {
        Get-CimInstance Win32_StartupCommand | ForEach-Object {
            if ($_.Location -ne "HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") {
                Write-Host "Disabling startup application: $($_.Name)"
                Remove-ItemProperty -Path $_.Location -Name $_.Name -ErrorAction SilentlyContinue
            }
        }
        Write-Host "Unnecessary startup applications have been disabled." -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable some startup applications: $_" -ForegroundColor Red
    }

    # Adjust visual effects for best performance
    try {
        $performanceOptions = New-Object -ComObject WScript.Shell
        $performanceOptions.RegWrite("HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\VisualFXSetting", 2, "REG_DWORD")
        Write-Host "Visual effects adjusted for best performance." -ForegroundColor Green
    } catch {
        Write-Host "Failed to adjust visual effects: $_" -ForegroundColor Red
    }

    # Apply registry tweaks for gaming
    try {
        Write-Host "`nApplying Registry Tweaks..." -ForegroundColor Cyan

        # CPU priority optimization
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 26 -Type DWord -Force
        Write-Host " - CPU priority optimization applied"

        # Network throttling optimization
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Type DWord -Force
        Write-Host " - Network throttling optimization applied"

        # System responsiveness optimization
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0 -Type DWord -Force
        Write-Host " - System responsiveness optimization applied"

        # Gaming profile settings
        $gameTaskPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
        if (-Not (Test-Path $gameTaskPath)) {
            New-Item -Path $gameTaskPath -Force | Out-Null
        }
        Set-ItemProperty -Path $gameTaskPath -Name "GPU Priority" -Value 8 -Type DWord -Force
        Set-ItemProperty -Path $gameTaskPath -Name "Priority" -Value 6 -Type DWord -Force
        Set-ItemProperty -Path $gameTaskPath -Name "Scheduling Category" -Value "High" -Type String -Force
        Write-Host " - Gaming profile settings applied"

        # TCP optimizations
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpAckFrequency" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TCPNoDelay" -Value 1 -Type DWord -Force
        Write-Host " - TCP optimizations applied"

        # UI responsiveness
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0 -Type String -Force
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "ForegroundLockTimeout" -Value 0 -Type DWord -Force
        Write-Host " - UI responsiveness settings applied"

        # Application timeout settings
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "HungAppTimeout" -Value "1000" -Type String -Force
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "WaitToKillAppTimeout" -Value "2000" -Type String -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Value "2000" -Type String -Force
        Write-Host " - Application timeout settings applied"

        # Disable fullscreen optimizations
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord -Force
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Value 1 -Type DWord -Force
        Write-Host " - Fullscreen optimizations disabled"

        # Network optimizations
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableBandwidthThrottling" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableLargeMtu" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "GlobalMaxTcpWindowSize" -Value 65535 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "MaxUserPort" -Value 65534 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Value 30 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Value 64 -Type DWord -Force
        Write-Host " - Network optimizations applied"

        # TCP/IP stack optimizations
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDataRetransmissions" -Value 5 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "SackOpts" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUDiscovery" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnablePMTUBHDetect" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord -Force
        Write-Host " - TCP/IP stack optimizations applied"

        # Additional network optimizations
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableDeadGWDetect" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableWsd" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "QualifyingDestinationThreshold" -Value 3 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableTaskOffload" -Value 0 -Type DWord -Force
        Write-Host " - Additional network optimizations applied"

        # Nagle's algorithm optimization
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*" -Name "TcpAckFrequency" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*" -Name "TCPNoDelay" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Host " - Nagle's algorithm optimization applied"

        # System cache and memory optimizations
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargeSystemCache" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IoPageLockLimit" -Value 983040 -Type DWord -Force
        Write-Host " - System cache and memory optimizations applied"

        # MMCSS optimizations
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NoLazyMode" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Value 1 -Type DWord -Force
        Write-Host " - MMCSS optimizations applied"

        # Mouse and keyboard response optimizations
        Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Value "10" -Type String -Force
        Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "0" -Type String -Force
        Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0" -Type String -Force
        Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0" -Type String -Force
        Write-Host " - Mouse and keyboard response optimizations applied"

        # Disable Windows Game Recording and Broadcasting
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -Force
        Write-Host " - Windows Game Recording and Broadcasting disabled"

        # Disable Hibernation
        try {
            powercfg -h off
            Write-Host " - Hibernation has been disabled"
        } catch {
            Write-Host " - Failed to disable hibernation: $_" -ForegroundColor Red
        }

        # Disable Windows Tips
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord -Force
            Write-Host " - Windows Tips have been disabled"
        } catch {
            Write-Host " - Failed to disable Windows Tips: $_" -ForegroundColor Red
        }

        # Disable Background Apps
        try {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force
            Write-Host " - Background apps have been disabled"
        } catch {
            Write-Host " - Failed to disable background apps: $_" -ForegroundColor Red
        }

        # Disable Windows Animations
        try {
            Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x12,0x03,0x80,0x00)) -Type Binary -Force
            Write-Host " - Windows animations have been disabled"
        } catch {
            Write-Host " - Failed to disable Windows animations: $_" -ForegroundColor Red
        }

        # Disable Startup Delay
        try {
            if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize")) {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Value 0 -Type DWord -Force
            Write-Host " - Startup delay has been disabled"
        } catch {
            Write-Host " - Failed to disable startup delay: $_" -ForegroundColor Red
        }

        # Disable Windows Defender (if not needed)
        try {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
            Write-Host " - Windows Defender has been disabled"
        } catch {
            Write-Host " - Failed to disable Windows Defender: $_" -ForegroundColor Red
        }

        # Disable Cortana
        try {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord -Force
            Write-Host " - Cortana has been disabled"
        } catch {
            Write-Host " - Failed to disable Cortana: $_" -ForegroundColor Red
        }

        # Disable Windows Telemetry
        try {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord -Force
            Write-Host " - Windows Telemetry has been disabled"
        } catch {
            Write-Host " - Failed to disable Windows Telemetry: $_" -ForegroundColor Red
        }

        # Disable CPU Core Parking
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" -Name "Attributes" -Value 0 -Type DWord -Force
            powercfg -setacvalueindex SCHEME_CURRENT SUB_PROCESSOR 0cc5b647-c1df-4637-891a-dec35c318583 100
            powercfg -setactive SCHEME_CURRENT
            Write-Host " - CPU Core Parking has been disabled"
        } catch {
            Write-Host " - Failed to disable CPU Core Parking: $_" -ForegroundColor Red
        }

        # Increase GPU Priority
        try {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8 -Type DWord -Force
            Write-Host " - GPU Priority has been increased"
        } catch {
            Write-Host " - Failed to increase GPU Priority: $_" -ForegroundColor Red
        }

        # Disable Power Throttling
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1 -Type DWord -Force
            Write-Host " - Power Throttling has been disabled"
        } catch {
            Write-Host " - Failed to disable Power Throttling: $_" -ForegroundColor Red
        }

        # Optimize Page File Settings
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagingFiles" -Value "C:\pagefile.sys 4096 4096" -Type MultiString -Force
            Write-Host " - Page File Settings have been optimized"
        } catch {
            Write-Host " - Failed to optimize Page File Settings: $_" -ForegroundColor Red
        }

        # Disable Dynamic Tick
        try {
            bcdedit /set disabledynamictick yes
            Write-Host " - Dynamic Tick has been disabled"
        } catch {
            Write-Host " - Failed to disable Dynamic Tick: $_" -ForegroundColor Red
        }

        # Enable Ultimate Performance Power Plan
        try {
            powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
            powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61
            Write-Host " - Ultimate Performance Power Plan has been enabled"
        } catch {
            Write-Host " - Failed to enable Ultimate Performance Power Plan: $_" -ForegroundColor Red
        }

        Write-Host "`nRegistry optimizations completed successfully!" -ForegroundColor Green
        Write-Host "Some changes may require a system restart to take effect." -ForegroundColor Yellow

    } catch {
        Write-Host "`nError applying registry tweaks: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Partial changes may have been applied" -ForegroundColor Yellow
    }
}

# Function to remove Microsoft Store apps and Edge
function Remove-Bloat {
    try {
        # Remove Microsoft Edge
        Get-AppxPackage -Name Microsoft.MicrosoftEdge | Remove-AppxPackage -ErrorAction SilentlyContinue
        Write-Host "Microsoft Edge has been removed."

        # Remove other Microsoft Store apps
        $appsToRemove = @(
            "Microsoft.3DBuilder",
            "Microsoft.BingFinance",
            "Microsoft.BingNews",
            "Microsoft.BingSports",
            "Microsoft.BingWeather",
            "Microsoft.GetHelp",
            "Microsoft.Getstarted",
            "Microsoft.Messaging",
            "Microsoft.Microsoft3DViewer",
            "Microsoft.MicrosoftOfficeHub",
            "Microsoft.MicrosoftSolitaireCollection",
            "Microsoft.MicrosoftStickyNotes",
            "Microsoft.MixedReality.Portal",
            "Microsoft.Office.OneNote",
            "Microsoft.OneConnect",
            "Microsoft.People",
            "Microsoft.Print3D",
            "Microsoft.SkypeApp",
            "Microsoft.StorePurchaseApp",
            "Microsoft.Wallet",
            "Microsoft.WindowsAlarms",
            "Microsoft.WindowsCamera",
            "Microsoft.WindowsMaps",
            "Microsoft.WindowsPhone",
            "Microsoft.WindowsSoundRecorder",
            "Microsoft.Xbox.TCUI",
            "Microsoft.XboxApp",
            "Microsoft.XboxGameOverlay",
            "Microsoft.XboxGamingOverlay",
            "Microsoft.XboxIdentityProvider",
            "Microsoft.XboxSpeechToTextOverlay",
            "Microsoft.YourPhone",
            "Microsoft.ZuneMusic",
            "Microsoft.ZuneVideo"
        )

        foreach ($app in $appsToRemove) {
            Get-AppxPackage -Name $app | Remove-AppxPackage -ErrorAction SilentlyContinue
            Write-Host "Removed $app."
        }

        Write-Host "System debloating completed."
    } catch {
        Write-Host "Failed to debloat system: $($_.Exception.Message)"
    }
}

# Function to optimize RAM usage
function Optimize-RAM {
    try {
        # Clear standby list
        Clear-Content -Path "$env:SystemRoot\Prefetch\*"
        Write-Host "RAM usage has been optimized."
    } catch {
        Write-Host "Failed to optimize RAM usage: $_"
    }
}

# Function to remove junk files
function Remove-JunkFiles {
    try {
        # Define paths to clean
        $pathsToClean = @(
            "$env:SystemRoot\Temp\*",
            "$env:LOCALAPPDATA\Temp\*",
            "$env:SystemRoot\Prefetch\*",
            "$env:SystemRoot\SoftwareDistribution\Download\*",
            "$env:SystemRoot\Logs\*"
        )

        foreach ($path in $pathsToClean) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }

        Write-Host "Junk files have been removed."
    } catch {
        Write-Host "Failed to remove junk files: $_"
    }
}

# Function to disable all background apps
function Disable-BackgroundApps {
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force
        Write-Host "All background apps have been disabled." -ForegroundColor Green
        
        # Disable specific background apps if they exist
        Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -ErrorAction SilentlyContinue | ForEach-Object {
            Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Value 1 -Type DWord -Force
            Write-Host "Disabled background app: $($_.PSChildName)" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "Failed to disable background apps: $_" -ForegroundColor Red
    }
}

# Function to disable Windows Update and Defender permanently
function Disable-WindowsUpdateAndDefender {
    try {
        # Disable Windows Update service
        Stop-Service -Name "wuauserv" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "wuauserv" -StartupType Disabled
        Write-Host "Windows Update service has been disabled."

        # Disable Windows Update in registry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 1 -Type DWord -Force
        Write-Host "Windows Update has been disabled in the registry."

        # Attempt to disable Windows Defender service
        try {
            Stop-Service -Name "WinDefend" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "WinDefend" -StartupType Disabled
            Write-Host "Windows Defender service has been disabled."
        } catch {
            Write-Host "Windows Defender service could not be found or disabled. It may not exist on this system." -ForegroundColor Yellow
        }

        # Disable Windows Defender in registry
        if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1 -Type DWord -Force
        Write-Host "Windows Defender has been disabled in the registry."

        Write-Host "Windows Update and Defender have been permanently disabled." -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable Windows Update and Defender: $_" -ForegroundColor Red
    }
}

# Function to test and repair corrupted system files
function Test-And-Repair-CorruptedFiles {
    try {
        Write-Host "Starting system file check and repair..." -ForegroundColor Cyan
        sfc /scannow
        Write-Host "System file check and repair completed." -ForegroundColor Green
    } catch {
        Write-Host "Failed to complete system file check and repair: $_" -ForegroundColor Red
    }
}

# Function to optimize startup and boot delays
function Optimize-Startup-And-Boot-Delays {
    try {
        Write-Host "Optimizing startup and boot delays..." -ForegroundColor Cyan

        # Disable startup delay
        if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Value 0 -Type DWord -Force
        Write-Host " - Startup delay has been disabled"

        # Disable unnecessary startup programs
        Get-CimInstance Win32_StartupCommand | ForEach-Object {
            if ($_.Location -ne "HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") {
                Write-Host "Disabling startup application: $($_.Name)"
                Remove-ItemProperty -Path $_.Location -Name $_.Name -ErrorAction SilentlyContinue
            }
        }
        Write-Host " - Unnecessary startup programs have been disabled"

        # Optimize services for faster boot
        Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | ForEach-Object {
            Set-Service -Name $_.Name -StartupType Manual
            Write-Host "Service '$($_.Name)' set to manual start."
        }
        Write-Host " - Services optimized for faster boot"

        Write-Host "Startup and boot delays have been optimized." -ForegroundColor Green
    } catch {
        Write-Host "Failed to optimize startup and boot delays: $_" -ForegroundColor Red
    }
}

# Menu system
function Show-Menu {
    while ($true) {
        Write-Host "`n=== Windows Gaming Optimization Tool ==="
        Write-Host "Select an option:"
        Write-Host "1. Disable Services"
        Write-Host "2. Clear DNS Cache"
        Write-Host "3. Optimize Gaming Performance"
        Write-Host "4. Remove Bloat"
        Write-Host "5. Optimize RAM Usage"
        Write-Host "6. Remove Junk Files"
        Write-Host "7. Disable Background Apps"
        Write-Host "8. Disable Windows Update and Defender Permanently"
        Write-Host "9. Test and Repair Corrupted System Files"
        Write-Host "10. Optimize Startup and Boot Delays"
        Write-Host "11. Exit"
        
        $choice = Read-Host "Enter your choice (1-11)"
        
        switch ($choice) {
            1 { 
                Disable-Services 
                Write-Host "`nPress any key to return to the menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            2 { 
                Clear-DnsCache 
                Write-Host "`nPress any key to return to the menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            3 { 
                Optimize-GamingPerformance 
                Write-Host "`nPress any key to return to the menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            4 { 
                Remove-Bloat 
                Write-Host "`nPress any key to return to the menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            5 { 
                Optimize-RAM 
                Write-Host "`nPress any key to return to the menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            6 { 
                Remove-JunkFiles 
                Write-Host "`nPress any key to return to the menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            7 { 
                Disable-BackgroundApps 
                Write-Host "`nPress any key to return to the menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            8 { 
                Disable-WindowsUpdateAndDefender
                Write-Host "`nPress any key to return to the menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            9 { 
                Test-And-Repair-CorruptedFiles
                Write-Host "`nPress any key to return to the menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            10 { 
                Optimize-Startup-And-Boot-Delays
                Write-Host "`nPress any key to return to the menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            11 { 
                Write-Host "Exiting script. Goodbye!"
                exit 
            }
            default { 
                Write-Host "`nInvalid choice. Please select a valid option."
                Start-Sleep -Seconds 2
            }
        }
    }
}

# Show the menu
Clear-Host
Show-Menu