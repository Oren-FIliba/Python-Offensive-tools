function Upload-FileToRemote {
    param(
        [string]$localFilePath,
        [string]$remoteFilePath,
        [string]$remoteHost,
        [string]$shareName
    )

    # Initialize variables to store result information
    $result = $null
    $ip = $null
    $share = "\\$remoteHost\$shareName"
    $fileName = (Split-Path $localFilePath -Leaf)

    # Copy the file to the remote host's share
    try {
        $output = Copy-Item -Path $localFilePath -Destination "$share\$remoteFilePath" -Force -ErrorAction Stop
        $result = "completed"
    } catch {
        $result = "not completed"
    }

    # Get the IP address of the remote host
    try {
        $ip = (Test-Connection -ComputerName $remoteHost -Count 1).IPAddress
    } catch {
        $ip = "Unknown"
    }

    # Output result to CSV
    [PSCustomObject]@{
        Technique = "SMB_UploadFile"
        IP = $remoteHost
        Share = $share
        FileName = $fileName
        Status = $result
    } | Export-Csv -Path "UploadResults.csv" -Append -NoTypeInformation
}

# Function to execute a file on the remote host using WMI
function Execute-RemoteFile_Wmi {
    param(
        [string]$remoteFilePath,
        [string]$remoteHost,
        [string]$shareName
    )

    # Initialize variables to store result information
    $result = $null
    $ip = $null
    $share = "\\$remoteHost\$shareName"
    $fileName = (Split-Path $remoteFilePath -Leaf)

    # Execute the file on the remote host using WMI
    try {
        $process = Get-WmiObject -Class Win32_Process -ComputerName $remoteHost -List -ErrorAction Stop
        $process.Create("cmd.exe /c $remoteFilePath")
        $result = "completed"
    } catch {
        $result = "not completed"
    }

    # Get the IP address of the remote host
    try {
        $ip = (Test-Connection -ComputerName $remoteHost -Count 1).IPAddress
    } catch {
        $ip = "Unknown"
    }

    # Output result to CSV
    [PSCustomObject]@{
        Technique = "WMI_Exec"
        IP = $remoteHost
        Share = $share
        FileName = $fileName
        Status = $result
    } | Export-Csv -Path "ExecutionResults.csv" -Append -NoTypeInformation
}

function Execute-RemoteFile_WinRm {
    param(
        [string]$remoteFilePath,
        [string]$remoteHost,
        [string]$shareName
    )

    # Initialize variables to store result information
    $result = $null
    $ip = $null
    $share = "\\$remoteHost\$shareName"
    $fileName = (Split-Path $remoteFilePath -Leaf)

    # Execute the file on the remote host with WinRm
    try {
        $nslookupOutput = nslookup $remoteHost
        $nameLine = ($nslookupOutput | Where-Object { $_ -like "Name:*" }) -split '\s+'
        $remoteHost = $nameLine[1]
    
        Invoke-Command -ComputerName $remoteHost -ScriptBlock {
            & "$using:remoteFilePath"
        }
        $result = "completed"
    } catch {
        $result = "not completed"
    }

    # Get the IP address of the remote host
    try {
        $ip = (Test-Connection -ComputerName $remoteHost -Count 1).IPAddress
    } catch {
        $ip = "Unknown"
    }

    # Output result to CSV
    [PSCustomObject]@{
        Technique = "WinRM_Exec"
        IP = $remoteHost
        Share = $share
        FileName = $fileName
        Status = $result
    } | Export-Csv -Path "ExecutionResults.csv" -Append -NoTypeInformation
}

function Execute-RemoteFile_PsExec {
    param(
        [string]$remoteFilePath,
        [string]$remoteHost,
        [string]$shareName
    )

    # Initialize variables to store result information
    $result = $null
    $ip = $null
    $share = "\\$remoteHost\$shareName"
    $fileName = (Split-Path $remoteFilePath -Leaf)

    # Run PsExec to execute the file on the remote host
    try {
        $psexecPath = "C:\Dev\PsExec.exe"  # Specify the path to PsExec.exe
        $psexecCommand = "$psexecPath \\$remoteHost -accepteula -s cmd.exe /c $remoteFilePath"

        Invoke-Expression $psexecCommand
        $result = "completed"
    } catch {
        $result = "not completed"
    }

    # Output result to CSV
    [PSCustomObject]@{
        Technique = "PsExec"
        IP = $remoteHost
        Share = $share
        FileName = $fileName
        Status = $result
    } | Export-Csv -Path "ExecutionResults.csv" -Append -NoTypeInformation
}
