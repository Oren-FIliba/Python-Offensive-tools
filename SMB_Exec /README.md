# SMB_Exec

This PowerShell script provides functions to upload and execute files on remote hosts using various techniques like SMB, WMI, WinRM, and PsExec. It facilitates remote administration and automation tasks in Windows environments.

## Usage

1. **Upload a File to Remote Host**

    ```powershell
    Upload-FileToRemote -localFilePath "local\path\to\file" -remoteFilePath "remote\path\to\file" -remoteHost "hostname" -shareName "sharename"
    ```

    - `localFilePath`: Path to the file on the local machine.
    - `remoteFilePath`: Path where the file will be copied on the remote machine.
    - `remoteHost`: Hostname or IP address of the remote machine.
    - `shareName`: Name of the share on the remote machine.

2. **Execute a File on Remote Host using WMI**

    ```powershell
    Execute-RemoteFile_Wmi -remoteFilePath "remote\path\to\file" -remoteHost "hostname" -shareName "sharename"
    ```

    - `remoteFilePath`: Path to the file on the remote machine.
    - `remoteHost`: Hostname or IP address of the remote machine.
    - `shareName`: Name of the share on the remote machine.

3. **Execute a File on Remote Host using WinRM**

    ```powershell
    Execute-RemoteFile_WinRm -remoteFilePath "remote\path\to\file" -remoteHost "hostname" -shareName "sharename"
    ```

    - `remoteFilePath`: Path to the file on the remote machine.
    - `remoteHost`: Hostname or IP address of the remote machine.
    - `shareName`: Name of the share on the remote machine.

4. **Execute a File on Remote Host using PsExec**

    ```powershell
    Execute-RemoteFile_PsExec -remoteFilePath "remote\path\to\file" -remoteHost "hostname" -shareName "sharename"
    ```

    - `remoteFilePath`: Path to the file on the remote machine.
    - `remoteHost`: Hostname or IP address of the remote machine.
    - `shareName`: Name of the share on the remote machine.

## Note

- Ensure that appropriate permissions are set on the remote machine and shares for successful execution.
- Specify the path to `PsExec.exe` for `Execute-RemoteFile_PsExec` function to work properly.
- Results of execution are logged in CSV files (`UploadResults.csv` for file upload and `ExecutionResults.csv` for execution).
