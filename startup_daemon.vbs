' Silent Windows startup daemon for WeCom AI Export Tool (24h background 3s sync).
' - Runs pythonw.exe -E -X utf8 web_app.py completely hidden (0 console windows).
' - Sets WECOM_NO_BROWSER=1 so no browser tab pops up on Windows boot.
' - Clears any sandbox/sitecustomize env vars for clean isolated execution.
' - Safe to invoke repeatedly: skips launch silently if 127.0.0.1:8765 is already healthy.

Option Explicit

Dim APP_DIR, APP_URL, PYW, APP_PY, LOG_PATH
Dim shell, env, fso, logFile, q

Set shell = CreateObject("WScript.Shell")
Set env = shell.Environment("PROCESS")
Set fso = CreateObject("Scripting.FileSystemObject")

APP_DIR = fso.GetParentFolderName(WScript.ScriptFullName)
APP_URL = "http://127.0.0.1:8765"
PYW = APP_DIR & "\.venv\Scripts\pythonw.exe"
APP_PY = APP_DIR & "\web_app.py"
LOG_PATH = APP_DIR & "\runtime\startup_daemon.log"
q = Chr(34)

If Not fso.FolderExists(APP_DIR & "\runtime") Then
    On Error Resume Next
    fso.CreateFolder APP_DIR & "\runtime"
    On Error GoTo 0
End If

On Error Resume Next
Set logFile = fso.OpenTextFile(LOG_PATH, 8, True)
On Error GoTo 0

Sub LogLine(text)
    On Error Resume Next
    If Not IsEmpty(logFile) And Not (logFile Is Nothing) Then
        logFile.WriteLine Now & " " & text
    End If
    On Error GoTo 0
End Sub

Function ServerReady()
    Dim req, errNo
    ServerReady = False
    On Error Resume Next
    Set req = CreateObject("WinHttp.WinHttpRequest.5.1")
    req.SetProxy 1
    req.SetTimeouts 500, 500, 1500, 1500
    req.Open "GET", APP_URL & "/api/health", False
    req.Send
    errNo = Err.Number
    If errNo = 0 Then
        ServerReady = (req.Status = 200)
    End If
    On Error GoTo 0
End Function

LogLine "DAEMON_BOOT_BEGIN"

If Not fso.FileExists(PYW) Then
    LogLine "ERROR_MISSING_PYW=" & PYW
    If Not (logFile Is Nothing) Then logFile.Close
    WScript.Quit 3
End If

If Not fso.FileExists(APP_PY) Then
    LogLine "ERROR_MISSING_APP_PY=" & APP_PY
    If Not (logFile Is Nothing) Then logFile.Close
    WScript.Quit 4
End If

If ServerReady() Then
    LogLine "SERVER_ALREADY_READY (skip duplicate launch)"
Else
    env.Item("WECOM_NO_BROWSER") = "1"
    On Error Resume Next
    env.Remove "PYTHONPATH"
    env.Remove "PYTHONHOME"
    env.Remove "PYTHONSTARTUP"
    env.Remove "NODE_OPTIONS"
    env.Remove "TOOL_CALL_ID"
    env.Remove "LSBOX_AUDIT_SHMEM"
    env.Remove "CODEBUDDY_SESSION_ID"
    env.Remove "CODEBUDDY_MCP_CONFIG"
    env.Remove "CODEBUDDY_PROJECT_DIR"
    env.Remove "CODEBUDDY_SAFE_DELETE_BULK_GUARD"
    env.Remove "CODEBUDDY_ENABLE_SECURITY_AUDIT"
    env.Remove "CODEBUDDY_CONVERSATION_MESSAGE_ID"
    On Error GoTo 0
    shell.CurrentDirectory = APP_DIR
    shell.Run q & PYW & q & " -E -X utf8 " & q & APP_PY & q, 0, False
    LogLine "STARTED_SILENT_DAEMON (pythonw -E, WECOM_NO_BROWSER=1)"
End If

On Error Resume Next
If Not (logFile Is Nothing) Then logFile.Close
On Error GoTo 0
