@echo off
rem 干净环境启动：先剔除 WorkBuddy 沙盒注入（PYTHONPATH -> sitecustomize.py），
rem 再委托 launch_web.vbs 用 pythonw.exe -E 隐藏启动，全程 0 黑框。
set "ROOT=D:\wecom-agent"
set "PYTHONPATH="
set "PYTHONHOME="
set "PYTHONSTARTUP="
set "NODE_OPTIONS="
set "TOOL_CALL_ID="
set "LSBOX_AUDIT_SHMEM="
set "CODEBUDDY_SESSION_ID="
set "CODEBUDDY_MCP_CONFIG="
set "CODEBUDDY_PROJECT_DIR="
set "CODEBUDDY_SAFE_DELETE_BULK_GUARD="
set "CODEBUDDY_ENABLE_SECURITY_AUDIT="
set "CODEBUDDY_CONVERSATION_MESSAGE_ID="
if not exist "%ROOT%\runtime" mkdir "%ROOT%\runtime" >nul 2>&1
if not exist "%ROOT%\launch_web.vbs" goto :missing
if not exist "%ROOT%\web_app.py" goto :missing
if not exist "%ROOT%\web_ui.html" goto :missing
start "" wscript.exe //B "%ROOT%\launch_web.vbs"
exit /b 0

:missing
echo [ERROR] Required file not found under %ROOT%
exit /b 1
