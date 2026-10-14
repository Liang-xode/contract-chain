@echo off
rem 国密区块链电子文件加密存证系统 —— PyQt5 图形界面启动脚本
chcp 65001 >nul
cd /d "%~dp0"

set "PY=D:\Anaconda\envs\contract-chain\python.exe"
set "PYW=D:\Anaconda\envs\contract-chain\pythonw.exe"

if not exist "%PY%" (
    echo [X] 未找到 conda 环境 contract-chain，请先执行：
    echo     conda create -n contract-chain python=3.11 -y
    echo     conda activate contract-chain ^&^& pip install -r requirements.txt
    pause
    exit /b 1
)

"%PY%" -c "import PyQt5" 2>nul
if errorlevel 1 (
    echo [!] 检测到缺少 PyQt5，正在自动安装...
    "%PY%" -m pip install PyQt5
)

echo 正在启动图形界面（无控制台窗口）...
start "" "%PYW%" -m app.gui
