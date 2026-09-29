@echo off
title ProxyTUI
cd /d "%~dp0"
python proxytui.py %*
if errorlevel 1 pause
