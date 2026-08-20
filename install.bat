@echo off
rem game-modifier 一键安装（PowerShell 脚本包装器）
rem 用法: install.bat [-Mode minimal|mcp|full|dev] [-SkipVenv] [-Force] [-PythonPath <path>] [-DryRun]
powershell.exe -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
