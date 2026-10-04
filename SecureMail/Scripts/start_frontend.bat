@echo off
title SecureMail Frontend Server
cd ..\Frontend
echo Starting SecureMail Frontend Server on http://localhost:3000 ...
python -m http.server 3000
pause
