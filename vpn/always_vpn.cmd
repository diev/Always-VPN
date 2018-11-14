@echo off
set version=1.0.3
title Always VPN v%version%
color 1B

set vpn=tunnel
set ip=127.0.0.1

for /f "tokens=5,*" %%i in ('netsh int ipv4 show route ^| find "0.0.0.0/0"') do (
  if /i "%%j" neq "%vpn%" (
    netsh int ipv4 del route 0.0.0.0/0 int=%%i
    netsh int ipv4 del dest int=%%i
    netsh int ipv4 add route %ip%/32 int=%%i %%j
))

for /f "tokens=4,* skip=3" %%i in ('netsh int ipv4 show int') do if /i "%%j" equ "%vpn%" goto :eof

rasdial "%vpn%"
