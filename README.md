# Welcome to PC Check Script for Red Angels eSport!

This is a script repos for Red Angels eSports when cheating is suspected in a tournament. It includes one with a Discord webhook and one without.

# Files

Version 1: [PcCheck1.ps1](https://raw.githubusercontent.com/xMaNuron/RA_PC-Check/refs/heads/main/pcCheck1.ps1), the version with the Discord webhook

Version 2: [PcCheck2.ps1](https://raw.githubusercontent.com/xMaNuron/RA_PC-Check/refs/heads/main/pcCheck2.ps1), the version without the Discord webhook


## Execution 

Version 1: Open Powershell and for this command:

    iwr -useb https://raw.githubusercontent.com/xMaNuron/RA_PC-Check/refs/heads/main/pcCheck1.ps1 | iex

With this version, a file is sent to Discord as a webhook, but also a copy of the file is created on the desktop. If there isn't one there, simply paste it with Ctrl + V.

Version 2: Open Powershell as administrator and for this command:

    iwr -useb https://raw.githubusercontent.com/xMaNuron/RA_PC-Check/refs/heads/main/pcCheck2.ps1 | iex

With this script, everything is in the console, so unfortunately, there is no saved file.

## Credits

These two files are from [dyvertigo](https://github.com/dyvertigo/pcCheck) and [zeywya](https://github.com/zeywya/PcCheckerr) and got change from me to fit our team for tournaments. 

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/xMaNuron/RA_PC-Check/blob/main/LICENSE) file for details.

