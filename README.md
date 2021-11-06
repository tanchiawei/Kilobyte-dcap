# ICT2202-Team-Project

## Project Background

Forensic investigators repeatedly find themselves looking for common attack patterns in logs that can become very large. dcap is a tool that will help to automate the gathering, parsing and analysing of these logs. It looks for 3 common markers of attack in an Ubuntu machine:

1. High numbers of failed logins (evidence of a brute force attack)
2. Commands that are not typically executed during a user's day-to-day usage, such as whoami, id, pwd, sudo, uname (evidence of a hijacked account)
3. Users who add users with useradd or change the bash shell of an account (evidence of privilege escalation)

With a single precise command, the investigator in a hurry can examine multiple large logs for several common malicious attack patterns, all at once, with dcap.

## Project Setup

NOTE: This tool is designed for Ubuntu systems.

To install python3 and utmp on the machine run the following commands:

sudo apt-get install python3\
sudo apt-get install python3-pip\
sudo pip3 install utmp

Download dcap and unzip to any folder. Alternatively, pull dcap from GitHub with:
>git repo clone https://github.com/tanchiawei/Kilobyte-dcap

Open a terminal in that folder and run the command as described in the next section.

## How-to run

usage: dcap.py [-h] [-b] [-a] [-e] outputlocation

Positional arguments:
>outputlocation\
>Define destination and name of output file

Optional arguments:
>-h, --help\
>Show this help message and exit\
>-b, --brute\
>Brute Force Detection - examines btmp log and outputs result to console and destination file\
>-a, --account\
>Account Hijack Detection - accesses .bash_history and outputs result to console and destination file\
>-e, --entrypoint\
>Entrypoint Detection - accesses auth.log and outputs result to console and destination file

Example usage:\
sudo python3 ./dcap.py -bae output.txt

NOTE: dcap must be run with sudo in order to have permissions to access files in /var/log!

## Dependencies

dcap requires Python 3 to run, and the utmp package must be instslideralled in order for dcap to read the btmp and wtmp logs.

Finally, this tool is designed for the Ubuntu system.
