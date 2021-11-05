# ICT2101-2201-Team-Project

Project Description

**Must have:**

- [1] Examine BTMP/WTMP/UTMP files
- [2] Examine .zsh_history files
- [3] Examine .auth_log files


##### Should have:

- [1] Analze files and flag possible brute force attack
- [2] Analze files and flag possible suspicious user behaviour
- [3] Analze files and flag possible rogue entry points


## Project Background

With a single precise command, the investigator in a hurry can examine multiple large logs for several common malicious attack patterns, all at once. To enable this, we will be working on 3 scripts written in python that will allow for command line arguments and file paths to be parsed in. Depending on the complexity of reading and analyzing the log file dumps, we might have to possibly user external library to read encrypted log files. To flag suspicious user behavour we will log at commands executed like whoami,id,pwd across all users in a single system.

With the 3 python scripts delivered we will intergrate them to our tool - dcap.py and format the output for the final deliverable, streamline and standardize the arguments used to run the tool.


## Project Setup


## How-to run


## Dependencies

With dcap the goal is to analyze large log files for multiple attack patterns at once, hence, there will be no need to run,traverse or analyze the logs individually and write them to a text file. Since this process is heavily streamlined for forensics investigators we have also went a step ahead to make sure there will be no additional dependencies needed to run dcap making it investigator-friendly.




