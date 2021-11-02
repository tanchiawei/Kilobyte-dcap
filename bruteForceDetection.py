# This is a sample Python script.
# !/bin/python3
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import re
import sys
import argparse
import utmp


def writeLog():
    # parser.add_argument('files', metavar='FILE', help='Files (utmp/wtmp/btmp) to read from', nargs='+')
    # args = parser.parse_args()
    all_contents = ""
    logPath = ['/var/log/wtmp', '/var/log/btmp', '/var/run/utmp']
    logName = ['wtmp', 'btmp', 'utmp']

    # for fn in args.files:
    noOfFiles = 0
    for fn in logPath:

        print(fn)
        with open(fn, 'rb') as fd:
            buf = fd.read()
            for entry in utmp.read(buf):
                all_contents += str(entry.time) + str(entry.type) + str(entry)
                all_contents += "\n"  # add line to all_contents
                # print(all_contents)
            fd.close()
        result = open(logName[noOfFiles] + ".txt", "w")  # create file allLogs.txt
        result.write(all_contents)
        result.close()
        noOfFiles += 1


def bruteForceDetection():
    writeLog()
    header = "Date  Time PID  User  IP"
    logs = open("btmp.txt")
    p1 = re.compile(
        "([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}).*type=(\d+), pid=(\d+), line='(.*)', id='.*', user='(.*)', host='(.*)',")
    count = {}
    usernames = []
    for line in logs:  # iterate over each line
        match = p1.match(line)  # match line with regex
        if match is not None:  # if there is a match do following
            match_index = None  # initialize match index. Can be of group3 or group4 depending on match
            if len(usernames) == 0:  # if usernames is empty, directly add this user and ip
                if match.group(5) is not None:
                    match_index = 5
                elif match.group(6) is not None:
                    match_index = 6

                usernames.append(match.group(match_index))
                count[match.group(match_index)] = {}
                count[match.group(match_index)]["count"] = 1
                count[match.group(match_index)]["Type"] = []
                count[match.group(match_index)]["Type"].append(match.group(2))
                count[match.group(match_index)]["PID"] = []
                count[match.group(match_index)]["PID"].append(match.group(3))
                count[match.group(match_index)]["time"] = []
                count[match.group(match_index)]["time"].append(match.group(1))
                count[match.group(match_index)]["User"] = []
                count[match.group(match_index)]["User"].append(match.group(5))
                count[match.group(match_index)]["IP"] = []
                count[match.group(match_index)]["IP"].append(match.group(6))
            else:  # if month is not empty check if username already exists
                exists = False
                if match.group(5) is not None:
                    match_index = 5
                elif match.group(6) is not None:
                    match_index = 6
                for name in usernames:  # Loop through the variable month
                    if name == match.group(match_index):  # if month already exists, increase count and add
                        exists = True
                        count[match.group(match_index)]["count"] += 1
                        ip_exists = False
                        # Append the necessary info into the same month
                        count[match.group(match_index)]["Type"].append(match.group(2))
                        count[match.group(match_index)]["PID"].append(match.group(3))
                        count[match.group(match_index)]["time"].append(match.group(1))
                        count[match.group(match_index)]["User"].append(match.group(5))
                        count[match.group(match_index)]["IP"].append(match.group(6))
                        break
                if not exists:  # if user does not exists yet, add username and ip
                    usernames.append(match.group(match_index))
                    count[match.group(match_index)] = {}
                    count[match.group(match_index)]["count"] = 1
                    count[match.group(match_index)]["Type"] = []
                    count[match.group(match_index)]["Type"].append(match.group(2))
                    count[match.group(match_index)]["PID"] = []
                    count[match.group(match_index)]["PID"].append(match.group(3))
                    count[match.group(match_index)]["time"] = []
                    count[match.group(match_index)]["time"].append(match.group(1))
                    count[match.group(match_index)]["User"] = []
                    count[match.group(match_index)]["User"].append(match.group(5))
                    count[match.group(match_index)]["IP"] = []
                    count[match.group(match_index)]["IP"].append(match.group(6))
    returnValue = [usernames,count]
    return returnValue
    #output=''
    #output =[]
    #for eachUser in usernames:
        #print(eachUser + ": " + " Number of Failed Login Attempts: " )
    #for key in count:
        #print("User " + count[key]["User"][0] + " Number of failed Login Attempts: " + str(count[key]["count"]))
        #if count[key]["count"] > 5:
            #print("Suspected Brute Force")
        #for i in range(len(count[key]["User"])):
            #if i == len(count[key]["User"])-1:
                #print("Login attempt at " + count[key]["time"][i] + " IP: " +  count[key]["IP"][i])
            #else:
                #print("Login attempt at " + count[key]["time"][i] + " IP: " + count[key]["IP"][i])

        #print("\n")

