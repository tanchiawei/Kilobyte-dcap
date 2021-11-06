# This is a sample Python script.
# !/bin/python3
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import datetime
import re
import subprocess
import sys

import utmp as utmp


def read_logs(path, number_files):
    all_contents = ""  # string that will contain all logs
    for files in range(0, number_files):  # iterate over all files
        try:
            if files == number_files:
                break
            if files == 0:
                fn = path
            else:
                fn = path + "." + str(files)
            fl = open(fn, "r")
            for line in fl:  # iterate over all lines in a single file
                all_contents += line  # add line to all_contents
            fl.close()

        except:
            print("Log read complete")
    result = open("allLogs.txt", "w")  # create file allLogs.txt
    result.write(all_contents)
    result.close()


def rougeEntrypointDetection():
    lastLogin = subprocess.run(['last'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    lastLogin2 = subprocess.run(['last', '-f', '/var/log/wtmp.1'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    result = open("last.txt", "w")  # create file last.txt
    result.write(lastLogin)
    result.write(lastLogin2)
    # uses linux command and output to lastb.txt (This is for failed login)
    lastLogin = subprocess.run(['lastb'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    lastLogin2 = subprocess.run(['lastb', '-f', '/var/log/wtmp.1'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    result = open("lastb.txt", "w")  # create file lastb.txt
    result.write(lastLogin)
    result.write(lastLogin2)
    result.close()

    path = '/var/log/auth.log'
    n_files = 2
    read_logs(path, int(n_files))
    logs = open("allLogs.txt")

    month = []
    p1 = re.compile(
        ".*([a-zA-Z]{3})[ ]{1,}([0-9]{1,}) (2[0-3]|[0-3]?[0-9]:[0-5]?[0-9]:[0-5]?[0-9]) .* (useradd).*: new user: name=(\w+), .*")
    p2 = re.compile(
        ".*([a-zA-Z]{3})[ ]{1,}([0-9]{1,}) (2[0-3]|[0-3]?[0-9]:[0-5]?[0-9]:[0-5]?[0-9]) .* (chsh).*: (\w+) (\w+) '(\w+)' shell to")

    count = {}
    for line in logs:  # iterate over each line
        match = p1.match(line)  # match line with regex
        match2 = p2.match(line)
        if match is not None:  # if there is a match do following
            match_index = None  # initialize match index. Can be of group3 or group4 depending on match
            if len(month) == 0:  # if month is empty, directly add this user and ip
                if match.group(1) is not None:
                    match_index = 1
                elif match.group(2) is not None:
                    match_index = 2
                elif match.group(3) is not None:
                    match_index = 3
                elif match.group(4) is not None:
                    match_index = 4
                elif match.group(5) is not None:
                    match_index = 5
                month.append(match.group(match_index))
                # Creates an array inside the count array
                count[match.group(match_index)] = {}
                # Indicate the first line / count
                count[match.group(match_index)]["count"] = 1
                # Creates an array of month key
                count[match.group(match_index)]["month"] = []
                # Append the data from match group 1 to the month key
                count[match.group(match_index)]["month"].append(match.group(1))
                # Create an array of day key
                count[match.group(match_index)]["day"] = []
                # Append the data from match group 2 to the day key
                count[match.group(match_index)]["day"].append(match.group(2))
                # Create an array of time key
                count[match.group(match_index)]["time"] = []
                # Append the data from match group 3 to the time key
                count[match.group(match_index)]["time"].append(match.group(3))
                # Create an array of addeduser key
                count[match.group(match_index)]["addeduser"] = []
                # Append the data from match group 5 to the addeduser key
                count[match.group(match_index)]["addeduser"].append(match.group(5))
                # Create an array of type key
                count[match.group(match_index)]["type"] = []
                # Append the data from match group 4 to the type key
                count[match.group(match_index)]["type"].append(match.group(4))
                # Create an array of flag key
                count[match.group(match_index)]["flag"] = []
                # Append the data with "Not SUS" to the flag key
                count[match.group(match_index)]["flag"].append("Not Suspicious")
            else:  # if month is not empty check if username already exists
                exists = False
                if match.group(1) is not None:
                    match_index = 1
                elif match.group(2) is not None:
                    match_index = 2
                elif match.group(3) is not None:
                    match_index = 3
                elif match.group(4) is not None:
                    match_index = 4
                elif match.group(5) is not None:
                    match_index = 5
                for name in month:  # Loop through the variable month
                    if name == match.group(match_index):  # if month already exists, increase count and add
                        exists = True
                        count[match.group(match_index)]["count"] += 1
                        ip_exists = False
                        # Append the necessary info into the same month
                        count[match.group(match_index)]["month"].append(match.group(1))
                        count[match.group(match_index)]["day"].append(match.group(2))
                        count[match.group(match_index)]["time"].append(match.group(3))
                        count[match.group(match_index)]["addeduser"].append(match.group(5))
                        count[match.group(match_index)]["type"].append(match.group(4))
                        count[match.group(match_index)]["flag"].append("Not Suspicious")
                        break
                if not exists:  # if user does not exists yet, add username and ip
                    month.append(match.group(match_index))
                    # Creates an array inside the count array
                    count[match.group(match_index)] = {}
                    # Indicate the first line / count
                    count[match.group(match_index)]["count"] = 1
                    # Creates an array of month key
                    count[match.group(match_index)]["month"] = []
                    # Append the data from match group 1 to the month key
                    count[match.group(match_index)]["month"].append(match.group(1))
                    # Create an array of day key
                    count[match.group(match_index)]["day"] = []
                    # Append the data from match group 2 to the day key
                    count[match.group(match_index)]["day"].append(match.group(2))
                    # Create an array of time key
                    count[match.group(match_index)]["time"] = []
                    # Append the data from match group 3 to the time key
                    count[match.group(match_index)]["time"].append(match.group(3))
                    # Create an array of addeduser key
                    count[match.group(match_index)]["addeduser"] = []
                    # Append the data from match group 5 to the addeduser key
                    count[match.group(match_index)]["addeduser"].append(match.group(5))
                    # Create an array of type key
                    count[match.group(match_index)]["type"] = []
                    # Append the data from match group 4 to the type key
                    count[match.group(match_index)]["type"].append(match.group(4))
                    # Create an array of flag key
                    count[match.group(match_index)]["flag"] = []
                    # Append the data with "Not SUS" to the flag key
                    count[match.group(match_index)]["flag"].append("Not Suspicious")

        # print(count)
        if match2 is not None:  # if there is a match do the folloiwing
            match_index = None  # initialize match index. Can be of group3 or group4 depending on match
            if len(month) == 0:  # if month is empty, directly add this user and ip
                if match2.group(1) is not None:
                    match_index = 1
                elif match2.group(2) is not None:
                    match_index = 2
                elif match2.group(3) is not None:
                    match_index = 3
                elif match2.group(4) is not None:
                    match_index = 4
                elif match2.group(5) is not None:
                    match_index = 5
                # Add the matched data if month is empty
                month.append(match2.group(match_index))
                count[match2.group(match_index)] = {}
                count[match2.group(match_index)]["count"] = 1
                count[match2.group(match_index)]["month"] = []
                count[match2.group(match_index)]["month"].append(match2.group(1))
                count[match2.group(match_index)]["day"] = []
                count[match2.group(match_index)]["day"].append(match2.group(2))
                count[match2.group(match_index)]["time"] = []
                count[match2.group(match_index)]["time"].append(match2.group(3))
                count[match2.group(match_index)]["addeduser"] = []
                count[match2.group(match_index)]["addeduser"].append(match2.group(7))
                count[match2.group(match_index)]["type"] = []
                count[match2.group(match_index)]["type"].append(match2.group(4))
                count[match2.group(match_index)]["flag"] = []
                count[match2.group(match_index)]["flag"].append("Not Suspicious")

            else:  # if month is not empty check if username already exists
                exists = False
                if match2.group(1) is not None:
                    match_index = 1
                elif match2.group(2) is not None:
                    match_index = 2
                elif match2.group(3) is not None:
                    match_index = 3
                elif match2.group(4) is not None:
                    match_index = 4
                elif match2.group(5) is not None:
                    match_index = 5
                for name in month:  # loop through the month array
                    if name == match2.group(
                            match_index):  # if month already exists, increase count and add matched value
                        exists = True
                        count[match2.group(match_index)]["count"] += 1
                        count[match2.group(match_index)]["month"].append(match2.group(1))
                        count[match2.group(match_index)]["day"].append(match2.group(2))
                        count[match2.group(match_index)]["time"].append(match2.group(3))
                        count[match2.group(match_index)]["addeduser"].append(match2.group(5))
                        count[match2.group(match_index)]["type"].append(match2.group(4))
                        count[match2.group(match_index)]["flag"].append("Not Suspicious")
                        break
                if not exists:  # if user does not exists yet, add username and ip
                    # Add the matched data if month is empty
                    month.append(match2.group(match_index))
                    count[match2.group(match_index)] = {}
                    count[match2.group(match_index)]["count"] = 1
                    count[match2.group(match_index)]["month"] = []
                    count[match2.group(match_index)]["month"].append(match2.group(1))
                    count[match2.group(match_index)]["day"] = []
                    count[match2.group(match_index)]["day"].append(match2.group(2))
                    count[match2.group(match_index)]["time"] = []
                    count[match2.group(match_index)]["time"].append(match2.group(3))
                    count[match2.group(match_index)]["addeduser"] = []
                    count[match2.group(match_index)]["addeduser"].append(match2.group(7))
                    count[match2.group(match_index)]["type"] = []
                    count[match2.group(match_index)]["type"].append(match2.group(4))
                    count[match2.group(match_index)]["flag"] = []
                    count[match2.group(match_index)]["flag"].append("Not Suspicious")


    #output = "Month" + "," + "Day" + "," + "Time " + "," + "Added User" + "," + "Type\n"  # create header for .csv
    output = []

    # p3 = re.compile(".*(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b).*([a-zA-Z]{3})[ ]{1,}([0-9]{1,}) (2[0-3]|[0-5]?[0-9]:[0-5]?[0-9]) - (2[0-3]|[0-5]?[0-9]:[0-5]?[0-9]).*")
    p3 = re.compile(
        ".* (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*([a-zA-Z]{3})[ ]{1,}([0-9]{1,}) (2[0-3]|[0-5]?[0-9]:[0-5]?[0-9]) - (2[0-3]|[0-5]?[0-9]:[0-5]?[0-9]) .*")
    for key in count:  # iterate over all users and add name, count and IPs to output string

        for i in range(len(count[key]["month"])):
            last = open("last.txt")
            for perLine in last:  # iterate over all last login lines
                match3 = p3.match(perLine)  # To match each login lines
                match_index = 0
                if match3 is not None:  # if there is a match do following
                    match_index = None  # initialize match index. Can be of group3 or group4 depending on match
                    if match3.group(1) is not None:
                        match_index = 1
                        if count[key]["month"][i] == match3.group(2) and count[key]["day"][i] == match3.group(3):
                            # Check if the matched value equals to the same day and month
                            # If equals, convert the stored variables to time
                            susTime = datetime.datetime.strptime(count[key]["time"][i], '%H:%M:%S')
                            loggedInTime = datetime.datetime.strptime(match3.group(4), '%H:%M')
                            exitTime = datetime.datetime.strptime(match3.group(5), '%H:%M')
                            # Check if the suspectedTime is bigger than logged in time and smaller than the exitTime
                            if loggedInTime.time() < susTime.time() and exitTime.time() > susTime.time():
                                # if match, do the following
                                susIP = match3.group(1)
                                susMonth = match3.group(2)
                                susDay = match3.group(3)
                                # Open failed logged in file lastb
                                failedLogin = open("lastb.txt")
                                for eachFail in failedLogin:  # iterate each line of the opened file
                                    match4 = p3.match(eachFail)  # Use regex to match the data
                                    if match4 is not None:  # if there is a match do following
                                        if match4.group(1) == susIP and match4.group(2) == susMonth and match4.group(
                                                3) == susDay:
                                            #print(match4)
                                            count[key]["flag"][i] = "Suspicious"

            if i == len(count[key]["month"]) - 1:
                # output.append((count[key]))
                output.append(str(count[key]["day"][i]) + " " + str(count[key]["month"][i]) + " " + str(count[key]["time"][i]).ljust(14) + str(count[key]["addeduser"][i]).ljust(20) + str(count[key]["type"][i]).ljust(15) + str(count[key]["flag"][i]))
                #output += str(count[key]["month"][i]) + ", " + str(count[key]["day"][i]) + ", " + str(
                    #count[key]["time"][i]) + ", " + str(count[key]["addeduser"][i]) + ", " + str(
                    #count[key]["type"][i]) + ", " + str(count[key]["flag"][i]) + "\n"

            else:
                output.append(str(count[key]["day"][i]) + " " + str(count[key]["month"][i]) + " " + str(
                    count[key]["time"][i]).ljust(14) + str(count[key]["addeduser"][i]).ljust(20) + str(
                    count[key]["type"][i]).ljust(15) + str(count[key]["flag"][i]))
                # output.append((count[key]))
                #output += str(count[key]["month"][i]) + "," + str(count[key]["day"][i]) + "," + str(
                    #count[key]["time"][i]) + "," + str(count[key]["addeduser"][i]) + "," + str(
                    #count[key]["type"][i]) + "," + str(count[key]["flag"][i]) + "\n"
    #print(output)
    return(output)

    #authlist = open("authlist.csv", "w")  # create empty authlist.csv
    #authlist.write(output)  # add text to authlist.csv
    #authlist.close()



# See PyCharm help at https://www.jetbrains.com/help/pycharm/
