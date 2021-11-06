import re
import sys
import argparse
import datetime
import re
import subprocess


def sudoFinder(data):
    subs = 'sudo'
    results = [i for i in data if subs in i]
    return results
    # for j in results:
    # print(j.strip())


def pwdFinder(data):
    subs = 'pwd'
    results = [i for i in data if subs in i]
    return results


def whoamiFinder(data):
    subs = 'whoami'
    results = [i for i in data if subs in i]
    return results


def idFinder(data):
    p = re.compile("(id$)")
    results = []
    # subs = 'id'
    for i in data:
        match = p.match(i)  # match line with regex
        if match is not None:  # if there is a match do following
            match_index = None  # initialize match index. Can be of group3 or group4 depending on match
            if match.group(1) is not None:
                match_index = 1
                results.append(match.group(match_index))

    return results


def unameFinder(data):
	subs = 'uname'
	results = [i for i in data if subs in i]
	return results


def hijackAccountDetection():
    retrieveUser = subprocess.run(['cat', '/etc/passwd'], stdout=subprocess.PIPE).stdout.decode('utf-8')
    result = open("existingUser.txt", "w")  # create file last.txt
    result.write(retrieveUser)
    result.close()

    logs = open("existingUser.txt")
    p1 = re.compile(".*:(\/.*):\/bin\/bash|.*:(\/.*):\/bin\/sh")
    userFilePath = []
    allFileHistory = []
    eachUserStatus = []
    for line in logs:  # iterate over each line

        match = p1.match(line)  # match line with regex
        if match is not None:  # if there is a match do following

            match_index = None  # initialize match index. Can be of group3 or group4 depending on match

            if match.group(1) is not None:
                output = ''
                match_index = 1
                userFilePath.append(match.group(match_index))
                filePath = match.group(match_index) + '/.bash_history'
                # print(filePath)
                # allFileHistory.append(subprocess.run(['cat', filePath], stdout=subprocess.PIPE).stdout.decode('utf-8'))
                output += subprocess.run(['cat', filePath], stdout=subprocess.PIPE).stdout.decode('utf-8')
                # print(output)
                allFileHistory.append(output)
                # print(allFileHistory)

    for count in range(len(userFilePath)):
        if allFileHistory[count] != '':
            parsed_data = allFileHistory[count].split('\n')
            eachUserStatus.append(
                [len(sudoFinder(parsed_data)), len(pwdFinder(parsed_data)), len(whoamiFinder(parsed_data)),len(idFinder(parsed_data)), len(unameFinder(parsed_data))])
        else:
            eachUserStatus.append([0, 0, 0, 0, 0])

    return userFilePath, eachUserStatus
