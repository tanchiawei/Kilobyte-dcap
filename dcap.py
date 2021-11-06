import argparse
import ctypes, os

from bruteForceDetection import bruteForceDetection
from hijackAccountDetection import hijackAccountDetection
from rougeEntrypointDetection import rougeEntrypointDetection  # rouge?

parser = argparse.ArgumentParser()
parser.add_argument("outputlocation", type=str, help="Define destination and name of output file")
parser.add_argument("-b", "--brute", action="store_true",
                    help="Brute Force Detection - examines btmp log and outputs result to console and destination file")
parser.add_argument("-a", "--account", action="store_true",
                    help="Account Hijack Detection - accesses .bash_history and outputs result to console and destination file")
parser.add_argument("-e", "--entrypoint", action="store_true",
                    help="Entrypoint Detection - accesses auth.log and outputs result to console and destination file")
args = parser.parse_args()

# check for root permissions and linux OS
try:
    rootBoolean = (os.getuid() == 0)
except AttributeError:
    print("This program is designed for Linux distributions only.")
    exit()

if rootBoolean:
    print("Root check OK")
else:
    print("This program is not running as root, are you sure you have the permissions to access all logs?")

# time to do work
bruteData = None
hijackData = None
entryData = None

f = open(args.outputlocation, "w")

if args.brute:
    print("\nDetecting brute force patterns...");
    f.write("--------------------Brute Force Detection Results--------------------\n");
    bruteData = bruteForceDetection();
    usernames = bruteData[0]
    count = bruteData[1]

    output = ''
    output = []
    for key in count:
        print("\nUser " + count[key]["User"][0].ljust(20) + "| Failed Login Attempts: " + str(count[key]["count"]),
              end="")
        f.write("\nUser " + count[key]["User"][0].ljust(20) + "\t|\tFailed Login Attempts: " + str(count[key]["count"]))
        if count[key]["count"] > 5:
            print(" (Suspected Brute Force)")
            f.write(" (Suspected Brute Force)\n")
        else:
            f.write("\n")
            print("\n", end="")
        for i in range(len(count[key]["User"])):
            if i == len(count[key]["User"]) - 1:
                print("Login attempt at " + count[key]["time"][i] + " IP: " + count[key]["IP"][i])
                f.write("Login attempt at " + count[key]["time"][i] + " IP: " + count[key]["IP"][i] + "\n")
            else:
                print("Login attempt at " + count[key]["time"][i] + " IP: " + count[key]["IP"][i])
                f.write("Login attempt at " + count[key]["time"][i] + " IP: " + count[key]["IP"][i] + "\n")

if args.account:
    print("\nDetecting hijacked account patterns...");
    f.write("\n--------------------Hijacked Account Detection Results--------------------\n");
    userFilePath, eachUserStatus = hijackAccountDetection();

    print("User".ljust(30), "sudo".ljust(10), "pwd".ljust(10), "whoami".ljust(10), "id")
    f.write("User".ljust(30) + "sudo".ljust(10) + "pwd".ljust(10) + "whoami".ljust(10) + "id" + "\n")
    print("User".ljust(30), "sudo".ljust(10), "pwd".ljust(10), "whoami".ljust(10), "id".ljust(10), "uname")
    f.write(
        "User".ljust(30) + "sudo".ljust(10) + "pwd".ljust(10) + "whoami".ljust(10) + "id".ljust(10) + "uname" + "\n")
    for eachUser, eachCountList in zip(userFilePath, eachUserStatus):
        print(str(eachUser).ljust(30), str(eachCountList[0]).ljust(10), str(eachCountList[1]).ljust(10),str(eachCountList[2]).ljust(10), str(eachCountList[3]).ljust(10), str(eachCountList[4]))
        f.write(str(eachUser).ljust(30) + str(eachCountList[0]).ljust(10) + str(eachCountList[1]).ljust(10) + str(eachCountList[2]).ljust(10) + str(eachCountList[3]).ljust(10) + str(eachCountList[4]) + "\n")

if args.entrypoint:
    print("\nDetecting rogue entrypoints...");
    f.write("\n--------------------Rogue Entrypoint Detection Results--------------------\n")
    entryData = rougeEntrypointDetection();
    print("Timestamp".ljust(20) + "User".ljust(20) + "Command".ljust(15) + "Flag")
    f.write("Timestamp".ljust(20) + "User".ljust(20) + "Command".ljust(15) + "Flag\n")
    for eachLine in entryData:
        print(eachLine)
        f.write(eachLine + "\n")

f.close()

print("\nFinal report written to " + str(args.outputlocation))
