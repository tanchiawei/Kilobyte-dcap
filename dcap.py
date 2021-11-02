import argparse
import ctypes, os


parser = argparse.ArgumentParser()
parser.add_argument("-b", "--brute", action="store_true", help="Brute Force Detection - accesses btmp log")
parser.add_argument("-a", "--account", action="store_true", help="Account Hijack Detection - accesses .zsh_history")
parser.add_argument("-e", "--entrypoint", action="store_true", help="Entrypoint Detection - accesses auth.log")
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

if args.brute:
	#bruteData = bruteForceDetection(); from sadesh
	print("Brute force detection invoked");

if args.account:
	#hijackData = hijackAccountDetection(); from sadiq
	print("Hijacked account detection invoked");

if args.entrypoint:
	#entryData = rogueEntrypointDetection(); from chiawei
	print("Rogue entrypoint detection invoked");

# and output the final form, html or text or console?
if bruteData is not None:
	pass
if hijackData is not None:
	pass
if entryData is not None:
	pass
