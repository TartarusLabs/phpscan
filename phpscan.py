#!/usr/bin/env python

# Quick and dirty script to scan through a PHP project and flag up functions that are of interest when looking for security vulnerabilities. Helps to save time when doing manual code review by drawing attention to specific places where vulnerabilities are more likely to exist.
# Example usage: ./phpscan.py ~/Downloads/ReallySecureCMS/

# james.fell@tartaruslabs.com


import os
import sys


# Set target directory from command line parameter

inputdir = sys.argv[1]


# Define strings that indicate interesting areas of a PHP script
# TODO - Use regular expressions instead of fixed strings for signatures

user_input = ["$_GET","$HTTP_GET_VARS","$_POST","$HTTP_POST_VARS","$_COOKIE","$HTTP_COOKIE_VARS","$_REQUEST","$_FILES","$HTTP_POST_FILES","$_SERVER"]
sessions = ["$_SESSION","$HTTP_SESSION_VARS"]
file_access = ["fopen","readfile","file","fpassthru","gzopen","gzfile","gzpassthru","readgzfile","copy","rename","rmdir","mkdir","unlink","file_get_contents","file_put_contents","parse_ini_file","include","include_once","require","require_once","virtual","highlight_file","show_source"]
db_access = ["mysql_query","mssql_query","pg_insert","pg_query","pg_select","pg_update","sqlite_array_query","sqlite_exec","sqlite_query"]
dynamic_code_exec = ["eval","call_user_func","call_user_func_array","call_user_method","call_user_method_array","create_function"]
os_command_exec = ["exec","passthru","popen","proc_close","proc_nice","proc_open","shell_exec","system","`"]
url_redirection = ["http_redirect","header","HttpMessage::setResponseCode","HttpMessage::setHeaders"]
sockets = ["socket_create","socket_connect","socket_write","socket_send","socket_recv","fsockopen","pfsockopen"]
clues = user_input + sessions + file_access + db_access + dynamic_code_exec + os_command_exec + url_redirection + sockets



# Scan a PHP file and flag any lines of interest

def scanFile(filename):

	print "Scanning: ", filename, "\n"

	for clue in clues:
		with open(filename) as myFile:
			for num, line in enumerate(myFile, 1):
				if clue in line:
					print "Found: ", clue, "\nLine: ", num, "\n"
		myFile.close()



# Recurse through input directory and scan each .php file

for root, dirs, files in os.walk(inputdir):
	for file in files:
		if file.endswith(".php"):
			scanFile(os.path.join(root, file))


