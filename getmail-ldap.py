#!/usr/bin/python3
# File: getmail-ldap.py

# apt-get install python3-ldap3

try:
	# system libraries we should have no error here
	import string
	#from StringIO import StringIO
	import time
	#import datetime
	from datetime import datetime, timedelta, timezone
	import re
	from os.path import os

except ImportError:
	print("Cannot find one of the system libraries, please install and try again")
	raise SystemExit

try:
	import errno
except ImportError:
	print("Cannot find library errno, please install it and try again")
	raise SystemExit
try:
	import logging
	import logging.handlers
except ImportError:
	print("Cannot find library logging, please install it and try again")
	raise SystemExit

try:
	import ldap3
	#from ldap3 import Server, Connection, ALL, SUBTREE, BASE, LEVEL, MODIFY_REPLACE
except ImportError:
	print("Cannot find library ldap3, please install it and try again")
	raise SystemExit

try:
	import ssl
	#from ldap3 import Server, Connection, ALL, SUBTREE, BASE, LEVEL, MODIFY_REPLACE
except ImportError:
	print("Cannot find library ssl, please install it and try again")
	raise SystemExit

try:
	from urllib.parse import urlparse
except ImportError:
	print("Cannot find library urllib3, please install it and try again")
	raise SystemExit

try:
	import configparser
	import threading
	import queue
	import subprocess
	#from subprocess import Popen,PIPE
	import signal
except ImportError:
	print("Cannot find all required libraries please install them and try again")
	raise SystemExit

config_file_location = '/home/secmail/getmail-ldap.cfg'

class CustomError(Exception):
	"""Base Class for getmail exceptions"""
	pass

def pid_exists(pid):
	"""Is there a process with PID pid?"""
	if pid < 0:
		return False

	exist = False
	try:
		os.kill(pid, 0)
		exist = True
	except OSError as x:
		if x.errno != errno.ESRCH:
			raise

	return exist

def getmail_command(getmail_binary, config_filename, config_data_dir, imap_idle):
	command = [getmail_binary, \
		#'--quiet', \
		'-v', \
		'--rcfile=' + config_filename, \
		'--getmaildir=' + config_data_dir]
	if imap_idle:
		#self.imap_idle = False
		command.append('--idle=INBOX')
	return command

def getmail_pid(pid_filename):
	# Check for a pidfile to see if the daemon already runs
	try:
		pid_file = open(pid_filename,'r')
		pid_number = pid = int(pid_file.read().strip())
		pid_file.close()
	except IOError:
		pid = None
	return pid


class RetrieveMails(threading.Thread):
	def __init__(self, getmail_binary, config_filename, config_data_dir, pid_filename, ldap_details, imap_idle, timeout=3600):
		super(RetrieveMails, self).__init__()
		#threading.Thread.__init__(self)
		self.getmail_binary, self.config_filename, self.config_data_dir, self.pid_filename, self.ldap_details, self.imap_idle, self.timeout = \
			getmail_binary, config_filename, config_data_dir, pid_filename, ldap_details, imap_idle, timeout

	def run(self):
		try:
			command = getmail_command(self.getmail_binary, self.config_filename, self.config_data_dir, self.imap_idle)

			pid_number = pid = getmail_pid(self.pid_filename) 
			#print("Command: "+" ".join(command)+"\nProcess ID: "+str(pid))

			# Check whether process is really running
			if (pid is not None) and (pid>0):
				pid = pid_exists(pid)
				if pid:
					log_object.info(" Existing pid for Command " + " ".join(command) +\
						" found in "+self.pid_filename+", pid " + str(pid_number) + " running")
				else:
					log_object.info(" Existing pid for Command " + " ".join(command) +\
						" found in "+self.pid_filename+", but pid " + str(pid_number) + " not running")
			else:
				pid = False
			if not pid:
				stdout = []
				stderr = []
				try:
					getmail_process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
					pid_number = getmail_process.pid
					open(self.pid_filename,'w+').write("%s\n" % getmail_process.pid)
					#log_object.info("Updating LDAP retrieval for "+self.ldap_details.write_dn)
					ldap_result=self.update_ldap()
					#log_object.info("Update of LDAP retrieval for "+self.ldap_details.write_dn+" finished")
					start_time = datetime.now()
					# wait until timeout - it is not possible to use communicate() as it will block threading
					while getmail_process.poll() is None:
						# Use sleep as otherwise 100% cpu usage
						time.sleep(1)
						if self.imap_idle:
							if datetime.now()>start_time + timedelta(seconds=self.timeout):
								raise subprocess.TimeoutExpired(getmail_process.args, self.timeout)
					(stdout,stderr) = getmail_process.communicate();
				except subprocess.TimeoutExpired:
					log_object.info("Command " + " ".join(command) +\
						" timed out with PID " + str(pid_number)+" trying to terminate gracefully")
					getmail_process.terminate()
					try:
						(stdout,stderr) = getmail_process.communicate(timeout=10);
					except subprocess.TimeoutExpired:
						log_object.info("Command " + " ".join(command) +\
							" forcing ungracefull kill for PID " + str(pid_number))
						getmail_process.kill()
						(stdout,stderr) = getmail_process.communicate()
				finally:
					# Delete the pid file if it exists
					if os.path.isfile(self.pid_filename):
						os.remove(self.pid_filename)
					# Zur Sicherheit die erstellte Konfigurationsdatei loeschen (Login-Daten!)
					if os.path.isfile(self.config_filename):
						os.remove(self.config_filename)
					# Remove spaces after every character
					#stderr_output = "".join(stderr).strip()
					#print("x"+stderr_output+"x")
					#print(getmail_process.returncode)
					if getmail_process.returncode != 0 or len("".join(stderr).strip())>0 :
						raise CustomError("Getmail command failed for " + " ".join(command) \
							+"\nStdErr: \n" + "".join(stderr) \
							+"\nStdOut: \n" + "".join(stdout) \
							+"\nExit Code: " + str(getmail_process.returncode))
			else:
				log_object.info("Command " + " ".join(command) +\
					" not executed, existing pid " + str(pid_number) + " found")
		except:
			log_object.exception("An error occured during mail retrieval!")
	
	# Updates the LDAP-Directory to store the date and time of the last mail retrieval
	def update_ldap(self):
		# check if ssl/tls are used
		use_ssl = self.ldap_details.ssl_mode == 'ssl'
		start_tls = self.ldap_details.ssl_mode == 'starttls'

		# create tls config if necessary
		tls = None
		if use_ssl or start_tls:
			tls = ldap3.Tls(validate=ssl.CERT_REQUIRED)
		# if multiple servers are given, add each of them zo the server pool
		server_pool = ldap3.ServerPool(None, ldap3.ROUND_ROBIN, active=True, exhaust=30)

		# add each server to the pool
		for server_url in self.ldap_details.server.split(','):
			parsed_url = urlparse(server_url.strip())
			if parsed_url.scheme == "ldaps":
				use_ssl = True
				port = 636
			elif parsed_url.scheme == "ldap":
				use_ssl = False
				port = 389
			elif parsed_url.scheme == "ldapi":
				use_ssl = False
				port = None
			else:
				raise RuntimeError(f"Unknown scheme '{parsed_url.scheme}' in URL '{server_url.strip()}'")

			if parsed_url.port:
				port = parsed_url.port
			
			host = parsed_url.hostname
			server = ldap3.Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ldap3.ALL)
			server_pool.add(server)

		# establish connection
		with ldap3.Connection(server_pool, user=self.ldap_details.bind_dn, password=self.ldap_details.bind_password, auto_bind=True) as conn:
			return conn.modify(self.ldap_details.write_dn, {self.ldap_details.attribute: [(ldap3.MODIFY_REPLACE, [datetime.utcnow().strftime("%Y%m%d%H%M%SZ")])]})
			#print(conn.result)

class RetrieveAccount:
	def __init__(self, account_name=None, account_type=None, server=None, login=None, password=None, mail_fetch_interval=300, last_mail_retrieval=None, imap_idle=False, imap_idle_timeout=3580):
		self.account_name, self.account_type, self.login, self.password, self.server, self.mail_fetch_interval, self.last_mail_retrieval, self.imap_idle, self.imap_idle_timeout = \
			account_name, account_type, login, password, server, mail_fetch_interval, last_mail_retrieval, imap_idle, imap_idle_timeout

class LDAPOptions:
	def __init__(self, server=None, ssl_mode=None, bind_dn=None, bind_password=None, write_dn=None, attribute=None):
		self.server, self.ssl_mode, self.bind_dn, self.bind_password, self.write_dn, self.attribute = \
			server, ssl_mode, bind_dn, bind_password, write_dn, attribute

class GetmailConfigFile(configparser.ConfigParser):
	output_filename = None
	def __init__(self, defaults, default_config_filename=None, output_filename=None):
		configparser.ConfigParser.__init__(self, defaults)
		if default_config_filename is not None:
			self.read(default_config_filename)
		self.output_filename = output_filename
	def set_mail_account(self, newRetrieveAccount):
		self.set('retriever','server',newRetrieveAccount.server)
		self.set('retriever','type',newRetrieveAccount.account_type)
		self.set('retriever','username',newRetrieveAccount.login)
		self.set('retriever','password',newRetrieveAccount.password)
		self.set('exim-local','arguments','("-i","'+newRetrieveAccount.account_name+'",)')
	def write(self):
		if self.output_filename is not None:
			"""try:
				output_file = open(self.output_filename, 'wb')
			except:
				raise Exception, "Unable to open " + \
					self.output_filename + "for writing"
			finally:
				output_file.close()
			"""
			# file has to be created with more permissive read permissions
			os.umask(0)
			output_file = open(os.open(self.output_filename, os.O_CREAT | os.O_WRONLY, 0o660), 'w')
			configparser.ConfigParser.write(self, output_file)
		else:
			raise CustomError("No output file for configuration defined")

def main_call():

	# Thread liste
	threads = []

	#print(config_object.get('LDAP','LDAPServer'));
	# first open a connection to the LDAP server
	ldap_options = LDAPOptions( \
		config_object['LDAP']['LDAPServer'], \
		config_object['LDAP']['SSLMode'], \
		config_object['LDAP']['BindDN'], \
		config_object['LDAP']['BindPassword'])

	# check if ssl/tls are used
	use_ssl = ldap_options.ssl_mode == 'ssl'
	start_tls = ldap_options.ssl_mode == 'starttls'

	# create tls config if necessary
	tls = None
	if use_ssl or start_tls:
		tls = ldap3.Tls(validate=ssl.CERT_REQUIRED)
	# if multiple servers are given, add each of them zo the server pool
	server_pool = ldap3.ServerPool(None, ldap3.ROUND_ROBIN, active=True, exhaust=30)

	for server_url in ldap_options.server.split(','):
		parsed_url = urlparse(server_url.strip())
		if parsed_url.scheme == "ldaps":
			use_ssl = True
			port = 636
		elif parsed_url.scheme == "ldap":
			use_ssl = False
			port = 389
		elif parsed_url.scheme == "ldapi":
			use_ssl = False
			port = None
		else:
			raise RuntimeError(f"Unknown scheme '{parsed_url.scheme}' in URL '{server_url.strip()}'")

		if parsed_url.port:
			port = parsed_url.port
		
		host = parsed_url.hostname
		server = ldap3.Server(host, port=port, use_ssl=use_ssl, tls=tls, get_info=ldap3.ALL)
		server_pool.add(server)

	with ldap3.Connection(server_pool, user=ldap_options.bind_dn, password=ldap_options.bind_password, auto_bind=True, return_empty_attributes=True) as conn:
		
		## The next lines will also need to be changed to support your search requirements and directory
		## retrieve all attributes - again adjust to your needs - see documentation for more options

		if config_object.get('LDAP','SearchScope').upper() == "SUB":
			ldap_search_scope = ldap3.SUBTREE
			#search_scope_sub = true
		elif config_object.get('LDAP','SearchScope').upper() == "ONE":
			ldap_search_scope = ldap3.LEVEL
			#search_scope_sub = false
		else:
			ldap_search_scope = ldap3.BASE
			#raise CustomError("Search on LDAP BASE needs to be specified by providing the relevant seearch dn")

		relattributes=config_object.get('LDAP','RelevantAttributes').split(',')

		conn.search(search_base=config_object.get('LDAP','SearchDN'), \
			search_filter=config_object.get('LDAP','SearchFilter'), \
			search_scope=ldap_search_scope, \
			attributes=relattributes)

		for ldap_result in conn.entries:
			#print(ldap_result)
			# Check results for optional values
			mail_fetch_interval = 300
			if getattr(ldap_result, relattributes[5]):
				mail_fetch_interval = int(getattr(ldap_result,relattributes[5])[0])

			# Set date and time for last mail retrieval based on LDAP entry
			last_mail_retrieval = None
			if getattr(ldap_result, relattributes[6]):
				last_mail_retrieval = getattr(ldap_result,relattributes[6])[0]
			#print(type(last_mail_retrieval));
			#print(last_mail_retrieval);

			# If no valid date and time is found, set back to two weeks ago and write log entry
			if last_mail_retrieval is None:
				log_object.info("Account with no valid time for last retrieval: " + \
					getattr(ldap_result,relattributes[0])[0])
				last_mail_retrieval = datetime.now(timezone.utc).timedelta(weeks=-2)
			#log_object.info("Datum :" + last_mail_retrieval.isoformat("#","milliseconds"))

			# IMAP Idle is not activated by default
			imap_idle = False
			if getattr(ldap_result,relattributes[7], None):
				imap_idle = getattr(ldap_result,relattributes[7])[0]

			# set timeout for IMAP idla to mail_fetch_interval
			imap_idle_timeout = None
			if imap_idle:
				imap_idle_timeout = mail_fetch_interval

			# print(getattr(ldap_result,relattributes[0])[0]+' '+str(imap_idle))
			account = RetrieveAccount( \
				# Account Name \
				getattr(ldap_result,\
					relattributes[0])[0] ,\
				# Account Type \
				getattr(ldap_result,\
					relattributes[1])[0],\
				# Server \
				getattr(ldap_result,\
					relattributes[2])[0],\
				# Login \
				getattr(ldap_result,\
					relattributes[3])[0],\
				# Password \
				getattr(ldap_result,\
					relattributes[4])[0],\
				# Mail Fetch Interval \
				mail_fetch_interval,\
				# Date and Time of last mail retrieval 
				last_mail_retrieval, \
				# Use IMAP IDLE yes or no
				imap_idle,\
				# Timeout for IMAP Idle
				imap_idle_timeout
			)
			# Define where to write the date and time for retrieval start so each thread knows..
			ldap_options.write_dn = ldap_result.entry_dn
			ldap_options.attribute = relattributes[6]
			config_output_filename = os.path.join(\
				config_object.get('Main','ConfigFileOutputDir'), \
				"getmail_" + \
				account.account_name + \
				".cfg")
			pid_filename = config_output_filename+'.pid'
			if imap_idle:
				pid = getmail_pid(pid_filename)
				#log_object.info("PID for account " + account.account_name + " is " + str(pid))

			# Pruefen, ob die Zeit bereits gekommen ist, um die Mails abzuholen
			# Wenn der Prozess nicht läuft und imap idle eingestellt ist => ebenfalls starten
			if (last_mail_retrieval + timedelta(seconds=mail_fetch_interval)<=datetime.now(timezone.utc)) or (imap_idle and pid is None):
				config_file = GetmailConfigFile(None, \
					config_object.get('Main','DefaultGetmailConfigFile'), config_output_filename)
				config_file.set_mail_account(account)
				log_object.info("Writing Account Configuration for " + account.account_name + \
						" to file " + config_output_filename)
				config_file.write()
				thread = RetrieveMails(\
					config_object.get('Main','GetmailBinary'), \
					config_output_filename, \
					config_object.get('Main','GetmailDir'), \
					pid_filename, \
					# new instance of the class needed to make sure variables are correct in the thread!
					LDAPOptions(ldap_options.server, ldap_options.ssl_mode, ldap_options.bind_dn, ldap_options.bind_password, ldap_options.write_dn, ldap_options.attribute), \
					account.imap_idle, \
					account.imap_idle_timeout \
				)
				threads += [thread]
				thread.start()
				#print(config_output_filename)
				#print("Name " + account.account_name)
				#print("Type " + account.account_type)
				#print("Server " + account.server)
				#print("Login " + account.login)
				#print("Password " + account.password)
				#print("Last mail retrieved on " + last_mail_retrieval.isoformat("#","milliseconds"))
				#print("Mailfetchinterval " + str(mail_fetch_interval))
				#print("IMAP Idle " + str(account.imap_idle))
				#print("DN " + ldap_options.write_dn)
				#print("-----------------")

	# Start all Threads
#	for x in threads: 
#		x.start()

	# Warten bis alle Threads beendet sind
	for x in threads: 
		x.join()

if __name__ == "__main__":
	# Konfigurationsdatei lesen
	config_object = configparser.ConfigParser()
	config_object.read(config_file_location)

	# Set-up Logging
	log_object = logging.getLogger("getmail-ldap")
	log_object.setLevel(logging.DEBUG)

	# This handler writes everything to a log file.
	log_file_handler = logging.FileHandler(config_object.get('Logging','LogFile'))
	log_file_formatter = logging.Formatter("%(levelname)s %(asctime)s %(funcName)s %(lineno)d %(message)s")
	log_file_handler.setFormatter(log_file_formatter)
	log_file_handler.setLevel(logging.DEBUG)
	log_object.addHandler(log_file_handler)

	# This handler emails anything that is an error or worse.
	log_smtp_handler = logging.handlers.SMTPHandler(\
		config_object.get('Logging','MailServer'),\
		config_object.get('Logging','MailFrom'),\
		config_object.get('Logging','MailTo').split(','),\
		config_object.get('Logging','MailSubject'))
	log_smtp_handler.setLevel(logging.ERROR)
	log_smtp_handler.setFormatter(log_file_formatter)
	log_object.addHandler(log_smtp_handler)

	try:
		main_call();
	except:
		log_object.exception("An error occured!")
