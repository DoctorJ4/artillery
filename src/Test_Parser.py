#THIS IS A TEST FILE OF THE PARSER FUNCTION
import re
import datetime

def persistant_404(apache_file):
	# create a record of each time a 404 occurred with each IP
	ipList = []
	ip404counter = []
	ipAlertList = [] 
	now = str(datetime.datetime.today())
	with open(apache_file) as f:
		logs = f.readlines()
	
	for line in logs:
		pattern = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
		ip = pattern.search(line).group()
		if '404' in line:
			# parse ip from line and record the activity in the parallel arrays
			if ip in ipList:
				index = ipList.index(ip)
				ip404counter[index] = ip404counter[index] + 1
			else:
				ipList.append(ip)
				ip404counter.append(1)
				
	# if the number of times a 404 is initiated by the IP exceeds a number ( maybe 4? ) then record that in a list
	for Badip, numHits in zip(ipList, ip404counter):
		if numHits > 2:
			#READABLE TESTING PHRASES
			print '{0:19} 404s: {1:1}'.format(Badip, numHits)
		#print "%s        404's:%s"% (Badip, numHits)
		
		#TESTING PHRASES
		#print "%s [!] Artillery has detected (in the apache logs) a possible attack from the IP Address: %s" % (now, Badip)
		#print "Artillery has detected a possible attack from IP address: %s after initiating %s 404 errors.\n" % (Badip, numHits)
		
		#subject = "%s [!] Artillery has detected (in the apache logs) a possible attack from the IP Address: %s" % (now, ip)
		#alert = "%s [!] Artillery has detected a possible attack from IP address: %s after initiating multiple 404 errors." % (now, ip)
		#warn_the_good_guys(subject, alert)----------------------------------------------------------------------------------
	
# grab the access logs and tail them
access = "access.log"

# check persistent 404's from access logs
persistant_404(access)
