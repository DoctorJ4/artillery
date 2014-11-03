#127.0.0.1 - - [10/Mar/2012:15:35:53 -0500] "GET /sdfsdfds.dsfds HTTP/1.1" 404 501 "-" "Mozilla/5.0 (X11; Linux i686 on x86_64; rv:10.0.2) Gecko/20100101 Firefox/10.0.2"
import re
import datetime

def tail(some_file):
    this_file = open(some_file)
    # Go to the end of the file
    this_file.seek(0,2)

    while True:
        line = this_file.readline()
        if line:
            yield line
        yield None

def persistant_404(apache_file):
	# create a record of each time a 404 occurred with each IP
	ipList = []
	ip404counter = []
	ipAlertList = []
	now = str(datetime.datetime.today())
	# search for 404's
	for line in apache_file
		if '404' in line
			# parse ip from line and record the activity in the parallel arrays
			ipList.append(re.findall( r'[0-9]+(?:\.[0-9]+){3}', s ))
			if ip in ipList
				index = ipList.index(ip)
				ip404counter[index] = ip404counter[index] + 1
			else
				ipList.append(ip)
				ip404counter.append(1)
				
	# if the number of times a 404 is initiated by the IP exceeds a number ( maybe 4? ) then record that in a list
	ipAlertList = [j for (i,j) in zip(ipList, ip404counter) if i >= 4]
	
	# let the good guys know
	for ip in ipAlertList
		subject = "%s [!] Artillery has detected (in the apache logs) a possible attack from the IP Address: %s" % (now, ip)
		alert = "Artillery has detected a possible attack from IP address: %s after initiating multiple 404 errors." % (ip)
		warn_the_good_guys(subject, alert)
	
# grab the access logs and tail them
access = "/var/log/apache2/access.log"
access_log = tail(access)

# check persistent 404's from access logs
persistant_404(access)

# grab the error logs and tail them
errors = "/var/log/apache2/error.log"
error_log = tail(errors)
