# snort
# snort

Fun little snort rule importer by Keith

#file locations

fileIOC = 'iocdns.txt'		# this is the location of the IOC to be read in
fileRules = 'my.rules' 		# this is the location for the rules file to append


#variables for script

act = 'alert' 			# alert | action | log | pass | drop | reject | sdrop | activate | dynamic
proto = 'udp' 			# ip | tcp | udp | icmp
scrip = 'any'			# A.B.C.D | A.B.C.D/XX | [A.B.C.D, A.B.C.E, A.B.C.G] 
srcprt = 'any'			# Port number
direction = '->'		# -> | <>
dstip = 'any'			# same as scrip
dstprt = '53'			# same as srcprt
msg = 'Alert'			# text to be printed in alert or must be in quotes eg "Yet another scan";
content = ''			# searches the entier packet payload for either an ASCII str or a "binary" this will be ref form fileIOC
sid = 1000001			# 1 - 1000000 reserved, 1000000-2000000 packaged rules, 2000000> now used for custom rules
rev = 1					# revistion of the snort rule (or set)
