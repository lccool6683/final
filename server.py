#server / attacker
import ConfigParser

configParser = ConfigParser.RawConfigParser()
configFilePath = r'config.txt'
configParser.read(configFilePath)

dstIP = configParser.get('config', 'dstIP')
srcIP = configParser.get('config', 'srcIP')
dstPort = configParser.get('config', 'dstPort')
fileDir = configParser.get('config', 'fileDir')

print dstIP



def getCmd(dstIP, srcIP, dstPort):
	while True: 
		cmd = raw_input("Enter a command: ")

		if cmd =="exit":
			print "Exiting"
			sys.exit()


		elif cmd =="close":
			#drop iptables rule
			print "Closing port"

		else :
			#create a packet to send to the victim
			print "your command " + cmd










#2 main threads. User commands & file extraction
def main():

	cmdThread = threading.Thread(target=getCmd, args=(dstIP, srcIP, dstPort))
	#fileThread = threading.Thread(target=getFile, args=(dstIP, srcIP, dstPort))
	

if __name__== '__main__':
	main()