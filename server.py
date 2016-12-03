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
