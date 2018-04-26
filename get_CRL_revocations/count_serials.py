import json

crlInfileName = 'megaCRL'

print('reading megaCRL...')
megaCRL = {}
crlFile = open(crlInfileName, 'r')
certCtr = 0
for line in crlFile:
    crlData = json.loads(line)
    certCtr += len(crlData["cert_serials"])
print('there are ' + str(certCtr) + ' total revocations')
