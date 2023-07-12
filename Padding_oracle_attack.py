import socket
import re

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = input("Enter Port Number: ")
s.connect(("128.186.120.191", int(port)))
messages = []
Secret_Message = []
offset = 0

def queryString(byteNum):
    paddedString = "-e " + "00"*(byteNum+offset)
    s.send(paddedString.encode())
    data = s.recv(1024).decode()
    return data

def formatData(data):
    data = data.replace("\n","")
    data = data.replace(" ","")
    encryptedData = re.findall("\\\\n(.*?)\\\\n'",data)
    IVdata = re.findall("IV:b'(.*?)'",data)
    eArgData = re.findall("-e(.*)",data)
    return (encryptedData[0],IVdata[0],eArgData[0])

def queryDecryptionOracle(cipherData):
		s.send(("-V "+cipherData).encode())
		isValid = s.recv(1024).decode()
		return isValid

def getMsgSize():
		data = formatData(queryString(0))
		ciphersize = len(data[0])/2
		newCiphersize = ciphersize
		numOfQueries = 0
		
		try:
			while (ciphersize == newCiphersize):
				r = queryString(numOfQueries)
				data = formatData(r)
				newCiphersize = len(data[0])/2
				numOfQueries += 1
		except Exception as e:
			print(e)
		return numOfQueries

offset =  (getMsgSize() - 1) % 16

def extractData(p):
	data,IV_data,padding = formatData(queryString(0))
	msgLength = len(data)
	numofBlocks = msgLength//32
	cblocks = [IV_data]
	for r in range(0, numofBlocks, 1):
		cblocks.append(data[r*32:r*32+32])

	for i in range(16):

		for j in range(2000):	
			data,IV_data,padding = formatData(queryString(i))
			bblocks = [IV_data]
			for r in range(0, numofBlocks, 1):
				bblocks.append(data[r*32:r*32+32])
			cblocks[numofBlocks] = bblocks[p]
			cipherData = "".join(cblocks[1:]) + " " + str(cblocks[0])
			isValid = queryDecryptionOracle(cipherData)
			if isValid == "Valid":
				messages.append(chr(15 ^ int(bblocks[p-1][30:],16) ^ int(cblocks[numofBlocks-1][30:],16)))
				print(messages)
				break
			
for i in range(1):
	data,IV_data,padding = formatData(queryString(0))
	numofBytes = int(((len(data)/2) - 32) / 16)

for p in range(1, numofBytes+1, 1):
	extractData(p)
	numofBytes-1
	messages.reverse()
	messages = ''.join(messages)
	Secret_Message.append(messages)
	messages = []

print('\nThe Secret message at Port ' +str(port)+ ' is:')
print(''.join(Secret_Message) + '\n\n')