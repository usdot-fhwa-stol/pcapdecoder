import J2735_201603_2023_06_22
import sys
import json
from binascii import unhexlify
from collections import defaultdict

def formatFileName():
    fileList = sys.argv[1].split('/')
    file = fileList[-1]
    fileName = 'decoded_' + file.replace('.pcap', '.txt')

    return fileName

def readLines():
    fileList = sys.argv[1].split('/')
    fileList[-1] = "pcap.txt"
    inputFile = "/".join(fileList)
    f = open(inputFile, 'r')
    Lines = f.readlines()
    f.close()

    return Lines

def writeIds(w, msgId_count):
    w.write('\nDecoded Message ID Counts:\n')
    print('\nDecoded Message ID Counts:')
    for msgId, count in msgId_count.items():
        w.write(f'{msgId}: {count}\n')
        print(f'{msgId}: {count}')

def isValidMessage(line):
    tempFrame = line[6:]
    if (len(tempFrame.strip('\n')) > 510):
        frameSize = 8
        encodedSize = int(line[5:8], 16) * 2
    else: 
        frameSize = 6
        encodedSize = int(line[4:6], 16) * 2

    newFrame = line[frameSize:].strip('\n')
    if (encodedSize == len(newFrame)):
        return True
    else:
        return False
    
def convertBytes(obj):
    if isinstance(obj, dict):
        return {k: convertBytes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convertBytes(item) for item in obj]
    elif isinstance(obj, tuple):
        return [convertBytes(item) for item in obj]
    elif isinstance(obj, bytes):
        return obj.hex()
    else:
        return obj

def decode(data, frame, w, msgId_count, id):
    w.write(data)
    w.write('\n')
    print(data)
    frame.from_uper(unhexlify(data))
    cleanObj = convertBytes(frame())
    jsonString = json.dumps(cleanObj, indent=2)
    print(jsonString)
    w.write(jsonString)
    w.write('\n')
    msgId_count[id] += 1  # increment count for successfully decoded msgId

def main():
    frame = J2735_201603_2023_06_22.DSRC.MessageFrame
    msgIds = ['0012','0013','0014','001f','0020','0029'] # can be updated to include other PSIDs
    msgId_count = defaultdict(int)  # dictionary to track decoded msgId and their counts
    fileName = formatFileName()
    w = open(fileName, 'w')

    for line in readLines():
        for id in msgIds:
            idx = line.find(id)
            if (idx != -1):
                data = line[idx:].strip('\n')
                if (isValidMessage(data) == True):
                    try:
                        decode(data, frame, w, msgId_count, id)
                    except Exception as e:
                        print("Error decoding message: ", e)
                        continue
            else: continue

    # Write the decoded message IDs and their counts to the output file
    writeIds(w, msgId_count)
    w.close()

    print('\nDecoding Complete. Check', fileName, '\n')
    sys.exit(0)

if __name__=="__main__":
    main()
