import socket
import struct
import time
from sympy.ntheory import factorint


# package needed for generating prime numbers
from Crypto.Util import number
# package needed in serializing and deserializing data
import pickle

def preProcessText(text):
    # make text in lower case
    text = text.lower()

    # creating a list
    text = list(text)

    # loop all over the text
    for i in range(len(text)):

        # map numbers from '0' -> '9' to 0 -> 9
        if '9' >= text[i] >= '0':
            text[i] = ord(text[i]) - ord('0')

        # map characters to 10 -> 35
        elif 'z' >= text[i] >= 'a':
            text[i] = ord(text[i]) - ord('a') + 10

        # otherwise, map to 36
        else:
            text[i] = 36

    # putting extra spaces at the end of text if it's not divisible by 5
    remainingSpaces = 5 - len(text) % 5
    if remainingSpaces != 5:
        for i in range(remainingSpaces):
            text.append(36)

    return text


def groupChars(text):
    # creating a list
    numberArray = []

    # grouping each 5 chars together
    for i in range(0, len(text), 5):
        numberArray.append(
            text[i] * (37 ** 4) + text[i + 1] * (37 ** 3) + text[i + 2] * (37 ** 2) + text[i + 3] * (37 ** 1) + text[
                i + 4])

    return numberArray


def deGroupChars(numberArray):
    # array to store the actual numbers in it
    decodedNums = [None] * (len(numberArray) * 5)

    # degroup values
    for i in range(len(numberArray)):
        num = numberArray[i]
        for j in range(4, -1, -1):
            decodedNums[i * 5 + (4 - j)] = num // (37 ** j)
            num %= (37 ** j)

    return decodedNums


def deProcess(numbers):
    # loop all over the numbers
    for i in range(len(numbers)):

        # map numbers from 0 -> 9 to '0' -> '9'
        if 9 >= numbers[i] >= 0:
            numbers[i] = chr(numbers[i] + ord('0'))

        # map characters from 10 -> 35 to 'a' -> 'z'
        elif 35 >= numbers[i] >= 10:
            numbers[i] = chr(ord('a') + numbers[i] - 10)

        # otherwise, map to ' '
        else:
            numbers[i] = ' '

    return ''.join(numbers)


def generatePrime(N):
    primeNum = number.getPrime(N)
    while not number.isPrime(primeNum):
        primeNum = number.getPrime(N)
    return primeNum


# generate the value of e
def generateEval(p, q):
    temp = max(p, q) + 1

    while not number.isPrime(temp):
        temp += 1

    return temp


# this function is to receive packets from the sender
def recvData(s):
    #receive length of data first
    dataLen = struct.unpack('>I', s.recv(4))[0]
    #receive the actual data
    data = s.recv(dataLen)
    return data

# factorize the prime number (NOT USED)
def factorizePrimeNum(primeNumber):
    factorizedVals = []
    for i in range(3, int(primeNumber**0.5) + 1, 2):
        if primeNumber % i == 0:
            factorizedVals.append(i)
            primeNumber //= i
            factorizedVals.append(primeNumber)
            break
    return factorizedVals


print('-------------------------------------------')
print('HACKER')
print('-------------------------------------------')

# getting hostname
host = socket.gethostname()

# the port that communication will happen through
portNum = 12345

# Creating a socket
mySocket = socket.socket()

# the port isn't created yet, as I am a server
mySocket.connect((host, portNum))

try:

    # receive public key of the server and deserialize IT
    data = recvData(mySocket)
    serverkey = pickle.loads(data)

    # receive public key of the client and deserialize IT
    data = recvData(mySocket)
    clientkey = pickle.loads(data)

    # hacking part for the server
    start = time.time()
    factors = factorint(serverkey[1])
    hackedP, hackedQ = list(factors.keys())
    hackedPhi = (hackedP - 1) * (hackedQ - 1)
    serverHackedD = pow(serverkey[0], -1, hackedPhi)
    end = time.time()
    print(f'Server Private Key = {[serverHackedD, serverkey[1]]}')
    print(f'time to break server key = {end-start} seconds')

    print('-------------------------------------------')

    start = time.time()
    # hacking part for the client
    factors = factorint(clientkey[1])
    hackedP, hackedQ = list(factors.keys())
    hackedPhi = (hackedP - 1) * (hackedQ - 1)
    clientHackedD = pow(clientkey[0], -1, hackedPhi)
    end = time.time()
    print(f'Client Private Key = {[clientHackedD, clientkey[1]]}')
    print(f'time to break client key = {end-start} seconds')

    while True:

        print('-------------------------------------------')

        # breaking client message
        data = recvData(mySocket)
        C = pickle.loads(data)
        hackedMessage = [pow(t1, serverHackedD, serverkey[1]) for t1 in C]
        print(f'client send to server : {deProcess(deGroupChars(hackedMessage))}')

        print('-------------------------------------------')

        # breaking server message
        data = recvData(mySocket)
        C = pickle.loads(data)
        hackedMessage = [pow(t1, clientHackedD, clientkey[1]) for t1 in C]
        print(f'server send to client: {deProcess(deGroupChars(hackedMessage))}')


except:
    # close the socket
    mySocket.close()

# close the socket
mySocket.close()
