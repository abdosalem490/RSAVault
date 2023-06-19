import socket
import struct
import time

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


# this is the least number of bits needed for encryption/decryption to be done correctly
# leastNumOfBits = number.size(36 * (37 ** 4) + 36 * (37 ** 3) + 36 * (37 ** 2) + 36 * (37 ** 1) + 36)

f = open("num_of_bits.txt", "r")
num_of_bits = int(f.read())

print('-------------------------------------------')
print('CLIENT')
print('-------------------------------------------')

start = time.time()
# calculating the main parameters of RSA algorithm
p = number.getPrime(num_of_bits)
q = number.getPrime(num_of_bits)
n = p * q
phi = (p - 1) * (q - 1)
e = generateEval(p, q)
d = pow(e, -1, phi)
end = time.time()
print(f'time to generate public and private keys = {end-start} seconds')

# generating both public and private keys
PublicKey = [e, n]
PrivateKey = [d, n]

print(f'Public Key = {PublicKey}')
print(f'Private Key = {PrivateKey}')


# getting hostname
host = socket.gethostname()

# the port that communication will happen through
portNum = 12345

# Creating a socket
mySocket = socket.socket()

# the port isn't created yet, as I am a server
mySocket.connect((host, portNum))

try:

    # serialize the public key and send it
    data = pickle.dumps(PublicKey)
    mySocket.send(struct.pack('>I', len(data)))
    mySocket.send(data)

    # receive public key of the server and deserialize IT
    data = recvData(mySocket)
    serverkey = pickle.loads(data)


    # the port is already open, so I am a client
    while True:

        print('-------------------------------------------')

        # take input from the user
        message = input(" -> ")

        # end the connection
        if message == 'bye':
            break

        #encoding the message
        start = time.time()
        processedText = preProcessText(message)
        groupedText = groupChars(processedText)
        # encryption
        C = [pow(M, serverkey[0], serverkey[1]) for M in groupedText]
        end = time.time()
        print(f'time to encrypt message = {end - start} seconds')

        # send message to the server
        data = pickle.dumps(C)
        mySocket.send(struct.pack('>I', len(data)))
        mySocket.send(data)

        print('-------------------------------------------')

        # receiving data from the server
        data = recvData(mySocket)

        if not data:
            # if the connection is closed then end the program
            break

        # decrypt the message
        C = pickle.loads(data)
        start = time.time()
        M = [pow(t1, PrivateKey[0], PrivateKey[1]) for t1 in C]

        # decoding the message
        degrouped = deGroupChars(M)
        print("received from the server:", end=" ")

        # printing the received message
        print(deProcess(degrouped))

        end = time.time()
        print(f'time to decrypt message = {end - start} seconds')

except:
    # close the socket
    mySocket.close()

# close the socket
mySocket.close()
