to RUN the project follow the next instructions:
------------------------------------------------
1. edit the number of bits used for the key generation in the file named "num_of_bits.txt" where the minimum safe value is 27 bits and this value is calculated from the max possible number to be encrypted and the max number can be calculated as follows:
maxNumber = 36 * (37 ** 4) + 36 * (37 ** 3) + 36 * (37 ** 2) + 36 * (37 ** 1) + 36
and it can happen when we send 5 concurrent white spaces, so any number less than 27 bits isn't accepted

2. make sure these modules is installed:
-> pickle
-> pycrypto
-> pycryptodome
-> socket
-> sympy

3. run these python scripts in order, each script on its own terminal
	a. server.py
	b. client.py
	c. hacker.py

4. wait for some time till "hacker.py" terminal could break the private keys of the both client and server, and it will be printed on the hacker terminal when it could break the key and get the private key

5. enjoy chatting and watch hacker could see the actual messages

-----------------------------------------------
note: I used pycharm to make and run the project, that's why there's a directory called ".idea" and "venv" and I am using conda python interperter for this project, that's why the dependecies wouldn't appear in this project settings.
note: I made a function to factorize numbers but it took so long time, so I used function called "factorint" from sympy library, you should see a function called "factorizePrimeNum" in hacker module but it's not used as it's taking so long time to factorize numbers