import hashlib;
import itertools;

BLOOM_FILTER_SIZE = 64;             # Length of each bloom filter table

hashFuncs = [];

passwd = {};        # dictionary of usernames and password bloom filters

def insert(username, password1, password2):
    if username in passwd:
        #print "Username already present. Choose another";
        return False;
    bloomHashes = [];
    for idx, hashFunc in enumerate(hashFuncs):
        bloomHash = [0] * BLOOM_FILTER_SIZE;
        bloomHash[hashFunc(password1)] = 1;
        bloomHash[hashFunc(password2)] = 1;
        bloomHashes.append(bloomHash);
    passwd[username] = bloomHashes;
    return True;

def checkLogin(username, password):
    if username not in passwd:
        #print "Username or password combination incorrect";
        return False;
    origBloomHashes = passwd[username];
    for idx, hashFunc in enumerate(hashFuncs):
        newBloomHash = hashFunc(password);
        if (origBloomHashes[idx][newBloomHash] == 0):
            #print "Username or password combination incorrect";
            return False;
    return True;

def hashFunc1(word):
    hash_object = hashlib.md5(bytes(word));
    return int(hash_object.hexdigest(), 16) % BLOOM_FILTER_SIZE;

def hashFunc2(word):
    hash_object = hashlib.sha1(bytes(word));
    return int(hash_object.hexdigest(), 16) % BLOOM_FILTER_SIZE;
        
def hashFunc3(word):
    hash_object = hashlib.sha224(bytes(word));
    return int(hash_object.hexdigest(), 16) % BLOOM_FILTER_SIZE;

def hashFunc4(word):
    hash_object = hashlib.sha256(bytes(word));
    return int(hash_object.hexdigest(), 16) % BLOOM_FILTER_SIZE;

def hashFunc5(word):
    hash_object = hashlib.sha384(bytes(word));
    return int(hash_object.hexdigest(), 16) % BLOOM_FILTER_SIZE;

def hashFunc6(word):
    hash_object = hashlib.sha512(bytes(word));
    return int(hash_object.hexdigest(), 16) % BLOOM_FILTER_SIZE;

def init():
    hashFuncs.extend([hashFunc1, hashFunc2, hashFunc3, hashFunc4, hashFunc5, hashFunc6]);

def tryBreaking(username, maxLen):
    for strLen in range(1, maxLen+1):
        print "Trying Length " + str(strLen);
        for i in itertools.product("abcdefghijklmnopqrstuvwxyz1234567890",repeat=strLen):
            combination  = ''.join(i);
            if checkLogin(username, combination) is True:
                print username + " " + combination + " logged in successfully"; 

def main():
    init();
    while True:
        inp = input("Enter command: ");
        if inp is -1:
            break;
        if inp is 0:
            print "-1 -> exit, 0 -> help, 1 -> add password, 2 -> login, 3 -> print passwd dict, 4 -> try to break";
        elif inp is 1:
            username = raw_input("Enter username: ");
            password1 = raw_input("Enter password 1: ");
            password2 = raw_input("Enter password 2: ");
            if insert(username, password1, password2) is True:
                print "User added successfully!";
            else:
                print "User was not added";
        elif inp is 2:
            username = raw_input("Enter username: ");
            password = raw_input("Enter password: ");
            if checkLogin(username, password) is True:
                print "Login Successful";
            else:
                print "Login Failed";
        elif inp is 3:
            print passwd;
        elif inp is 4:
            username = raw_input("Enter username: ");
            maxLen = input("Enter maximum length: ");
            tryBreaking(username, maxLen);
        else:
            print "Wrong input!!!";



if __name__ == "__main__":
    main();
