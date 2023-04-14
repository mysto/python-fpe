import sys
from ff3 import FF3Cipher

def encrypt():
    c = FF3Cipher(sys.argv[1], sys.argv[2])
    print(c.encrypt(sys.argv[3]))

def decrypt():
    c = FF3Cipher(sys.argv[1], sys.argv[2])
    print(c.decrypt(sys.argv[3]))

#if __name__ == '__main__':
#    sys.exit(main()) 
