
from ff3 import FF3Cipher
import string, random
import time

def timeit(f):

    def timed(*args, **kw):

        ts = time.time()
        result = f(*args, **kw)
        te = time.time()

        print( 'func:%r args:[%r, %r] took: %2.4f sec' % \
          (f.__name__, args, kw, te-ts))
        return result

    return timed

@timeit
def test_performance(runs=100000):

        key = "EF4359D8D580AA4F7F036D6F04FC6A94"
        tweak = "D8E7920AFA330A73"
        plaintext = []
        for i in range(runs):
            plaintext.append(''.join(random.choices(string.ascii_uppercase + string.digits, k=8)))
        for i in range(runs):
            c = FF3Cipher(key, tweak, 62)
            s = c.encrypt(plaintext[i])

if __name__ == '__main__':
   test_performance()

