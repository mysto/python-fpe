from ff3 import FF3Cipher
import string, random
import time


def timeit(f):
    def timed(*args, **kw):
        ts = time.time()
        result = f(*args, **kw)
        te = time.time()

        print(f'func:{f.__name__} took: {te - ts:2.4f}')
        return result

    return timed


@timeit
def test_encrypt(plaintext):
    key = "EF4359D8D580AA4F7F036D6F04FC6A94"
    tweak = "D8E7920AFA330A73"
    for txt in plaintext:
        c = FF3Cipher(key, tweak, 62)
        s = c.encrypt(txt)


def test_performance(runs=100_000):
    plaintext = []
    for i in range(runs):
        plaintext.append(''.join(random.choices(string.ascii_uppercase + string.digits, k=8)))
    test_encrypt(plaintext)


if __name__ == '__main__':
    test_performance()
