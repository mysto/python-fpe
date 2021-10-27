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
def test_encrypt(plaintexts):
    key = "EF4359D8D580AA4F7F036D6F04FC6A94"
    tweak = "D8E7920AFA330A73"
    for pt in plaintexts:
        c = FF3Cipher(key, tweak, 62)
        s = c.encrypt(pt)


def test_performance(runs=100_000):
    plaintexts = []
    for i in range(runs):
        plaintexts.append(''.join(random.choices(string.ascii_uppercase + string.digits, k=8)))
    test_encrypt(plaintexts)


if __name__ == '__main__':
    test_performance()
