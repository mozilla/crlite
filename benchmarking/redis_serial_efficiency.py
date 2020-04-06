import redis
from timeit import default_timer as timer


def make_serial(*, num, serialLen=20):
    s = f"{num:X}"
    return (serialLen - len(s)) * "0" + s


def calculate_bytes_per_cert(
    r, *, addFunc, countFunc, key="test", serialLen, numSerials
):
    r.delete(key)

    start = timer()
    for x in range(0, numSerials):
        addFunc(key, x)

    end = timer()

    count = countFunc(key)
    if count != numSerials:
        raise Exception(f"mismatch {count} != {numSerials}")

    sz = r.memory_usage(key, 0)
    print(
        f"Serial Len={serialLen} number of Serials={numSerials:,} "
        + f"total bytes={format_bytes(sz)} bytes/cert={sz / numSerials} "
        + f"insertionTime/cert={(end - start) / numSerials * 1000}ms"
    )

    r.delete(key)


def format_bytes(size):
    power = 2 ** 10
    n = 0
    power_labels = {0: "", 1: "kilo", 2: "mega", 3: "giga", 4: "tera"}
    while size > power:
        size /= power
        n += 1
    return size, power_labels[n] + "bytes"


def main():
    r = redis.Redis(host="localhost")

    # Sorted sets
    # def addFunc(key,value): r.zadd(key, {make_serial(num=value): 0})
    # def countFunc(key): return r.zcount(key, 0, 0)

    # Unsorted sets
    def addFunc(key, value):
        r.sadd(key, make_serial(num=value))

    def countFunc(key):
        return r.scard(key)

    calculate_bytes_per_cert(
        r, addFunc=addFunc, countFunc=countFunc, serialLen=20, numSerials=100
    )
    calculate_bytes_per_cert(
        r, addFunc=addFunc, countFunc=countFunc, serialLen=20, numSerials=1_000
    )
    calculate_bytes_per_cert(
        r, addFunc=addFunc, countFunc=countFunc, serialLen=20, numSerials=10_000
    )
    calculate_bytes_per_cert(
        r, addFunc=addFunc, countFunc=countFunc, serialLen=20, numSerials=100_000
    )
    calculate_bytes_per_cert(
        r, addFunc=addFunc, countFunc=countFunc, serialLen=20, numSerials=1_000_000
    )


if __name__ == "__main__":
    main()
