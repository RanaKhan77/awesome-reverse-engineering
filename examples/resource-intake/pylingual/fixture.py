"""Self-authored PyLingual fixture with branch, loop, exception, and comprehension behavior."""


def classify(n):
    if n < 0:
        return "negative"
    if n == 0:
        return "zero"
    return "even" if n % 2 == 0 else "odd"


def checksum(data):
    total = 0
    for index, value in enumerate(data):
        if value == 0:
            continue
        total = (total * 31 + value + index) % 65521
    return total


def parse_port(text):
    try:
        port = int(text)
    except ValueError:
        return -1
    if not 0 < port < 65536:
        return -2
    return port


def squares(limit):
    return [value * value for value in range(limit) if value % 3 != 0]


def label(name, count):
    return f"{name}:{count:03d}"
