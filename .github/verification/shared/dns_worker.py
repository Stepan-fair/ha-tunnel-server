"""Private resolver child protocol. Only the parent supplies arguments."""
import json
import socket
import sys


def main():
    try:
        host, port, family = json.loads(sys.argv[1])
        rows = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
        if len(rows) > 256:
            raise ValueError()
        raw = json.dumps(rows, separators=(',', ':')).encode('ascii')
        if len(raw) > 32768:
            raise ValueError()
        sys.stdout.buffer.write(raw)
    except Exception:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
