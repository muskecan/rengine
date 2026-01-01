#!/bin/bash

# Fix DNS resolution - keep Docker DNS for internal, add public DNS for external
cat > /etc/resolv.conf << EOF
nameserver 127.0.0.11
nameserver 1.1.1.1
nameserver 8.8.8.8
options ndots:0
EOF

python3 manage.py migrate

exec "$@"
