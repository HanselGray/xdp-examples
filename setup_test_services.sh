#!/bin/bash
# Lightweight test services for ports 80, 443, 25, and 52

set -e

echo "Starting HTTP on port 80..."
sudo python3 -m http.server 80 &
HTTP_PID=$!

echo "Generating self-signed certificate for HTTPS..."
openssl req -new -x509 -keyout key.pem -out cert.pem -nodes -days 365 -subj "/CN=localhost"

echo "Starting HTTPS on port 443..."
openssl s_server -key key.pem -cert cert.pem -port 443 &
HTTPS_PID=$!

echo "Starting SMTP debug server on port 25..."
sudo python3 -m smtpd -c DebuggingServer -n localhost:25 &
SMTP_PID=$!

echo "Starting UDP listener on port 52..."
sudo nc -ul 52 &
UDP_PID=$!

echo "All services started!"
echo "HTTP PID: $HTTP_PID"
echo "HTTPS PID: $HTTPS_PID"
echo "SMTP PID: $SMTP_PID"
echo "UDP PID: $UDP_PID"

echo "Press Ctrl+C to stop all services."

# Trap Ctrl+C to kill background processes
trap "echo 'Stopping services...'; kill $HTTP_PID $HTTPS_PID $SMTP_PID $UDP_PID; exit 0" SIGINT

# Keep script running
while true; do sleep 1; done
