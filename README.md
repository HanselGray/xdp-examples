# xdp-examples
Examples XDP program for presentation

# XDP Demo Test Setup

This setup allows you to test **two XDP use cases**:  
1. Counting packets on selected ports  
2. Dropping all UDP packets  

Your eBPF/XDP programs handle the logic — this is only the test environment.

---

## 1. Test Setup for Port-Counter XDP Program  
Ports being tracked: **52, 80, 443, 22, 25**

### Start Services

#### **HTTP on port 80**
```bash
sudo python3 -m http.server 80
```

#### HTTPS on port 443
```bash
openssl req -new -x509 -keyout key.pem -out cert.pem -nodes
openssl s_server -key key.pem -cert cert.pem -port 443
```

#### SMTP on port 25
```bash
sudo python3 -m smtpd -c DebuggingServer -n localhost:25
```
#### UDP listener on port 52
```bash
sudo nc -ul 52
```

### Generate Traffic

```bash
curl http://<server-ip>
curl -k https://<server-ip>
ssh <server-ip>
echo "test" | nc -u <server-ip> 52
echo "mail" | nc <server-ip> 25
```
## 2. Test Setup for UDP-Drop XDP Program

### Start a UDP listener
```bash
sudo nc -ul 9000
```

### Send UDP traffic (should be dropped after XDP is attached)
```bash
echo "hello" | nc -u <server-ip> 9000
```
