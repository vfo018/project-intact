This folder contains manifest files which are used to deploy MMT + 5Greplay at a worker node inside the Kubernetes infrastructure of Ubitech.

## Usage:

### 1. Access to the worker node using VPN


- start up the vpn client service:
```bash
$ sudo systemctl start tailscaled.service
```

- login to the VPN using `auth-key` given by Ubitech:
```bash
$ sudo tailscale up --login-server=https://hs.ubitech.eu --auth-key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --json
{
  "BackendState": "Running"
}
$ tailscale status
100.64.0.69     mmt                  nsit-intact  linux   -
100.64.0.64     nsit-intact-master   nsit-intact  linux   -
100.64.0.63     nsit-intact-w0       nsit-intact  linux   -
```

**NOTE**: as the worker node's IP is `100.64.0.63`, mmt-operator GUI is accessible at `http://100.64.0.63:30010`

- connect to the worker node using SSH:
```
$ ssh -i .ssh/id_intact montimage@100.64.0.64
```

### 2. Generate malicious traffic to the AMF

```bash
root@5greplay-8479d8b747-dbscr:/opt/mmt/5greplay# ./5greplay replay -t pcap/oai.pcap -Xforward.target-protocols=SCTP -Xforward.target-ports=38412 -Xforward.target-hosts=10.100.50.248 -Xforward.nb-copies=1 -Xforward.default=DROP -Xforward.bind-ip=10.100.50.249
mmt-5greplay: 5Greplay v0.0.8-86f2074 using DPI v1.7.10 (6dc7907) is running on pid 584
mmt-5greplay: Overridden value of configuration parameter 'forward.nb-copies' by '1'
mmt-5greplay: Overridden value of configuration parameter 'forward.default' by '1'
mmt-5greplay: Overridden value of configuration parameter 'forward.bind-ip' by '10.100.50.249'
mmt-5greplay: Binded successfully socket to 10.100.50.249:0 using SCTP.
mmt-5greplay: MMT-5Greplay 0.0.8 (86f2074 - Feb 19 2024 15:08:42) is verifying 16 rules having 11 proto.atts using the main thread
mmt-5greplay: Registered attribute to extract: 178.13
mmt-5greplay: Registered attribute to extract: 304.2
mmt-5greplay: Registered attribute to extract: 304.5
mmt-5greplay: Registered attribute to extract: 376.2
mmt-5greplay: Registered attribute to extract: 624.6
mmt-5greplay: Registered attribute to extract: 700.2
mmt-5greplay: Registered attribute to extract: 903.1
mmt-5greplay: Registered attribute to extract: 903.4
mmt-5greplay: Registered attribute to extract: 903.4099
mmt-5greplay: Registered attribute to extract: 904.2
mmt-5greplay: Registered attribute to extract: 904.3

```

### 3. Results

These screenshorts of the test performed on June 19, 2025:

- execution log of 5Greplay

<img src=img/5greplay.png>

- AMF log

<img src=img/amf-log.png>

- Security alerts

<img src=img/security-alerts.png>
