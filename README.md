# pylstar-quic

State Machine Inference Model for gQUIC

### How to run Sample Handshake
1. local-server
```
$ sudo python3 src/learner/localhost_test.py 
```
2. public web-server(`www.litespeedtech.com`)
```
$ sudo python3 src/learner/litespeed_test.py
```

## How to run learner
```
$ sudo python3 src/learner/learn_server.py [servername] [dotfilename].dot
```
1. local-server
```
$ sudo python3 src/learner/learn_server.py localhost gQUIC43_localhost.dot
```

## How to run fuzzer
```
$ python3 src/learner/FuzzTesting.py [dotfilename].dot
```
