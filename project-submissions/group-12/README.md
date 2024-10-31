# CS431 : Security Guard

## Team Members:
- Chakradhar Basani
- Koleti Eswar Sai Ganesh
- Sriman Reddy
- Manav Jain
- Nakka Naga Bhuvith
- Pavan Deekshith
- Venigalla Harshith

### Installing `libssl-dev` Library

Before running the program, ensure that the `libssl-dev` library is installed on your system. Here are the instructions for different operating systems:

##### Linux
```sh
sudo apt-get update
sudo apt-get install -y libssl-dev
```

##### Mac
```sh
brew install openssl
```

### Setting up the machine

If the client (logappend, logread) and server programs are run on the same machine, replace <ip_address> with 127.0.0.1 in the respective lines of code in the logappend and logread code files.

If the client and server programs are run on different machines, replace <ip_address> in the logappend and logread code files with the IP address of the server machine

```cpp
 if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        cout << "Invalid address/ Address not supported" << endl;
        return 255;
    }
```

The IP address of the server machine can be obtained using the following commands:

##### Linux
```
ip a
```

##### Mac
```
ipconfig getifaddr en0
```

- Invoke Makefile to run the program.



#### Usage of logread and loappend commands : 
https://github.com/IITGN-CS431/problems/blob/main/securityguard/EXAMPLES.md  

#### References :
RSA algorithm : https://www.geeksforgeeks.org/rsa-algorithm-cryptography/ 
