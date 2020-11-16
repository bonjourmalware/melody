## Go version
Minimum supported Go version is 1.11, but we recommend using Go 1.13+ since that's the lowest version we're using for testing.

## libpcap

You'll need the `libpcap` C headers to build the program.

Install it with :

```
sudo apt update
sudo apt install libpcap-dev
```

!!! Note
    You won't need them if you're using Docker or a pre-compiled release binary.

## HTTPS dummy server
You'll need TLS certificates in order to use the built-in dummy HTTPS server.

Use one of these commands to generate them for you :

```
make certs
```

or

```
mkdir -p var/https/certs
openssl req -x509 -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=localhost" -newkey rsa:4096 -keyout var/https/certs/key.pem -out var/https/certs/cert.pem -days 3650 -nodes
```

!!! Warning
    Using these commands will overwrite any `cert.pem` or `key.pem` file already present in `$melody/var/https/certs/` 

!!! Tip
    You can also use your own by putting the `key.pem` and `cert.pem` in `$melody/var/https/certs`. **Keep in mind that it might be used by attackers to fingerprint or gain information on your infrastructure.**
