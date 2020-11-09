default:
	echo "No default make"

certs:
	mkdir -p var/https/certs
	openssl req -x509 -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=localhost" -newkey rsa:4096 -keyout var/https/certs/key.pem -out var/https/certs/cert.pem -days 3650 -nodes

run_local_stdout: build
	./melody -s

build:
	go build -ldflags="-s -w" -o melody
	sudo setcap cap_net_raw,cap_setpcap=ep ./melody

install: build
	mkdir /opt/melody
	ln -rs ./melody /opt/melody/
	cp ./config.yml.sample /opt/melody/config.yml
	cp ./filter.bpf.sample /opt/melody/filter.bpf
	echo "Don't forget to update /opt/melody/config.yml and /opt/melody/filter.bpf"

supervisor:
	sudo ln -rs ./etc/melody.conf /etc/supervisor/conf.d/
	sudo supervisorctl reload
	sudo supervisorctl status all

enable:
	sudo ln -rs ./etc/melody.service /etc/systemd/system/melody.service
	sudo systemctl daemon-reload && sudo systemctl enable melody
	sudo systemctl status melody
