default:
	echo "No default make"

certs:
	mkdir -p var/https/certs
	openssl req -x509 -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=localhost" -newkey rsa:4096 -keyout var/https/certs/key.pem -out var/https/certs/cert.pem -days 3650 -nodes

run_local_stdout: build
	./pinknoise -n "" -N "" -s

build:
	go build -ldflags="-s -w" -o pinknoise
	sudo setcap cap_net_raw,cap_setpcap=ep ./pinknoise

install: build
	mkdir /opt/pinknoise
	ln -rs ./pinknoise /opt/pinknoise/
	cp ./config.yml.sample /opt/pinknoise/config.yml
	cp ./filter.bpf.sample /opt/pinknoise/filter.bpf
	echo "Don't forget to update /opt/pinknoise/config.yml and /opt/pinknoise/filter.bpf"

supervisor:
	sudo ln -rs ./etc/pinknoise.conf /etc/supervisor/conf.d/
	sudo supervisorctl reload
	sudo supervisorctl status all

enable:
	sudo ln -rs ./etc/pinknoise.service /etc/systemd/system/pinknoise.service
	sudo systemctl daemon-reload && sudo systemctl enable pinknoise
	sudo systemctl status pinknoise
