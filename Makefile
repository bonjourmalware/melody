.PHONY: docs

default:
	echo "No default make"

certs:
	mkdir -p var/https/certs
	openssl req -x509 -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=localhost" -newkey rsa:4096 -keyout var/https/certs/key.pem -out var/https/certs/cert.pem -days 3650 -nodes

default_rules:
	ln -rs ./rules/rules-available/* ./rules/rules-enabled/

docker_build:
	docker build . -t melody

docker_run:
	docker run \
		--net=host \
		-e "MELODY_CLI=$MELODY_CLI" \
		--mount type=bind,source="$(pwd)"/filter.bpf,target=/app/filter.bpf,readonly \
		--mount type=bind,source="$(shell pwd)"/config.yml,target=/app/config.yml,readonly \
		--mount type=bind,source="$(shell pwd)"/logs,target=/app/logs/ \
		melody

docker: docker_build docker_run

docs:
	cd docs/; mkdocs gh-deploy

run_local_stdout: build
	./melody -s

build:
	go build -ldflags="-s -w" -o melody
	sudo setcap cap_net_raw,cap_setpcap=ep ./melody

install:
	@echo "> Setting listening interface to \"$(shell route | grep '^default' | grep -o '[^ ]*$$')\""
	sed -i "s/# listen.interface: \"lo\"/listen.interface: \"$(shell route | grep '^default' | grep -o '[^ ]*$$')\"/g" /opt/melody/config.yml
	@echo
	@echo -n "Current listening interface :\n\t"
	@grep listen.interface /opt/melody/config.yml

	@echo "Current BPF is '$(shell cat /opt/melody/filter.bpf)'"

	# Don't forget to filter the noise by editing filter.bpf

supervisor:
	sudo ln -s $(shell pwd)/etc/melody.conf /etc/supervisor/conf.d/
	sudo supervisorctl reload
	sudo supervisorctl status all

service:
	sudo ln -s $(shell pwd)/etc/melody.service /etc/systemd/system/melody.service
	sudo systemctl daemon-reload && sudo systemctl enable melody
	sudo systemctl status melody
