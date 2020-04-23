default:
	echo "No default make"

install:
	go build -ldflags="-s -w" -o pinknoise
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