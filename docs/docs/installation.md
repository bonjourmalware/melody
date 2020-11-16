To install Melody, use `make install` or enter the following commands :

```bash
go build -ldflags="-s -w -extldflags=-static" -o melody
sudo setcap cap_net_raw,cap_setpcap=ep ./melody

mkdir /opt/melody
ln -s "$(pwd)/melody" /opt/melody/
ln -s "$(pwd)/config.yml" /opt/melody/config.yml
ln -s "$(pwd)/filter.bpf" /opt/melody/filter.bpf
ln -s "$(pwd)/rules" /opt/melody/rules

echo "> Setting listening interface to \"$(route | grep '^default' | grep -o '[^ ]*$')\""
sed -i "s/# listen.interface: \"lo\"/listen.interface: \"$(route | grep '^default' | grep -o '[^ ]*$')\"/g" /opt/melody/config.yml
echo
echo -n "Current listening interface :\n\t"
grep listen.interface /opt/melody/config.yml

echo "Current BPF is '$(cat /opt/melody/filter.bpf)'"

# Don't forget to filter the noise by editing filter.bpf
```

## Systemd

You can tweak the provided service file to use Melody with `systemd`.

The file can be found in `$melody/etc/melody.service`.

!!! Example
    ```service
    [Unit]
    Description=Melody sensor
    After=network-online.target
    
    [Service]
    Type=simple
    WorkingDirectory=/opt/melody
    ExecStart=/opt/melody/melody
    Restart=on-failure
    # User=melody
    # Groupd=melody
    
    [Install]
    WantedBy=multi-user.target
    ```

Install it with :

```bash
make service
```

or

```bash
sudo ln -s "$(pwd)/etc/melody.service" /etc/systemd/system/melody.service
sudo systemctl daemon-reload
sudo systemctl enable melody
sudo systemctl status melody
```

## Supervisord

You can also tweak the provided configuration file to use Melody with `supervisord`.

The file can be found in `$melody/etc/melody.conf`.

!!! Example
    ```init
    [program:melody]
    command=/opt/melody/melody
    directory=/opt/melody
    stdout_logfile=/opt/melody/melody.out
    stderr_logfile=/opt/melody/melody.err
    autostart=true
    autorestart=true
    stopasgroup=true
    killasgroup=true
    ```

Install it with :

```bash
make supervisor
```

or

```bash
sudo ln -s $(pwd)/etc/melody.conf /etc/supervisor/conf.d/melody.conf
sudo supervisorctl reload
sudo supervisorctl status all
```

## Uninstall
Uninstall by removing log directories (default `$melody/logs`), service files (`/etc/systemd/system/melody.service` and `/etc/supervisor/conf.d/melody.conf`) and Melody home directory (default `/opt/melody`).

!!! Example
    Uncomment and use these command carefully.
    ```bash
    # sudo systemctl stop melody && rm /etc/systemd/system/melody.service
    # sudo supervisorctl stop melody && rm /etc/supervisor/conf.d/melody.conf
    # rm -rf /opt/melody
    ```
    
    !!! Danger
        Keep in mind that removing Melody's home directory will most likely remove its logs directory as well. All log data might be lost.
