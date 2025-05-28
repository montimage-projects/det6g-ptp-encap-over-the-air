# Install linuxptp

```bash
git clone https://github.com/richardcochran/linuxptp.git
cd linuxptp
make
sudo make install
```

# Setup Slave, Master services:

- create folder `/opt/ptp4l`
- copy the *.cfg files to that folder
- copy the *.service files to `/etc/systemd/system/`
- run `sudo systemctl daemon-reload`
- then, depending on slave or master you want to execute, for example:
   - to start: `sudo systemctl start ptp4l-master.service` 
   - to get status: `sudo systemctl status ptp4l-master.service`
   - to start at login: `sudo systemctl enable ptp4l-master.service`