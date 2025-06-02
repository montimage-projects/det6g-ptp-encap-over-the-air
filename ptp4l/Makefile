# install ptp

all:
	echo "Done"

install:
	sudo mkdir -p /opt/ptp4l/
	sudo cp * /opt/ptp4l
	sudo cp *.service  /etc/systemd/system/
	sudo systemctl daemon-reload

install-linuxptp:
	git clone https://github.com/richardcochran/linuxptp.git
	cd linuxptp && make && sudo make install