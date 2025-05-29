# install ptp

all:
	echo "Done"

install:
	sudo mkdir -p /opt/ptp4l/
	sudo cp collector.py /opt/ptp4l
	sudo cp ptp4l-collector.service /etc/systemd/system/
	sudo systemctl daemon-reload
