all:
	echo "Done"

clean:
	rm tc.p4.p4info.txt tc.json
	sudo rm -rf pcaps logs


install:
	sudo mkdir /opt/ptp4l/
	sudo cp master.cfg slave.cfg /opt/ptp4l
	sudo cp ptp4l-master.service /etc/systemd/system/
	sudo cp ptp4l-slave.service  /etc/systemd/system/
	sudo systemctl daemon-reload
	

install-linuxptp
	git clone https://github.com/richardcochran/linuxptp.git
	cd linuxptp && make && sudo make install