P4C = p4c-bm2-ss
P4C_ARGS += --p4runtime-files $(basename $@).p4.p4info.txt
P4C_ARGS += --emit-externs


# compile P4 program
%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $@ $<
	
all: tc.json
	echo "Done"

clean:
	rm tc.p4.p4info.txt tc.json
	sudo rm -rf pcaps logs


install: tc.json
	sudo mkdir /opt/ptp4l/
	sudo cp tc.json *.sh /opt/ptp4l
	sudo cp ptp4l-nw-tt.service /etc/systemd/system/
	sudo cp ptp4l-ds-tt.service /etc/systemd/system/
	sudo systemctl daemon-reload
	
run-nw-tt: tc.json
	bash -x ./run-ptp-nw-tt.sh
	
run-ds-tt: tc.json
	bash -x ./run-ptp-ds-tt.sh