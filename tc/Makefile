P4C = p4c-bm2-ss
P4C_ARGS += --p4runtime-files $(basename $@).p4.p4info.txt
P4C_ARGS += --emit-externs

#export BMV2_SWITCH_EXE=/home/montimage/hn/behavioral-model/targets/simple_switch/.libs/simple_switch

%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $@ $<
	
all: tc.json
	echo "Done"

clean:
	sudo mn -c
	rm tc.p4.p4info.txt tc.json topos/*.pdf
	sudo rm -rf pcaps logs __pycache__
