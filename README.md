PTP time synchronization over 5G network.

The testbed includes 3 transparent clocks:

- TC 0
- TC 1
- logical TC which represents the whole 5G network (from UE to UPF) as a transparent clock. It is a P4-based TC consisting of:
    - nw-tt: network side time translator
    - ds-tt: device side time translator


<img src="img/testbed.jpg" />