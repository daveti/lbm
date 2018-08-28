# BT stack protection for HCI layer
# Aug 28, 2018
# daveti

# Start lbmtool
(
	((bt.hci.type == 1) && (bt.hci.len < 3)) ||
	((bt.hci.type == 2) && (bt.hci.len < 4)) ||
	((bt.hci.type == 3) && (bt.hci.len < 3)) ||
	((bt.hci.type == 4) && (bt.hci.len < 2))
)
# End lbmtool
