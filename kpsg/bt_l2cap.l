# BT stack protection for L2CAP layer
# Aug 28, 2018
# daveti

# Start lbmtool
(
	((bt.l2cap.skb_len < 4)) ||
	((bt.l2cap.cid == 1) && (bt.l2cap.len < 8)) ||
	((bt.l2cap.cid == 2) && (bt.l2cap.len < 6)) ||
	((bt.l2cap.cid == 5) && (bt.l2cap.len < 8))
)
# End lbmtool
