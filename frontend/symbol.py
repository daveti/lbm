from enum import Enum

class Type(Enum):
    TY_INT_1 = 1
    TY_INT_8 = 2
    TY_INT_16 = 3
    TY_INT_32 = 4
    TY_INT_64 = 5
    TY_STRING = 6

class LBMType(object):
    pass

class Number(LBMType):
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "%d" % self.value

class Symbol(LBMType):
    pass

class SymbolContext(Symbol):
    def __init__(self, ty, offset):
        self.ty = ty
        self.offset = offset

class SymbolHelper(Symbol):
    def __init__(self, ty, name):
        self.ty = ty
        self.name = name

class SymbolString(Symbol):
    def __init__(self, ty, length, load):
        self.ty = ty
        self.length = length
        self.load = load

usb_symbol_table = {
    "pipe" :                   SymbolContext(ty=Type.TY_INT_32, offset=0),
    "stream_id" :              SymbolContext(ty=Type.TY_INT_32, offset=4),
    "status" :                 SymbolContext(ty=Type.TY_INT_32, offset=8),
    "transfer_flags" :         SymbolContext(ty=Type.TY_INT_32, offset=12),
    "transfer_buffer_length" : SymbolContext(ty=Type.TY_INT_32, offset=16),
    "actual_length" :          SymbolContext(ty=Type.TY_INT_32, offset=20),
    "setup_packet" :           SymbolContext(ty=Type.TY_INT_32, offset=24),
    "start_frame" :            SymbolContext(ty=Type.TY_INT_32, offset=28),
    "number_of_packets" :      SymbolContext(ty=Type.TY_INT_32, offset=30),
    "interval" :               SymbolContext(ty=Type.TY_INT_32, offset=34),
    "error_count" :            SymbolContext(ty=Type.TY_INT_32, offset=38),

    "devnum" :                 SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_devnum"),
    "bcdUSB" :                 SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_bcdUSB"),
    "bDeviceClass" :           SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_bDeviceClass"),
    "bDeviceSubClass" :        SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_bDeviceSubClass"),
    "bDeviceProtocol" :        SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_bDeviceProtocol"),
    "bMaxPacketSize0" :        SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_bMaxPacketSize0"),
    "idVendor" :               SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_idVendor"),
    "idProduct" :              SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_idProduct"),
    "bcdDevice" :              SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_bcdDevice"),
    "iManufacturer" :          SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_iManufacturer"),
    "iProduct" :               SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_iProduct"),
    "iSerialNumber" :          SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_iSerialNumber"),
    "bNumConfigurations" :     SymbolHelper(ty=Type.TY_INT_32, name="lbm_usb_get_bNumConfigurations"),

    "devpath" :                SymbolString(ty=Type.TY_STRING, length="lbm_usb_get_devpath_len", load="lbm_usb_devpath_load_bytes_reg"),
    "manufacturer" :           SymbolString(ty=Type.TY_STRING, length="lbm_usb_get_manufacturer_len", load="lbm_usb_manufacturer_load_bytes_reg"),
    "product" :                SymbolString(ty=Type.TY_STRING, length="lbm_usb_get_product_len", load="lbm_usb_product_load_bytes_reg"),
    "serial" :                 SymbolString(ty=Type.TY_STRING, length="lbm_usb_get_serial_len", load="lbm_usb_serial_load_bytes_reg"),

    #data # requires load bytes
    #request # requires load bytes
}

bt_hci = {
    "len" :        SymbolContext(ty=Type.TY_INT_32, offset=0),
    "prio" :       SymbolContext(ty=Type.TY_INT_32, offset=4),

    "type" :       SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_get_pkt_type"),
    "event" : {
        "evt" :    SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_event_get_evt"),
        "plen" :   SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_event_get_plen"),
        #"data" # needs stack and manual ASM
    },
    "acl" : {
        "handle" : SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_acl_get_handle"),
        "flags" :  SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_acl_get_flags"),
        "dlen" :   SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_acl_get_dlen"),
        #"data" # needs stack and manual ASM
    },
    "sco" : {
        "handle" : SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_sco_get_handle"),
        "flags" :  SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_sco_get_flags"),
        "dlen" :   SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_sco_get_dlen"),
        #"data" # needs stack and manual ASM
    },
    "command" : {
        "ogf" :    SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_command_get_ogf"),
        "ocf" :    SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_command_get_ocf"),
        "plen" :   SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_command_get_plen"),
        #"data" # needs stack and manual ASM
    },
    "conn" : {
        "" :              SymbolHelper(ty=Type.TY_INT_1,  name="lbm_bluetooth_has_conn"),
        "dst" :           SymbolHelper(ty=Type.TY_INT_64, name="lbm_bluetooth_get_conn_dst"),
        "dst_type" :      SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_get_conn_dst_type"),
        "src" :           SymbolHelper(ty=Type.TY_INT_64, name="lbm_bluetooth_get_conn_src"),
        "src_type" :      SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_get_conn_src_type"),
        "state" :         SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_get_conn_state"),
        "mode" :          SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_get_conn_mode"),
        "type" :          SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_get_conn_type"),
        "role" :          SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_get_conn_role"),
        "key_type" :      SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_get_conn_key_type"),
        "auth_type" :     SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_get_conn_auth_type"),
        "sec_level" :     SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_get_conn_sec_level"),
        "io_capability" : SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_get_conn_io_capability"),
    },
}

bt_l2cap = {
    "cid" : SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_cid"),
    "len" : SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_len"),

    "conn" : {
        "dst" :           SymbolHelper(ty=Type.TY_INT_64, name="lbm_bluetooth_l2cap_get_conn_dst"),
        "dst_type" :      SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_conn_dst_type"),
        "src" :           SymbolHelper(ty=Type.TY_INT_64, name="lbm_bluetooth_l2cap_get_conn_src"),
        "src_type" :      SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_conn_src_type"),
        "state" :         SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_conn_state"),
        "mode" :          SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_conn_mode"),
        "type" :          SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_conn_type"),
        "role" :          SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_conn_role"),
        "key_type" :      SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_conn_key_type"),
        "auth_type" :     SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_conn_auth_type"),
        "sec_level" :     SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_conn_sec_level"),
        "io_capability" : SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_conn_io_capability"),
    },
    "sig" : {
        "cmd" : {
            "num" : SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_sig_cmd_num"),
            #code[i] lbm_bluetooth_l2cap_get_sig_cmd_code_idx # indexed needs manual ASM
            #id[i] lbm_bluetooth_l2cap_get_sig_cmd_id_idx
            #len[i] lbm_bluetooth_l2cap_get_sig_cmd_len_idx
            #data # need load bytes
        }
    },
    "conless" : {
        "psm" : SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_conless_psm"),
        #data # need load bytes
    },
    "le" : {
        "sig" : {
            "cmd": {
                "code" : SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_le_sig_cmd_code"),
                "id" : SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_le_sig_cmd_id"),
                "len" : SymbolHelper(ty=Type.TY_INT_32, name="lbm_bluetooth_l2cap_get_le_sig_cmd_len"),
                #data # need load bytes
            }
         }
    },
    "skb_len" :        SymbolContext(ty=Type.TY_INT_32, offset=0),
    "skb_prio" :       SymbolContext(ty=Type.TY_INT_32, offset=4),
    #"data" # need load bytes
}

bt_symbol_table = {
    "hci" : bt_hci,
    "l2cap" : bt_l2cap,
}

symbol_table = {
    "usb" : usb_symbol_table,
    "bt" : bt_symbol_table,
}

symbol_subsystem = {
    "usb" : 0,
    "bt.hci" : 1,
    "bt.l2cap" : 2,
    "nfc" : 3,
}

def lookup_symbol(symbol):
    parts = symbol.split(".")

    if len(parts) == 0:
        return None

    level = symbol_table
    for obj in parts:
        if not isinstance(level, dict):
            return None

        if obj not in level:
            return None

        level = level[obj]

    symbol_result = None
    subsystem = None

    for k,v in symbol_subsystem.iteritems():
        if symbol.startswith(k):
            subsystem = v
            break

    if isinstance(level, dict) and "" in level:
        symbol_result = level[""]

    if isinstance(level, Symbol):
        symbol_result = level

    # annotate the symbol result with the subsystem
    if symbol_result:
        assert subsystem is not None
        symbol_result.subsystem = subsystem

    return symbol_result
