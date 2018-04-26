from enum import Enum

class Type(Enum):
    TY_INT_32 = 1
    TY_STRING = 2

class Symbol(object):
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

    "devpath" :                SymbolString(ty=Type.TY_STRING, length="lbm_usb_get_devpath_len", load="lbm_usb_devpath_load_8_bytes"),
    "manufacturer" :           SymbolString(ty=Type.TY_STRING, length="lbm_usb_get_manufacturer_len", load="lbm_usb_manufacturer_load_8_bytes"),
    "product" :                SymbolString(ty=Type.TY_STRING, length="lbm_usb_get_product_len", load="lbm_usb_product_load_8_bytes"),
    "serial" :                 SymbolString(ty=Type.TY_STRING, length="lbm_usb_get_serial_len", load="lbm_usb_serial_load_8_bytes"),
}

symbol_table = {
    "usb" : usb_symbol_table,
    "bt" : {}
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

    if not isinstance(level, Symbol):
        return None
    else:
        return level
