# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # # List of settings that a user can set for this High Level Analyzer.
    # my_string_setting = StringSetting()
    # my_number_setting = NumberSetting(min_value=0, max_value=100)
    process_signal_setting = ChoicesSetting(choices=('TDI', 'TDO'))

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'dmi_access_out': {
            'format': 'DMI Access, {{data.op}} {{data.address}}={{data.data}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self._last_ir = 0x0

        # print("Settings:", self.my_string_setting,
        #       self.my_number_setting, self.my_choices_setting)

    def parse_bitfields(self, b: bytes, abits: int):
        # Convert the bytes into an integer treating the first byte of b as the least significant byte.
        # In other words, 'little' ensures the bit 0 will correspond to the lowest-order bit of b[0].
        val = int.from_bytes(b, 'big')
        # print(hex(val))
        
        # Extract OP (lowest 2 bits)
        op = val & 0b11
        val >>= 2  # Move past OP
        
        # Extract Data (next 32 bits)
        data_field = val & ((1 << 32) - 1)
        val >>= 32  # Move past Data
        
        # Extract Address (next abits bits)
        address = val & ((1 << abits) - 1)
        # No need to shift after since no more fields
        
        return op, data_field, address

    def decode(self, frame: AnalyzerFrame):
        if frame.type == 'Ex1IR':
            self._last_ir = frame.data['TDI'][0]
        elif frame.type == 'TstLogRst':
            self._last_ir = 0x0
        elif frame.type == 'Ex1DR':
            if self._last_ir == 0x11:
                # BitCount
                op, data, address = self.parse_bitfields(frame.data[self.process_signal_setting], frame.data['BitCount'])
                ops = {
                    "TDI": {
                        0x00: "nop",
                        0x01: "read",
                        0x02: "write",
                        0x03: "rsvd"
                    },
                    "TDO": {
                        0x00: "success",
                        0x01: "rsvd",
                        0x02: "fail",
                        0x03: "in-progress"
                    }
                }
                return AnalyzerFrame('dmi_access_out', frame.start_time, frame.end_time, {
                    'op': ops[self.process_signal_setting].get(op, "unkn"),
                    'data': hex(data),
                    'address': hex(address)
                })