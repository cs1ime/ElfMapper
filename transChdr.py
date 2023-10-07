import sys

filename = sys.argv[1]

with open(filename,'rb') as tst:
    data=tst.read()


c_array = ['0x{:02X}'.format(byte) for byte in data]
c_array_str = ', '.join(c_array)

namespace = 'test_binso'

header_content = '#ifndef _FILE__BINARY_DATA_H_\n'
header_content += '#define _FILE__BINARY_DATA_H_\n\n'
header_content += 'namespace ' + namespace + ' {\n\n'
header_content += 'unsigned char binary_data[] = {\n'
header_content += '   ' + c_array_str + '\n};\n\n'
header_content += '}\n\n'
header_content += '#endif // _FILE__BINARY_DATA_H_'

print(header_content)
