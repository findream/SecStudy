#coding = utf-8

class Doc_OleFile():
    def __init__(self,filepath):
        self.filepath = filepath
        self.seg = b''             # +00：符合文档的文件标志符
        self.byteorder = b''       # +28: 大端：FFhFEh  小端：FEhFFh
        self.is_bigEndian = False  # 是否是大端
        self.sector_size = 0       # +30: sector的大小 以2的n次幂进行计算
        self.shortsector_size = 0  # +32: short-sector的大小，以2的幂形式存储
        self.num_fatsector = 0     # +44: 用于存放扇区配置表（SAT）的sector总数



    def parse_oleheader(self):
        pass

    def parse_directoryentry(self):
        pass

