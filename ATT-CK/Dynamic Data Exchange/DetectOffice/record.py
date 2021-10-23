#coding = utf-8
from struct import unpack
import common
import record_base
import xls_parser


# 遍历整块数据段
def iter_records(stream):
    while True:
        pos = stream.stream.tell()
        # index > size
        if pos >= stream.size:
            break
        
        # read records head
        rec_type,rec_size = unpack("<HH",stream.stream.read(4))

        # record class for type
        # rec_type = 2057
        if rec_type == xls_parser.XlsRecordBof.TYPE:
            rec_clz =  xls_parser.XlsRecordBof
            force_read = True
        # rec_type = 10
        elif rec_type == xls_parser.XlsRecordEof.TYPE:
            rec_clz = xls_parser.XlsRecordEof
            force_read = False
        # rectype = 430
        elif rec_type == xls_parser.XlsRecordSupBook.TYPE:
            rec_clz = xls_parser.XlsRecordSupBook
            force_read = True
        else:
            rec_clz = xls_parser.XlsRecord
            force_read = False

        #read data
        data = None
        if force_read:
            data = stream.stream.read(rec_size)
            if len(data) != rec_size:
                common._error("len(data) not eq rec_size")
        else:
            stream.stream.seek(rec_size,1)

        # init record object
        rec_object = rec_clz(rec_type, rec_size, None, pos, data)
        rec_object.read_some_more(stream.stream)
        yield rec_object
        









    