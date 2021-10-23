#coding = utf-8
import re
import sys
from oleobj import OleObject
from oleobj import OleNativeStream
from olefile import isOleFile
from olefile import OleFileIO
from clsid import KNOWN_CLSIDS
import binascii
import hashlib

TYPE_LINKED = 0x01
TYPE_EMBEDDED = 0x02

if sys.version_info[0] <= 2:
    BACKSLASH = '\\'
    BRACE_OPEN = '{'
    BRACE_CLOSE = '}'
else:
    BACKSLASH = ord('\\')
    BRACE_OPEN = ord('{')
    BRACE_CLOSE = ord('}')
    UNICODE_TYPE = str

# 清除\\
def CleanSlash(data,flag):
    slash_list = []
    count = 0
    #print(chr(data[len(data)-1]))
    if chr(data[len(data)-1]) !='\\':
        flag = True
        data = data + b'\\'
    tempdata = data
    for eachbyte in data:
        if chr(eachbyte) == '\\' and len(slash_list)==0:
            slash_list.append(count)
            count = count + 1
            continue
        if chr(eachbyte) == '\\' and len(slash_list) >0:
            tempdata = data[:slash_list[0]]+data[count:]
            slash_list[0] = count
            return  CleanSlash(tempdata,flag)
        count = count + 1
    if flag == True and chr(data[len(data)-1]) == '\\':
        data = data[:len(data)-1]
    return data

# 清除bin混淆
def CleanBinConfuse(data,index):
    if data[index-1:index+3] != b"\\bin":
        return data
    # \\binxxxxxxnumber
    i = 0
    for i in range(index+3,len(data)):
        if not re.search("\d{1}",chr(data[i])):
            break
    len_confusedata = int(chr(data[i-1]))
    confusedata = data[i+1:i+len_confusedata+1]
    data = data[:i+1]+binascii.hexlify(confusedata)+data[i+len_confusedata+1:]
    return data

# 判断是否存在ole文件，并返回Magic的Index
def IsOleFile(data):
    MAGIC = b'D0CF11E0A1B11AE1'
    if MAGIC in data:
        return [i.start() for i in re.finditer(MAGIC, data)][0]
    else:
        return False

# 判断是否是超长控制符
def CleanTooLongCtrlWord(data):
    count = 0
    result_data = data
    for eachbyte in data:
        special_data = b''
        if eachbyte == BACKSLASH:
            special_data = data[count+1:count+0xFE].decode("ascii","replace")
            if re.search("[0-9a-zA-Z]{253}",special_data):
                special_data = "\\" + special_data
                special_data = special_data.encode("utf-8","ignore")
                #data = data.decode("ascii","replace")
                result_data = result_data.replace(special_data,b"",1)
        count += 1
    return result_data

# 判断是否需要被忽略
# {\par2211 5555}
# \datastore2211
# {\unknown2211 5555}
# {\*\par314 5555}
def IsIgnore(data,count):
    if count == 0:
        return False
    if data[0] == BACKSLASH or data[0:3] == b'\\*\\':
        return True
    else:
        return False

def GetIndexofSlash(data,count):
    offset = 0
    for eachbyte in data:
        if eachbyte == ord('\\') or eachbyte == ord(" "):
            return offset+1
        offset = offset + 1
    return len(data)+1

#\f3455 1 
# \\*\\objdata
def CleanSlash2(data):
    is_objdata = False
    if data[0:10] ==b'\\*\\objdata':
        data = data[10:]
        is_objdata = True
    ret_data = b''
    is_brackets = False # 作为获取'\'符号的标志
    count = 0
    while(count < len(data)):
        eachbyte = data[count]
        if eachbyte == ord('\\'):
            is_brackets = True
        if is_brackets == False:
            end_offset = GetIndexofSlash(data[count:],count)
            # because A[a:b] not include A[b] so + 1
            ret_data = ret_data + data[count:count + end_offset]
            count = count + end_offset
            continue
        else:
            end_offset = GetIndexofSlash(data[count+1:],count)
            count = count + end_offset
            is_brackets = False
            continue
        count = count + 1
    if is_objdata == True:
        ret_data = b'\\*\\objdata' + ret_data
    return ret_data
            

        




def ObjdataParse(data):
    # 然后依次遍历 以{}作为一个基本结构
    # 两个list，一个存{},一个存index
    brace_list = []
    index_list = []


    # {\*\objdata62479 
    # TODO 数字位数是随机的
    count = 11
    for count in range(11,len(data)):
        if not re.search("\d{1}",chr(data[count])):
            break
    data = data[:11]+data[count:]

    
    ## 处理一些混淆
    # NO1:处理BIN混淆
    index_bin = [i.start() for i in re.finditer("bin", data.decode("ascii","replace"))]
    if len(index_bin) > 0:
        for eachindex in index_bin:
            data = CleanBinConfuse(data,eachindex)

    data = data.translate(None, b'\t\r\n\f\v')

    # 判断是否存在OLE文件
    OleIndex = IsOleFile(data)

    bin_data = b"{"
    # 首地址为{
    count = 0
    # 是否是带有'\'的混淆，如果是，则忽略
    is_ignore = False 
    # 是否处于括号内部
    is_brackets = False 
    if data[count] == BRACE_OPEN:
        for eachbyte in data:
            if eachbyte == BRACE_OPEN:
                # 如果没有{,则插入list
                if len(brace_list) == 0:
                    brace_list.append('{')
                    index_list.append(count)
                    is_ignore = IsIgnore(data[count+1:],count)
                    count = count + 1
                    continue

                # 第n个{,n>1
                if len(brace_list) > 0 :
                    is_brackets = True
                    brace_list.append('{')
                    index_list.append(count)
                    # 排除这种可能{xxxxx{xxxxx}}
                    if len(brace_list) >= 2:
                        tempdata = data[index_list[len(index_list)-2]+1:index_list[len(index_list)-1]]
                        if data[index_list[len(index_list)-2]] == 92:
                            tempdata = b'\\'+data[index_list[len(index_list)-2]+1:index_list[len(index_list)-1]]
                        #print(tempdata)
                        tempdata = CleanSlash2(tempdata)
                        if is_ignore == False:
                            bin_data += tempdata
                        #print(bin_data)
                    is_ignore = IsIgnore(data[count+1:],count)
                    count = count + 1
                    continue
            
            if eachbyte == BRACE_CLOSE:
                is_ignore = False
                is_brackets = False
                # 不止一个{
                if len(brace_list) > 1:
                    # 如果不在Ole中
                    if OleIndex != False and count > OleIndex:
                        tempdata = data[index_list[len(index_list)-1]:count+1]
                        bin_data = bin_data + tempdata
                        #print(bin_data)

                    brace_list.pop()
                    index_list.append(count)
                    count = count + 1
                    continue

                # 如果只有一个{
                if len(brace_list) == 1:
                    brace_list.pop()
                    index_list.append(count)
                    tempdata = data[index_list[len(index_list)-2]+1:index_list[len(index_list)-1]]
                    if data[index_list[len(index_list)-2]] == 92:
                        tempdata = b'\\'+data[index_list[len(index_list)-2]+1:index_list[len(index_list)-1]]
                    #print(tempdata)
                    tempdata = CleanSlash2(tempdata)
                    bin_data = bin_data + tempdata
                    #print(bin_data)

            # //
            if eachbyte == BACKSLASH:
                # 首先需要排除处于{}内部的情况
                # 并以'\,' '作为结束的标志
                if is_brackets == True or (count ==1 or count == 3):
                    count = count + 1
                    continue
                
                index_list.append(count)
                tempdata = data[index_list[len(index_list)-2]+1:index_list[len(index_list)-1]]
                if data[index_list[len(index_list)-2]] == 92:
                    tempdata = b'\\'+data[index_list[len(index_list)-2]+1:index_list[len(index_list)-1]]
                #print(tempdata)
                tempdata = CleanSlash2(tempdata)
                bin_data = bin_data + tempdata
                #print(bin_data)
                count = count + 1
                continue
                

            # 整个objdata结束
            if not brace_list:
                break
            count = count + 1
        
        bin_data = bin_data[11:]
        bin_data = bin_data.translate(None, b' ')
        print(bin_data)
        return bin_data
    else:
        return 

class RtfObject(object):
    def __init__(self):
        self.is_ole = False
        self.oledata = None
        self.format_id = None
        self.class_name = None
        self.oledata_size = None
        # OLE Package data (extracted from oledata)
        self.is_package = False
        self.olepkgdata = None
        self.filename = None
        self.src_path = None
        self.temp_path = None
        # Additional OLE object data
        self.clsid = None
        self.clsid_desc = None

def OleParse(object_data):
    obj = OleObject()
    rtfobj = RtfObject()
    try:
        obj.parse(object_data)
        # 赋值
        rtfobj.format_id = obj.format_id
        rtfobj.class_name = obj.class_name
        rtfobj.oledata_size = obj.data_size
        rtfobj.oledata = obj.data
        rtfobj.oledata_md5 = hashlib.md5(obj.data).hexdigest()         
        rtfobj.is_ole = True
        if obj.class_name.lower() == b'package':
            opkg = OleNativeStream(bindata=obj.data,package=True)
            rtfobj.filename = opkg.filename
            rtfobj.src_path = opkg.src_path
            rtfobj.temp_path = opkg.temp_path
            rtfobj.olepkgdata = opkg.data
            rtfobj.olepkgdata_md5 = hashlib.md5(opkg.data).hexdigest()     
            rtfobj.is_package = True
        else:
            if isOleFile(obj.data):
                ole = OleFileIO(obj.data)
                rtfobj.clsid = ole.root.clsid
                rtfobj.clsid_desc = KNOWN_CLSIDS.get(rtfobj.clsid,
                'unknown CLSID (please report at https://github.com/decalage2/oletools/issues)')
    except:
        print("\t *** Not an OLE 1.0 Object")
        return
    return rtfobj

def GetObjdata(data,Index_Objdata):
    # {\*\objdata12345
    if data.decode("ascii","replace")[Index_Objdata-4:Index_Objdata] == "{\\*\\":
        data = data[Index_Objdata-4:len(data)]
        Objdata = ObjdataParse(data)
    # {\pokedata\objdata
    else:
        data = b'{\\*\\'+data[Index_Objdata:len(data)]
        Objdata = ObjdataParse(data)
    hexdata = re.sub(b'[^a-fA-F0-9]', b'', Objdata)
    try:
        object_data = binascii.unhexlify(hexdata)
    except binascii.Error:
        object_data = binascii.unhexlify(hexdata+b'0')
    # 将解析内容返回到rtfobj
    rtfobj = OleParse(object_data)
    if not rtfobj:
        return 
    if rtfobj.is_ole:
        # format_id
        if rtfobj.format_id == OleObject.TYPE_EMBEDDED:
            print("\t format_id:(Embedded)")
        elif rtfobj.format_id == OleObject.TYPE_LINKED:
            print("\t format_id:(Linked)")
        else:
            print("\t format_id:(Unknown)")
        # classname
        print("\t class_name:%s"%rtfobj.class_name)

        # data_size
        if rtfobj.oledata_size is None:
            print("\t data_size: N/A")
        else:
            print("\t data_size:%s"%rtfobj.oledata_size)
        
        if rtfobj.is_package == True:
            print("\t OLE Package object:")
            print("\t Filename: %r" % rtfobj.filename)
            print("\t Source path: %r" % rtfobj.src_path)
            print("\t Temp path = %r" % rtfobj.temp_path)
            print("\t MD5 = %r" % rtfobj.olepkgdata_md5)
        else:
            print("\t MD5 = %r" % rtfobj.oledata_md5)
        
        if rtfobj.clsid is not None:
            print("\t CLSID: %s" % rtfobj.clsid)
            print("\t %s" % rtfobj.clsid_desc)
            

        if rtfobj.class_name == b'OLE2Link':
            print("\t Possibly an exploit for the OLE2Link vulnerability (VU#921560, CVE-2017-0199)")
            found_list =  re.findall(r'[a-fA-F0-9\x0D\x0A]{128,}',data)
            urls = []
            for item in found_list:
                try:
                    temp = item.replace("\x0D\x0A","").decode("hex")
                except:
                    continue
                pat = re.compile(r'(?:[\x20-\x7E][\x00]){3,}')
                words = [w.decode('utf-16le') for w in pat.findall(temp)]
                for w in words:
                    if "http" in w:
                        urls.append(w)
            urls = sorted(set(urls))
            if urls:
                print("\t URL extracted:" + ','.join(urls))

        elif rtfobj.class_name.lower().startswith(b'equation.3'):
            print("\t Possibly an exploit for the Equation Editor vulnerability (VU#421280, CVE-2017-11882)")


if __name__ == "__main__":

    IsObjdata = False
    Index_Objdata = []

    if len(sys.argv) !=2:
        exit()
    filepath = sys.argv[1]
    with open(filepath,'rb') as fp:
        data = fp.read()
        data = CleanTooLongCtrlWord(data)
        if "objdata" in str(data):
            IsObjdata = True
        if IsObjdata == True:
            str_data = data.decode("ascii",'replace')
            # 可能不止一个objdata
            Index_Objdata = [i.start() for i in re.finditer("objdata", str_data)]
            for eachindex in Index_Objdata:
                GetObjdata(data,eachindex)
        else:
            print("\t No objdata")

