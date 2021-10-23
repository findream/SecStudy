#coding =  utf-8
import xml.etree.ElementTree as ET
import re
from zipfile import is_zipfile

from oletools.record_base import OleFileIO 
import common
import os
import shutil
import xls_parser
import record
import doc_olefile
import olefile
import sys
import  zipfile

OLE_FIELD_START = 0x13
OLE_FIELD_SEP = 0x14
OLE_FIELD_END = 0x15
OLE_FIELD_MAX_SIZE = 1000   # max field size to analyze, rest is ignored

if sys.version_info[0] >= 3:
    unichr = chr

class DETECTDDE():
    def __init__(self,filepath,filetype):
        self.filepath = filepath
        self.ddetext = ''
        self.zipper = None
        self.filetype = filetype
        self.embeddingfilepath  = ''

    def detect_dde(self):
        if self.filetype == common.FILETYPE_DOCX:
            result = self.detect_docx()
            if result:
                common._info("dde links: \n\t %s" % self.ddetext)
            else:
                common._info("no dde")

        elif self.filetype == common.FILETYPE_DOC:
            result = self.detect_doc()
            if result:
                common._info("dde links: \n\t %s" % self.ddetext)
            else:
                common._info("no dde")
        elif self.filetype == common.FILETYPE_XLSX:
            result = self.detect_xlsx()
            if result:
                common._info("dde links: \n\t %s" % self.ddetext)
            else:
                common._info("no dde")
        elif self.filetype == common.FILETYPE_PPTX:
            result = self.detect_pptx()
            if result:
                common._info("dde links: \n\t %s" % self.ddetext)
            else:
                common._info("no dde")
        elif self.filetype == common.FILETYPE_XLS:
            result = self.detect_xls()
            if result:
                common._info("dde links: \n\t %s" % self.ddetext)
            else:
                common._info("no dde")
        elif self.filetype == common.FILETYPE_RTF:
            result = self.detect_rtf()
            if result:
                common._info("dde links: \n\t %s" % self.ddetext)
            else:
                common._info("no dde")        
    
    # detect docx
    def detect_docx(self):
        if self.embeddingfilepath != '':
            self.zipper = common.is_contain_targetxmlfile(self.embeddingfilepath,"word/document.xml")
        else:
            self.zipper = common.is_contain_targetxmlfile(self.filepath,"word/document.xml")
        if self.zipper is None:
            common._error("word/document.xml did not found")
            return None
        # Ref https://yuukou-exp.plus/handle-xlsx-with-python-intro/
        tree = ET.parse(self.zipper.open("word/document.xml"))
        for elem in tree.iter():
            if elem.tag.split('}')[1] =='r':
                for sub in elem:
                    if sub.tag.split('}')[1] == "instrText":
                        text = sub.text.strip().replace('\n', '').replace('\r', '')
                        if "QUOTE" in text:
                            text = self.clean_quote(text)
                        self.ddetext += text

        self.zipper.close()               
        if re.match(r'\\s*dde(auto)?\\s+',self.ddetext,re.M|re.I):
            #common._info("dde links: \n\t %s" % self.ddetext)
            return self.ddetext
        else:
            if 'DDE' in  self.ddetext.upper():
                #common._info("dde links: \n\t %s" % self.ddetext)
                return self.ddetext
            else:
                #common._info("no dde")
                return None
        
    def clean_quote(self,text):
        cleanquote_str = ''
        if "QUOTE" not in text:
            return text
        parts = text.strip().split(" ")
        for part in parts[1:]:
            try:
                character = chr(int(part))
            except ValueError:
                character = part
            cleanquote_str += character
        return cleanquote_str

    def detect_xlsx(self):
        # Todo: xl/externalLinks have many xml file named externalLink.xml such as externalLink1.xml externalLink2.xml
        filepath = self.filepath
        ddetext = ''
        ddetext_list = []
        if not zipfile.is_zipfile(filepath):
            common._error("file is not a zip")
            return None
        zipper = zipfile.ZipFile(filepath)
        #print(zipper.namelist())
        for subfile in zipper.namelist():
            if "xl/externalLinks/" not in subfile:
                continue
            self.zipper = common.is_contain_targetxmlfile(self.filepath,subfile)
            if self.zipper is None:
                common._error("%s did not found" % subfile)
                self.zipper.close()
                return None
            tree = ET.parse(self.zipper.open(subfile))
            for elem in tree.iter():
                if elem.tag.split('}')[1] =='ddeLink':
                    if "ddeService" in elem.attrib.keys() and "ddeTopic" in elem.attrib.keys():
                        if elem.attrib["ddeService"]:
                            ddetext += elem.attrib["ddeService"]
                        if elem.attrib["ddeTopic"]:
                            ddetext += elem.attrib["ddeTopic"]
            if ddetext != '':
                ddetext_list.append(ddetext)
        # if self.ddetext != '':
        #     common._info("dde links: \n\t %s" % self.ddetext)
        # else:
        #     common._info("no dde")
        if u'\n'.join(ddetext_list):
            self.ddetext = u'\n\t '.join(ddetext_list)
        if self.ddetext !='':
            return self.ddetext
        else:
            return None

    def detect_pptx(self):
        result = ''
        extractfilepath = common.is_contain_targetdir(self.filepath,"ppt/embeddings")
        if extractfilepath is None:
            common._error("/ppt/embeddings did not found")
            return None
        self.embeddingfilepath = extractfilepath
        file_type = common.get_file_type(self.embeddingfilepath)
        
        if file_type == common.FILETYPE_DOCX:
            result = self.detect_docx()
        elif file_type == common.FILETYPE_DOC:
            result = self.detect_doc()
        elif file_type == common.FILETYPE_XLS:
            result = self.detect_xls()
        elif file_type == common.FILETYPE_XLSX:
            result = self.detect_xlsx()
        elif file_type == common.FILETYPE_RTF:
            result = self.detect_rtf()
        
        shutil.rmtree("C:/Users/Public/ppt")
        return result

    def detect_xls(self):
        # ole
        # Traverse stream --> Traverse Record
        result = []
        filepath = self.filepath
        xls_file = xls_parser.XlsFile(filepath)
        for stream in xls_file.iter_streams():
            if not isinstance(stream, xls_parser.WorkbookStream):
                continue
            for eachrecord in record.iter_records(stream):
                # record.type == 430?
                if not isinstance(eachrecord, xls_parser.XlsRecordSupBook):
                    continue
                if eachrecord.support_link_type in (
                        xls_parser.XlsRecordSupBook.LINK_TYPE_OLE_DDE,
                        xls_parser.XlsRecordSupBook.LINK_TYPE_EXTERNAL):
                    result.append(eachrecord.virt_path.replace(u'\u0003', u' '))
        if u'\n'.join(result):
            self.ddetext = u'\n'.join(result)
        # if self.ddetext != '':
        #     common._info("dde links: \n\t %s" % self.ddetext)
        # else:
        #     common._info("no dde")
        if self.ddetext !='':
            return self.ddetext
        else:
            return None
    
    def detect_doc(self):
        filepath = self.filepath
        result = []
        
        with olefile.OleFileIO(filepath,path_encoding=None) as ole:
            for sid, direntry in enumerate(ole.direntries):

                # load direntry
                if not direntry: 
                    direntry = ole._load_direntry(sid)
                
                # determine whether direntry's type is stream by direntry->type==2
                if direntry.entry_type == olefile.STGTY_STREAM:

                    #  get stream of directory
                    #  direntry.isectStart means the start index of Sector
                    #  direntry.size means the size of this stream
                    #  offset of stream = sizeofoleheader + isecStart * sizeofsector
                    #  usually sizeofsector is 0x200,sizeofoleheader is 0x200
                    stream = ole._open(direntry.isectStart,direntry.size)
                    result2 = self.process_doc_stream(stream)
                    if result2:
                        result.extend(result2)


        if u'\n'.join(result):
            self.ddetext = u'\n'.join(result)
        # if self.ddetext != '':
        #     common._info("dde links: \n\t %s" % self.ddetext)
        # else:
        #     common._info("no dde")
        if self.ddetext !='':
            return self.ddetext
        else:
            return None

    def process_doc_stream(self,stream):
        # read each byte of stream
        index = -1
        is_start = False
        is_sep = False
        is_end = False
        dde_result = []
        field_contents = None
        while True:

            # index increases 1 when every traversal
            index += 1
            char = stream.read(1)
            # char is None means end of stream
            if len(char) ==0:
                break
            else:
                char = ord(char)
            
            # Start
            if char == OLE_FIELD_START:
                is_start = True
                is_sep = False
                field_contents = u''
                continue
            elif is_start == False:
                continue

            # Step
            if char == OLE_FIELD_SEP:
                is_sep = True

            # End
            if char == OLE_FIELD_END:
                if field_contents:
                    field_contents = self.process_doc_field(data=field_contents)
                    if field_contents:
                        dde_result.append(field_contents)

                is_end = True
                is_start = False
                is_sep = False
                field_contents = None
            
            if is_start == True and is_sep == False and is_end == False:
                if char > 31 and char < 127:
                    field_contents += unichr(char)
        
        if dde_result:
            return dde_result
        else:
            return None
        
    def process_doc_field(self,data):
        if data.lstrip().lower().startswith(u'dde'):
            return data
        if data.lstrip().lower().startswith(u'\x00d\x00d\x00e\x00'):
            return data
        return u''

    def detect_rtf(self):
        filepath = self.filepath
        have_field = False
        result = []
        with open(filepath,'rb') as handle:
            data = handle.read()
            if "\\field" in str(data):
                have_field = True
            if have_field:
                str_data = data.decode("ascii",'replace')
                index_field = [i.start() for i in re.finditer(r"\\field", str_data)]
                for eachindex in index_field:
                    result.append(self.process_rtf_stream(filedata = data,index = eachindex))
            
        if u'\n'.join(result):
            self.ddetext = u'\n'.join(result)
        # if self.ddetext != '':
        #     common._info("dde links: \n\t %s" % self.ddetext)
        # else:
        #     common._info("no dde")
        if self.ddetext !='':
            return self.ddetext
        else:
            return None

    def process_rtf_stream(self,filedata,index):
        start_index = 0
        end_indx = 0
        max_index = 256
        flag = 0
        is_open = False        # contrl {
        is_close = False       # contrl }
        is_ignore = False      # ignore ctrl word
        is_force  = False      # if is_force == False means is_ignore effect but is_force == True means is_ignore not effect
        resutlt = ''
        str_data = filedata.decode("ascii",'replace')
        # get start_index of field_block
        while max_index != 0:
            if str_data[index - (256 - max_index)] == "{":
                start_index = index - (256 - max_index)
                break
            max_index = max_index - 1
        if str_data[start_index] == "{":
            offset = start_index-1
            while offset < len(filedata):
                offset += 1
                if str_data[offset] == "{":
                    flag += 1
                    continue
                if str_data[offset] == "}":
                    flag -= 1
                    continue
                # it means field block is over
                if flag == 0:
                    end_indx = offset
                    break
                
                # open
                if 'fldinst' in str_data[offset:offset+7]:
                    is_open = True
                    offset += 7
                
                # close
                if "fldrslt" in str_data[offset:offset+7]:
                    is_close = True
                
                # open=True close = False
                if is_open ==True and is_close == False:
                    if str_data[offset] == ' ':
                        if is_ignore == True:
                            is_ignore = False
                            continue
                    elif str_data[offset] == '{':
                        continue
                    elif str_data[offset] == '}':
                        if is_force == True:
                            is_force = False
                        continue
                    elif str_data[offset] == '\\' and is_force == False:
                        is_ignore = True
                        continue
                        
                    if is_ignore == False:
                        resutlt += str_data[offset]
                    
                    if "DDE" in resutlt.upper() and is_force == False:
                        is_force = True

        return resutlt.replace('\n','').replace('\r','').replace('\t','').replace('\f','').replace('\v','')

                

def main():
    if len(sys.argv) != 2:
        common._error("argv error:[python detectdde.py officefilename]")
        return None
    
    filepath = sys.argv[1]
    
    #filepath = "C:\\Users\\Administrator\\Desktop\\DDE\\dde_test.rar"
    filetype = common.get_file_type(filepath)
    if filetype in [common.FILETYPE_DOC,common.FILETYPE_DOCX,common.FILETYPE_PPT,common.FILETYPE_PPTX,common.FILETYPE_RTF,common.FILETYPE_XLS,common.FILETYPE_XLSX]:
        detectdde = DETECTDDE(filepath,filetype)
        detectdde.detect_dde()





if __name__ == '__main__':
    main()
    