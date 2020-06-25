import oletools
import olefile
import sys
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML



def main():
    filename = readfile()
    checkfile(filename)
    

def readfile():
    filename = input("Input file name to analysis: ")
    return(filename)

def checkfile(filename):
    def has_macros(vbparser):
        if vbparser.detect_vba_macros():
            return True
        else:
            return False
    



    vbparser = VBA_Parser(filename)
    print('The file type is "%s"' % (vbparser.type))
    if has_macros(vbparser):
        print("VBA Macros найден!")
    else:
        print("VBA Macros не найден!")
        
    


    
    

if __name__ == "__main__":
    main()


input()
