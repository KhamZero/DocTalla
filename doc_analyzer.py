import oletools
from pathlib import Path
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML


def main():
    filename = readfile_from_documents()
    checkfile(filename)
    macros = extract_macros(filename)  # Возвращает все входящие в файл макросы
    print(macros)


def readfile_from_documents():
    filename = input("Input file name to analysis: ")
    base_path = Path(__file__).parent
    directory_path = (base_path / "documents").resolve()
    file_path = Path(directory_path, filename)
    return(file_path)


def checkfile(filename):
    vbparser = VBA_Parser(filename)
    print('The file type is "%s"' % (vbparser.type))
    if vbparser.detect_vba_macros():
        print("VBA Macros найден!")
    else:
        print("VBA Macros не найден!")


def extract_macros(filename):
    vbaparser = VBA_Parser(filename)
    for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
        print('-'*79)
        print('Filename    :', filename)
        print('OLE stream  :', stream_path)
        print('VBA filename:', vba_filename)
        print('- '*39)
        print(vba_code)  # Все это не нужно, оставим только return
        return vba_code


if __name__ == "__main__":
    main()


input()
