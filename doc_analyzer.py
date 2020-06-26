import oletools
from pathlib import Path
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML


def main():
    filename = readfile_from_documents()
    if not is_file_has_VBA_macros(filename):
        return 
    code_items = get_items(filename)  # Возвращает словарь с данными о входящих в документ макросах
    print(code_items)
    
    

def readfile_from_documents():
    """Return file path from directory and input."""
    filename = input("Input file name to analysis: ")
    base_path = Path(__file__).parent
    directory_path = (base_path / "documents").resolve()
    file_path = Path(directory_path, filename)
    return(file_path)


def is_file_has_VBA_macros(filename):
    vbaparser = VBA_Parser(filename)
    print('The file type is "%s"' % (vbaparser.type))
    if vbaparser.detect_vba_macros():
        print("VBA Macros найден!")
        print('- '*39)
        return True
    else:
        print("VBA Macros не найден!")
        print('- '*39)
        return False


def get_items(filename):
    vbaparser = VBA_Parser(filename)
    vbaparser.analyze_macros()
    print ('Ключевые слова автоматического вызова: %d' % vbaparser.nb_autoexec)
    print ('Подозрительные ключевые слова: %d' % vbaparser.nb_suspicious)
    print ('IOCs: %d' % vbaparser.nb_iocs)
    print ('Шестнадцатеричные обфусцированные строки: %d' % vbaparser.nb_hexstrings)
    print ('Base64 обфусцированные строки: %d' % vbaparser.nb_base64strings)
    print ('Dridex обфусцированные строки: %d' % vbaparser.nb_dridexstrings)
    print ('VBA обфусцированные строки: %d' % vbaparser.nb_vbastrings)
    print('- '*39)
    return({'AutoExec': vbaparser.nb_autoexec, 'Dridex': vbaparser.nb_dridexstrings, 'VBA': vbaparser.nb_vbastrings})
    


if __name__ == "__main__":
    main()