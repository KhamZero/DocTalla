from xlutils.copy import copy as xl_copy
import xlrd


class DocCleaner:
    """
    Cleaner for files containing vba scripts.
    Windows only
    """

    def __init__(self, file_path):
        """Initialize Cleaner."""
        if not file_path:
            return
        self.results = ""
        self.file_path = file_path
        self.results = self.clean_file(file_path)

    def clean_file(self, file_path):
        """Clean file using xlrd."""
        result = "Файл очищен!"

        try:
            rb = xlrd.open_workbook(file_path)
        except Exception as e:
            print(e)
            result = "Файл не может быть очищен! :"
            result += str(e)
        else:
            wb = xl_copy(rb)
            wb.save(file_path)
        return result
