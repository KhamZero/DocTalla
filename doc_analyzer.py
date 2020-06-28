"""Analyzer layer of Project."""
from oletools import olevba
from oletools.olevba import VBA_Parser
from pathlib import Path


class Report:
    """
    Create Report from macros information.

    we have list of info dictionaries of the following structure:
        {
            'number': vbaparser.nb_autoexec, 
            'description': 'Ключевые слова автоматического вызова',
            'danger': False
        },
    """

    def __init__(self, infos):
        """Initialize Report."""
        self.infos = infos
        if not self.infos:
            self.infos = []
        self.warnings = self.get_warnings(self.infos)
        self.dangers = self.get_dangers(self.infos)
        self.is_danger = self.check_if_danger()
        self.is_warning = self.check_if_warning()

    def check_if_warning(self):
        """Return true if warnings detected."""
        if self.warnings:
            return True
        return False

    def check_if_danger(self):
        """Return true if dangers detected."""
        if self.dangers:
            return True
        return False

    def get_warnings(self, infos):
        """Return list of warnings."""
        warnings = []
        for info in self.infos:
            if not info["danger"] and info["number"] > 0:
                warnings.append(info)
        return warnings

    def get_dangers(self, infos):
        """Return list of dangers."""
        dangers = []
        for info in self.infos:
            if info["danger"] and info["number"] > 0:
                dangers.append(info)
        return dangers

    def print_warnings(self):
        """Print warnings."""
        if not self.warnings:
            return
        print("""Обнаружен подозрительный код!""")
        print('- '*39)
        for warning in self.warnings:
            print(f"""{warning["description"]} : {warning["number"]}""")

    def print_danger(self):
        """Print dangers."""
        if not self.dangers:
            return
        print("""Обнаружен вредоносный код!""")
        print('- '*39)
        for danger in self.dangers:
            print(f"""{danger["description"]} : {danger["number"]}""")

    def get_result(self):
        """Return string with report result."""
        report_result = "Вирус не найден!"

        if self.is_warning:
            report_result = "Вирус не найден! Но обнаружен подозрительный код!"

        if self.is_danger:
            report_result = "Найден вирус!"

        return report_result

    def get_warning_message_list(self):
        warning_list = []
        for warning in self.warnings:
            warning_list.append(
                f"""{warning["description"]} : {warning["number"]}""")
        return warning_list

    def get_danger_message_list(self):
        danger_list = []
        for danger in self.dangers:
            danger_list.append(
                f"""{danger["description"]} : {danger["number"]}""")
        return danger_list


class FileAnalytics:
    """File analytics class."""

    def __init__(self, file_path):
        """Initialize FileAnalytics."""
        self.file_path = file_path
        self.has_macros = self.is_file_has_VBA_macros()
        self.macros_infos = self.get_macros_infos()
        self.vba_code = self.get_vba_code()


    def is_file_has_VBA_macros(self):
        """Check if file has VBA macros."""
        file_path = self.file_path
        vbaparser = VBA_Parser(file_path)
        print('The file type is "%s"' % (vbaparser.type))
        report = vbaparser.detect_vba_macros()
        vbaparser.close()
        return report


    def get_macros_infos(self):
        """Check file macroses for suspisious behaviour."""
        if not self.has_macros:
            return None
        vbaparser = VBA_Parser(self.file_path)
        vbaparser.analyze_macros()

        # obfuscated vba and autoexec danger
        autoexec_and_vba = 0
        if vbaparser.nb_autoexec > 0 and vbaparser.nb_vbastrings > 0:
            autoexec_and_vba = vbaparser.nb_vbastrings

        # obfuscated Base64 and autoexec danger
        autoexec_and_base64 = 0
        if vbaparser.nb_autoexec > 0 and vbaparser.nb_base64strings > 0:
            autoexec_and_base64 = vbaparser.nb_base64strings

        # obfuscated HEX and autoexec danger
        autoexec_and_HEX = 0
        if vbaparser.nb_autoexec > 0 and vbaparser.nb_hexstrings > 0:
            autoexec_and_HEX = vbaparser.nb_hexstrings

        macros_infos = [
            {'number': vbaparser.nb_autoexec,
                'description': 'Ключевые слова автоматического вызова', 'danger': False, 'function': olevba.detect_autoexec},
            {'number': autoexec_and_HEX,
                'description': 'Автоматический вызов шеснадцатиричных обфусцированных строк', 'danger': False, 'function': olevba.detect_hex_strings},
            {'number': vbaparser.nb_vbastrings,
                'description': 'VBA обфусцированные строки', 'danger': False, 'function': olevba.detect_vba_strings},
            {'number': vbaparser.nb_suspicious,
                'description': 'Подозрительные ключевые слова', 'danger': False, 'function': olevba.detect_suspicious},
            {'number': autoexec_and_vba,
                'description': 'Автоматический вызов обфусцированного кода', 'danger': True, 'function': olevba.detect_vba_strings},
            {'number': vbaparser.nb_dridexstrings,
                'description': 'Dridex обфусцированные строки', 'danger': True, 'function': olevba.detect_dridex_strings},
            {'number': autoexec_and_base64,
                'description': 'Автоматический вызов Base64 обфусцированных строк', 'danger': True, 'function': olevba.detect_base64_strings},
        ]

        vbaparser.close()
        return macros_infos


    def get_vba_code(self):
        """Code analysis for malicious parts. Returns malicious code, if any."""
        if not self.has_macros:
            return "Документ не содержит макросов!"

        vbaparser = VBA_Parser(self.file_path)
        vbaparser.detect_vba_macros()
        code_list = list()

        for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
            code_list.append(vba_code)
            code = vba_code

        report_vba = code_list[0]
        macros_infos = self.macros_infos
        for i in range(len(macros_infos)):
            if macros_infos[i]['number'] > 0:
                macro_code = macros_infos[i]['function'](code)
                for i in macro_code:
                    for j in i:
                        report_vba += j

        vbaparser.close()
        return report_vba


def check_one_file():
    """Check one file from documents directory."""
    file_name = input("Input file name to analysis: ")

    base_path = Path(__file__).parent
    directory_path = (base_path / "documents").resolve()
    file_path = Path(directory_path, file_name)

    analyzer = FileAnalytics(file_path)
    analyze_results = analyzer.macros_infos

    report = Report(analyze_results)
    report.print_warnings()
    report.print_danger()


def check_directory():
    """Check the directory files."""
    directoryname = input("Input directory name to analysis: ")
    file_paths_in_directory = []
    for p in Path(directoryname).iterdir():
        if p.is_file():
            file_paths_in_directory.append(p)

    for file_path in file_paths_in_directory:
        analyzer = FileAnalytics(file_path)
        analyze_results = analyzer.macros_infos
        report = Report(analyze_results)
        report.print_warnings()
        report.print_danger()




def main():
    """Entry of the script."""
    check_one_file()


if __name__ == "__main__":
    main()
