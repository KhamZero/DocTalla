"""Visual interface for Project."""
import queue
import tkinter as tk
from tkinter import ttk, VERTICAL, HORIZONTAL, N, S, E, W
from tkinter import filedialog, Button
import os
from doc_analyzer import Report, FileAnalytics
from doc_cleaner import DocCleaner
from pathlib import Path
import logging
from tkinter.scrolledtext import ScrolledText
import signal

logger = logging.getLogger(__name__)


class QueueHandler(logging.Handler):
    """Send logging records to a queue."""

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        self.log_queue.put(record)


class BottomUi:
    def __init__(self, frame):
        self.frame = frame
        ttk.Label(self.frame, text='Программа распространяется свободно. Грозный 2020').grid(
            column=0, row=1, sticky=W)


class ConsoleUi:
    """Poll the messages from a logging queue and display them in a widget."""

    def __init__(self, frame):
        self.frame = frame
        # Create a ScrolledText wdiget
        self.scrolled_text = ScrolledText(frame, state='disabled', height=12)
        self.scrolled_text.grid(row=0, column=0, sticky=(N, S, W, E))
        self.scrolled_text.configure(font='TkFixedFont')
        self.scrolled_text.tag_config('INFO', foreground='black')
        self.scrolled_text.tag_config('DEBUG', foreground='gray')
        self.scrolled_text.tag_config('WARNING', foreground='orange')
        self.scrolled_text.tag_config('ERROR', foreground='red')
        self.scrolled_text.tag_config(
            'CRITICAL', foreground='red', underline=1)
        # Create a logging handler using a queue
        self.log_queue = queue.Queue()
        self.queue_handler = QueueHandler(self.log_queue)
        formatter = logging.Formatter('%(message)s')
        self.queue_handler.setFormatter(formatter)
        logger.addHandler(self.queue_handler)
        # Start polling messages from the queue
        self.frame.after(100, self.poll_log_queue)

    def display(self, record):
        msg = self.queue_handler.format(record)
        self.scrolled_text.configure(state='normal')
        self.scrolled_text.insert(tk.END, msg + '\n', record.levelname)
        self.scrolled_text.configure(state='disabled')
        # Autoscroll to the bottom
        self.scrolled_text.yview(tk.END)

    def poll_log_queue(self):
        # Check every 100ms if there is a new message in the queue to display
        while True:
            try:
                record = self.log_queue.get(block=False)
            except queue.Empty:
                break
            else:
                self.display(record)
        self.frame.after(100, self.poll_log_queue)


class FormUi:
    """Leftside form with buttons."""

    def __init__(self, frame):
        self.frame = frame
        # Create a combobbox to select the scans
        Button(
            self.frame, text="Выбрать файл для анализа", command=self.analyze_file).grid(
            column=0, row=1, sticky=W, padx=10, pady=10)

        Button(
            self.frame, text="Выберите директорию для анализа",
            command=self.analyze_directory).grid(column=0, row=2, sticky=W, padx=10, pady=10)

        Button(
            self.frame, text="Посмотреть VBA код файла",
            command=self.extract_vba).grid(column=0, row=3, sticky=W, padx=10, pady=10)

        Button(
            self.frame, text="Очистить файл",
            command=self.clean_file).grid(column=0, row=4, sticky=W, padx=10, pady=10)

    def select_file(self):
        """Run dialog to select file."""
        currdir = os.getcwd()
        file_selected = filedialog.askopenfilename(
            parent=self.frame, initialdir=currdir, title="Please select a file")
        if len(file_selected) > 0:
            print("You chose: %s" % file_selected)
        return file_selected

    def select_directory(self):
        """Run dialog to select folder."""
        directory_selected = filedialog.askdirectory()
        return directory_selected

    def analyze_file(self):
        """Analyze the file."""
        file_path = self.select_file()

        analyzer = FileAnalytics(file_path)
        # VBA_analyzer = analyzer.is_file_has_VBA_macros()
        analyze_results = analyzer.macros_infos

        report = Report(analyze_results)
        report_result = Path(file_path).name + " " + report.get_result()

        for warning in report.get_warning_message_list():
            logger.log(logging.WARNING, warning)

        for danger in report.get_danger_message_list():
            logger.log(logging.ERROR, danger)

        logger.log(logging.INFO, report_result)
        logger.log(logging.DEBUG, '- '*39)

    def analyze_directory(self):
        """Analyze the file."""
        directoryname = self.select_directory()
        file_paths_in_directory = []
        for p in Path(directoryname).iterdir():
            if p.is_file():
                file_paths_in_directory.append(p)

        for file_path in file_paths_in_directory:
            analyzer = FileAnalytics(file_path)
            analyze_results = analyzer.macros_infos
            report = Report(analyze_results)

            for warning in report.get_warning_message_list():
                logger.log(logging.WARNING, warning)

            for danger in report.get_danger_message_list():
                logger.log(logging.ERROR, danger)

            report_result = Path(file_path).name + " " + report.get_result()
            logger.log(logging.INFO, report_result)
            logger.log(logging.DEBUG, '- '*39)

    def extract_vba(self):
        """Extract vba macros from file."""
        file_path = self.select_file()
        vba = FileAnalytics(file_path)
        vba_code = vba.vba_code

        vba = Path(file_path).name + ":\n\n" + vba_code
        logger.log(logging.DEBUG, vba)
        logger.log(logging.DEBUG, '- '*39)

    def clean_file(self):
        """Analyze the file."""
        file_path = self.select_file()

        cleaner = DocCleaner(file_path)
        clean_results = cleaner.results

        report_result = Path(file_path).name + " " + clean_results
        logger.log(logging.ERROR, report_result)
        logger.log(logging.DEBUG, '- '*39)


class App:
    """Return main application."""

    def __init__(self, root):
        self.root = root
        root.title('Antivirus DocTalla')
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        # Create the panes and frames

        vertical_pane = ttk.PanedWindow(self.root, orient=VERTICAL)
        vertical_pane.grid(row=0, column=0, sticky="nsew")
        horizontal_pane = ttk.PanedWindow(vertical_pane, orient=HORIZONTAL)
        vertical_pane.add(horizontal_pane)

        form_frame = ttk.Labelframe(horizontal_pane, text="Анализатор")
        form_frame.columnconfigure(1, weight=1)
        horizontal_pane.add(form_frame, weight=1)

        console_frame = ttk.Labelframe(
            horizontal_pane, text="Результаты сканирования")
        console_frame.columnconfigure(0, weight=1)
        console_frame.rowconfigure(0, weight=1)
        horizontal_pane.add(console_frame, weight=1)

        third_frame = ttk.Labelframe(vertical_pane, text="Copyright")
        vertical_pane.add(third_frame, weight=1)

        # Initialize all frames
        self.form = FormUi(form_frame)
        self.console = ConsoleUi(console_frame)
        self.third = BottomUi(third_frame)
        self.root.protocol('WM_DELETE_WINDOW', self.quit)
        self.root.bind('<Control-q>', self.quit)
        signal.signal(signal.SIGINT, self.quit)

    def quit(self, *args):
        self.root.destroy()


def main():
    logging.basicConfig(level=logging.DEBUG)
    root = tk.Tk()
    app = App(root)
    app.root.mainloop()


if __name__ == "__main__":
    main()
