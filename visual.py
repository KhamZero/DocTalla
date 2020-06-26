"""Visual interface for Project."""
import tkinter as tk
from tkinter import filedialog, Button, messagebox
import os
from doc_analyzer import Report, FileAnalytics, FileManager


class VisualApplication(tk.Frame):
    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.parent = parent
        self.add_button()

    def add_button(self):
        B = Button(root, text="Выбрать файл для анализа",
                   command=self.analyze_file)
        B.place(x=50, y=50)

    def analyze_file(self):
        """Analyze the file."""
        file_path = self.select_file()

        analyzer = FileAnalytics(file_path)
        analyze_results = analyzer.macros_infos

        report = Report(analyze_results)
        messagebox.showinfo("Репорт", report.get_result())
        
        report.print_warnings()
        report.print_danger()

    def select_file(self):
        """Run dialog to select file."""
        currdir = os.getcwd()
        file_selected = filedialog.askopenfilename(
            parent=root, initialdir=currdir, title='Please select a file')
        if len(file_selected) > 0:
            print("You chose: %s" % file_selected)
        return file_selected


if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("500x500")

    VisualApplication(root).pack(side="top", fill="both", expand=True)
    root.mainloop()
