import os
import requests
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QProgressBar, QPushButton, QFileDialog, QVBoxLayout, QWidget
from PyQt5.QtCore import QThread, pyqtSignal

class AntivirusScanner(QMainWindow):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('AVation -Samir Sengupta')
        self.setGeometry(100, 100, 500, 300)

        self.output_text = QTextEdit(self)
        self.output_text.setReadOnly(True)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setGeometry(50, 200, 400, 20)

        self.full_scan_button = QPushButton('Full PC Scan', self)
        self.full_scan_button.clicked.connect(self.full_scan)

        self.folder_scan_button = QPushButton('Folder Scan', self)
        self.folder_scan_button.clicked.connect(self.folder_scan)

        self.stop_button = QPushButton('Stop Scan', self)
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)

        layout = QVBoxLayout()
        layout.addWidget(self.output_text)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.full_scan_button)
        layout.addWidget(self.folder_scan_button)
        layout.addWidget(self.stop_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.scan_thread = None

    def full_scan(self):
        self.scan_thread = ScanThread('C:\\', self.progress_bar, self.output_text)
        self.scan_thread.scan_result_signal.connect(self.update_output)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()
        self.full_scan_button.setEnabled(False)
        self.folder_scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)

    def folder_scan(self):
        folder_path = QFileDialog.getExistingDirectory(self, 'Select Folder to Scan')
        if folder_path:
            self.scan_thread = ScanThread(folder_path, self.progress_bar, self.output_text)
            self.scan_thread.scan_result_signal.connect(self.update_output)
            self.scan_thread.finished.connect(self.scan_finished)
            self.scan_thread.start()
            self.full_scan_button.setEnabled(False)
            self.folder_scan_button.setEnabled(False)
            self.stop_button.setEnabled(True)

    def stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop()
            self.full_scan_button.setEnabled(True)
            self.folder_scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def update_output(self, message):
        self.output_text.append(message)

    def scan_finished(self):
        self.full_scan_button.setEnabled(True)
        self.folder_scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)

class ScanThread(QThread):
    scan_result_signal = pyqtSignal(str)

    def __init__(self, scan_path, progress_bar, output_text):
        super().__init__()
        self.scan_path = scan_path
        self.progress_bar = progress_bar
        self.output_text = output_text
        self._stop = False

    def stop(self):
        self._stop = True

    def scan_file(self, api_key, file_path):
        try:
            url = 'https://www.virustotal.com/vtapi/v2/file/scan'
            params = {'apikey': api_key}

            with open(file_path, 'rb') as file:
                files = {'file': (file_path, file)}
                response = requests.post(url, files=files, params=params)

            result = response.json()
            return result
        except (PermissionError, FileNotFoundError):
            return None
        except ValueError as e:
            print(f"Error decoding JSON for file {file_path}: {e}")
            print("Response content:", response.content)
            return None

    def get_scan_report(self, api_key, resource):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': api_key, 'resource': resource}
        response = requests.get(url, params=params)

        try:
            result = response.json()
            return result
        except ValueError as e:
            print(f"Error decoding JSON for resource {resource}: {e}")
            print("Response content:", response.content)
            return None

    def run(self):
        api_key = '3a4041e72df3d6abb16150af81d73a81734204fcbffb4cb3f420938c433f3916'
        total_files = sum(len(files) for _, _, files in os.walk(self.scan_path))
        current_file = 0

        for root, dirs, files in os.walk(self.scan_path):
            for file_name in files:
                if self._stop:
                    return

                file_path = os.path.join(root, file_name)

                # Update progress
                current_file += 1
                progress_value = int((current_file / total_files) * 100)
                self.progress_bar.setValue(progress_value)

                # Step 1: Scan the file
                scan_result = self.scan_file(api_key, file_path)

                if scan_result and 'resource' in scan_result:
                    resource = scan_result['resource']

                    # Step 2: Retrieve the scan report using the resource from the scan result
                    report = self.get_scan_report(api_key, resource)

                    if report:
                        if 'positives' in report and report['positives'] > 0:
                            message = f"Detected as malicious: {file_path}"
                            self.scan_result_signal.emit(message)
                        else:
                            message = f"Clean: {file_path}"
                            self.scan_result_signal.emit(message)

        self.scan_result_signal.emit("Scan finished.")

if __name__ == '__main__':
    app = QApplication([])
    window = AntivirusScanner()
    window.show()
    app.exec_()
