import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QLabel, QMessageBox
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import QSize, Qt
# Import the DecompilerApp from the main code file
from A2ForensicsKit import DecompilerApp



class FrontPageUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()  # Ensure this call matches the method name

    def initUI(self):
        self.setWindowTitle('A2ForensicsKit')
        self.setGeometry(100, 100, 800, 600)

        layout = QVBoxLayout()

    # Logo
        logo_label = QLabel(self)
        logo_pixmap = QPixmap('logo1.png')  # Ensure the logo file path is correct
        scaled_logo = logo_pixmap.scaled(QSize(200, 100), Qt.KeepAspectRatio, Qt.SmoothTransformation)  # Scale logo while keeping the aspect ratio
        logo_label.setPixmap(scaled_logo)
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        # Header layout with stretch to center the header label
        header_layout = QHBoxLayout()
        header_layout.addStretch(1)
        header = QLabel('A2 Forensics Kit', self)
        header.setStyleSheet("""
        font-size: 44px; 
        font-weight: bold; 
        font-style: italic; 
        text-align: center; 
        color: #101660; 
        font-family: 'Arial'; 
        """)
        header.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(header)
        header_layout.addStretch(1)
        layout.addLayout(header_layout)
        # About button with PNG icon
        btnAbout = QPushButton('About', self)
        self.setAboutButtonIcon(btnAbout)
        btnAbout.clicked.connect(self.showAbout)
        btnAbout.setStyleSheet("font-size: 12pt; font-weight: bold; color: black; padding: 5px;")
        layout.addWidget(btnAbout)

        # APK Analysis button
        btnAnalysis = QPushButton('Apk File Analysis', self)
        self.setAPKAnalysisButtonIcon(btnAnalysis)  # Call the method to set the icon
        btnAnalysis.clicked.connect(self.openAPKAnalysis)
        btnAnalysis.setStyleSheet("font-size: 12pt; font-weight: bold; ; color: black; padding: 5px;")
        layout.addWidget(btnAnalysis)

        btnDownloads = QPushButton('Exit', self)
        self.setDownloadsButtonIcon(btnDownloads)  # Call the method to set the icon
        btnDownloads.setStyleSheet("font-size: 12pt; font-weight: bold; ; color: black; padding: 5px;")
        btnDownloads.clicked.connect(self.exitApplication)  # Connect the button to the exitApplication method
        layout.addWidget(btnDownloads)

        centralWidget = QWidget()
        centralWidget.setLayout(layout)
        self.setCentralWidget(centralWidget)

        # Apply stylesheet
        self.setStyleSheet(
            "QMainWindow { background-color: #598BB7; }"  # Dark blue background color for the main window
            "QLabel { color: black; }"  # White text color for labels
            "QPushButton { "
            "    background-color: #6C93FF; "  # Light blue for buttons
            "    border: 2px solid #555; "  # Grey border for buttons
            "    padding: 5px; "
            "    border-radius: 3px; "
            "}"  
            "QPushButton:hover { "
            "    background-color: #384E90; "  # Slightly lighter grey for button hover
            "}"
        )

    def setAboutButtonIcon(self, button):
        icon_path = r'about.png'
        pixmap = QPixmap(icon_path)
        icon = QIcon(pixmap)
        button.setIcon(icon)
        button.setIconSize(QSize(150, 150))

    def setAPKAnalysisButtonIcon(self, button):
        icon_path = r'analysis.png'
        pixmap = QPixmap(icon_path)
        icon = QIcon(pixmap)
        button.setIcon(icon)
        button.setIconSize(QSize(150, 150))

    def setDownloadsButtonIcon(self, button):
        icon_path = r'exit.png'
        pixmap = QPixmap(icon_path)
        icon = QIcon(pixmap)
        button.setIcon(icon)
        button.setIconSize(QSize(150, 150))

    def showAbout(self):
        about_message = "<b><u>A2ForensicsKit</u>, is an innovative mobile security toolkit designed for simplicity and effectiveness. It integrates advanced features like Reverse engineering and Static Vulnerability Analysis for APK files, making comprehensive forensic analysis accessible to users of all skill levels.</b>"
        QMessageBox.information(self, 'About A2ForensicsKit', about_message)

    def openAPKAnalysis(self):
        self.hide()  # Hide the current window
        self.decompilerApp = DecompilerApp(self)  # Pass self as the reference to FrontPageUI
        self.decompilerApp.show()

    def exitApplication(self):
        reply = QMessageBox.question(self, 'Exit Confirmation', 'Are you sure you want to exit A2ForensicsKit?', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            QApplication.quit()  # Close the application

if __name__ == '__main__':
    app = QApplication(sys.argv)
    frontPageUI = FrontPageUI()
    frontPageUI.show()
    sys.exit(app.exec_())
