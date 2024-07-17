from fpdf import FPDF
import pandas as pd
import logging
from typing import Dict, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PDFReport(FPDF):
    def __init__(self, start_date: str, end_date: str):
        super().__init__()
        self.start_date = start_date
        self.end_date = end_date
        self.alias_nb_pages()

    def header(self):
        self.set_font('Arial', 'B', 14)
        self.cell(0, 10, 'Panorama Analysis Report', 0, 1, 'L')
        self.set_font('Arial', '', 12)
        self.cell(0, 10, f'{self.start_date} to {self.end_date}', 0, 1, 'L')
        self.image('organization_logo.png', x=170, y=10, w=30)
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'R')

    def chapter_title(self, title: str):
        self.set_font('Arial', 'B', 12)
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, title, 0, 1, 'L')
        self.ln(5)

    def chapter_body(self, body: str):
        self.set_font('Arial', '', 12)
        self.set_text_color(0, 0, 0)
        if body:
            self.multi_cell(0, 10, body)
        self.ln()

    def add_image(self, image_path: str, x: Optional[float] = None, y: Optional[float] = None, w: float = 0, h: float = 0):
        self.image(image_path, x=x, y=y, w=w, h=h)

    def add_table(self, data: pd.DataFrame, col_widths: Dict[str, float]):
        self.set_font('Arial', 'B', 12)
        for header in data.columns:
            self.cell(col_widths[header], 10, header, 1, 0, 'C')
        self.ln()

        self.set_font('Arial', '', 12)
        for index, row in data.iterrows():
            for col in data.columns:
                self.cell(col_widths[col], 10, str(row[col]), 1, 0, 'C')
            self.ln()
        self.ln()

def print_and_append(pdf: PDFReport, message: str, to_terminal: bool = True):
    if to_terminal:
        logger.info(message)
    pdf.chapter_body(message)