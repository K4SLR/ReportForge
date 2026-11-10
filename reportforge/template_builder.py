from pathlib import Path
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from .registry import PRESET_CATALOG, PresetConfig


class TemplateBuilder:
    """
    Generates formal, monochrome, Times New Roman, justified
    CSIRT VDP report templates structured like a formal academic makalah/proposal.
    """

    FONT_NAME = "Times New Roman"
    BLACK = RGBColor(0, 0, 0)

    @staticmethod
    def set_table_borders_black(table, sz="4"):
        tbl_pr = table._tbl.tblPr
        borders = tbl_pr.first_child_found_in("w:tblBorders")
        if borders is None:
            borders = OxmlElement("w:tblBorders")
            tbl_pr.append(borders)
        else:
            borders.clear()

        for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
            elem = OxmlElement(f"w:{edge}")
            elem.set(qn("w:val"), "single")
            elem.set(qn("w:sz"), str(sz))
            elem.set(qn("w:space"), "0")
            elem.set(qn("w:color"), "000000")
            borders.append(elem)

    @staticmethod
    def set_table_borderless(table):
        tbl_pr = table._tbl.tblPr
        borders = tbl_pr.first_child_found_in("w:tblBorders")
        if borders is None:
            borders = OxmlElement("w:tblBorders")
            tbl_pr.append(borders)
        else:
            borders.clear()

        for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
            elem = OxmlElement(f"w:{edge}")
            elem.set(qn("w:val"), "nil")
            borders.append(elem)

    @staticmethod
    def clear_cell_shading(cell):
        tc_pr = cell._tc.get_or_add_tcPr()
        for shd in tc_pr.findall(qn("w:shd")):
            tc_pr.remove(shd)

    @staticmethod
    def set_cell_margins(cell, top=100, bottom=100, left=140, right=140):
        tc_pr = cell._tc.get_or_add_tcPr()
        for old_mar in tc_pr.findall(qn("w:tcMar")):
            tc_pr.remove(old_mar)
        tc_mar = OxmlElement("w:tcMar")
        for m_name, val in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
            node = OxmlElement(f"w:{m_name}")
            node.set(qn("w:w"), str(val))
            node.set(qn("w:type"), "dxa")
            tc_mar.append(node)
        tc_pr.append(tc_mar)

    @classmethod
    def configure_document_styles(cls, doc):
        normal_style = doc.styles["Normal"]
        normal_style.font.name = cls.FONT_NAME
        normal_style.font.size = Pt(12)
        normal_style.font.color.rgb = cls.BLACK
        normal_style.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        normal_style.paragraph_format.line_spacing = 1.15
        normal_style.paragraph_format.space_after = Pt(6)

        for level, pt_size in ((1, 14), (2, 13), (3, 12)):
            h_style = doc.styles[f"Heading {level}"]
            h_style.font.name = cls.FONT_NAME
            h_style.font.size = Pt(pt_size)
            h_style.font.bold = True
            h_style.font.color.rgb = cls.BLACK
            h_style.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            h_style.paragraph_format.space_before = Pt(12 if level == 1 else 10)
            h_style.paragraph_format.space_after = Pt(4)

    @classmethod
    def add_formatted_paragraph(
        cls,
        doc,
        text="",
        size_pt=12.0,
        bold=False,
        italic=False,
        align=WD_ALIGN_PARAGRAPH.JUSTIFY,
        space_before=0.0,
        space_after=6.0,
        style_name=None,
    ):
        p = doc.add_paragraph(style=style_name) if style_name else doc.add_paragraph()
        p.alignment = align
        p.paragraph_format.space_before = Pt(space_before)
        p.paragraph_format.space_after = Pt(space_after)
        p.paragraph_format.line_spacing = 1.15
        if text:
            run = p.add_run(text)
            run.font.name = cls.FONT_NAME
            run.font.size = Pt(size_pt)
            run.font.bold = bold
            run.font.italic = italic
            run.font.color.rgb = cls.BLACK
        return p

    @classmethod
    def populate_two_col_table(cls, table, rows_data):
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        cls.set_table_borders_black(table, sz="4")
        col_widths = (Inches(2.37), Inches(3.90))

        for idx, (label_text, val_text) in enumerate(rows_data):
            row = table.rows[idx]
            for c_i, text_val in enumerate((label_text, val_text)):
                cell = row.cells[c_i]
                cell.width = col_widths[c_i]
                cell.vertical_alignment = WD_ALIGN_VERTICAL.TOP
                cls.clear_cell_shading(cell)
                cls.set_cell_margins(cell, top=90, bottom=90, left=120, right=120)

                p = cell.paragraphs[0]
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT if c_i == 0 else WD_ALIGN_PARAGRAPH.JUSTIFY
                p.paragraph_format.space_before = Pt(0)
                p.paragraph_format.space_after = Pt(0)
                p.paragraph_format.line_spacing = 1.15

                run = p.add_run(text_val)
                run.font.name = cls.FONT_NAME
                run.font.size = Pt(12)
                run.font.bold = False
                run.font.color.rgb = cls.BLACK

    @classmethod
    def build_preset_template(cls, config, output_path):
        doc = Document()
        cls.configure_document_styles(doc)

        section = doc.sections[0]
        section.page_width = Inches(8.27)
        section.page_height = Inches(11.69)
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

        cls.add_formatted_paragraph(
            doc,
            text="",
            size_pt=12,
            align=WD_ALIGN_PARAGRAPH.CENTER,
            space_before=36,
            space_after=12,
        )
        cls.add_formatted_paragraph(
            doc,
            text="LAPORAN HASIL PENGUJIAN VULNERABILITY DISCLOSURE PROGRAM",
            size_pt=16,
            bold=True,
            align=WD_ALIGN_PARAGRAPH.CENTER,
            space_before=24,
            space_after=12,
        )
        cls.add_formatted_paragraph(
            doc,
            text="{{ASSET_HEADER}}",
            size_pt=14,
            bold=True,
            align=WD_ALIGN_PARAGRAPH.CENTER,
            space_before=0,
            space_after=140,
        )

        cls.add_formatted_paragraph(
            doc,
            text="{{PROGRAM_BANNER}}",
            size_pt=14,
            bold=True,
            align=WD_ALIGN_PARAGRAPH.CENTER,
            space_before=120,
            space_after=12,
        )

        date_tbl = doc.add_table(rows=1, cols=1)
        date_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        cls.set_table_borderless(date_tbl)
        d_cell = date_tbl.rows[0].cells[0]
        d_cell.width = Inches(6.27)
        cls.clear_cell_shading(d_cell)
        d_p = d_cell.paragraphs[0]
        d_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        d_run = d_p.add_run("{{REPORT_DATE_LONG}}")
        d_run.font.name = cls.FONT_NAME
        d_run.font.size = Pt(12)
        d_run.font.color.rgb = cls.BLACK

        doc.add_page_break()

        cls.add_formatted_paragraph(
            doc,
            text="Informasi Umum",
            size_pt=14,
            bold=True,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=6,
            space_after=6,
            style_name="Heading 1",
        )
        cls.add_formatted_paragraph(
            doc,
            text="Isi informasi dasar mengenai laporan dan aset yang diuji.",
            size_pt=12,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=0,
            space_after=8,
        )

        info_rows = [
            ("Nama Peserta", "{{NAMA_PESERTA}}"),
            ("Nama Alias", "{{NAMA_ALIAS}}"),
            ("Tanggal Pengujian", "{{TANGGAL_PENGUJIAN}}"),
            ("Nama Aset", "{{NAMA_ASET}}"),
            ("Jenis Aset", "{{JENIS_ASET}}"),
            ("Domain/IP", "{{DOMAIN_IP}}"),
            ("Versi Aplikasi (jika diketahui)", "{{VERSI_APLIKASI}}"),
            ("Kontak Penanggung Jawab (opsional)", "{{KONTAK_PJ}}"),
        ]
        info_table = doc.add_table(rows=len(info_rows), cols=2)
        cls.populate_two_col_table(info_table, info_rows)

        cls.add_formatted_paragraph(
            doc,
            text="*Data yang diperoleh akan kami rahasiakan dan tidak akan kami sebar luaskan, karena hanya akan digunakan untuk keperluan Vulnerability Disclosure Program {{ORG_NAME}}.",
            size_pt=11,
            italic=True,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=10,
            space_after=12,
        )

        doc.add_page_break()

        cls.add_formatted_paragraph(
            doc,
            text="Detail Kerentanan",
            size_pt=14,
            bold=True,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=6,
            space_after=6,
            style_name="Heading 1",
        )
        cls.add_formatted_paragraph(
            doc,
            text="Detail kerentanan yang ditemukan.",
            size_pt=12,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=0,
            space_after=8,
        )

        vuln_rows = [
            ("Judul Kerentanan", "{{JUDUL_KERENTANAN}}"),
            ("Kategori (OWASP/CWE/CVE bila ada)", "{{KATEGORI_KERENTANAN}}"),
            ("Aset Terdampak", "{{NAMA_ASET}}"),
            ("Jenis Aset", "{{JENIS_ASET}}"),
            ("Domain/IP", "{{DOMAIN_IP}}"),
            ("URL/Endpoint", "{{URL_ENDPOINT}}"),
            ("Versi Aplikasi (jika diketahui)", "{{VERSI_APLIKASI}}"),
            ("Severity", "{{SEVERITY}}"),
            ("CVSS Score", "{{CVSS_SCORE}}"),
            ("Deskripsi Kerentanan", "{{DESKRIPSI_KERENTANAN}}"),
            ("Dampak", "{{DAMPAK_KERENTANAN}}"),
            ("Rekomendasi Perbaikan", "{{REKOMENDASI_PERBAIKAN}}"),
            ("Referensi", "{{REFERENSI}}"),
        ]
        vuln_table = doc.add_table(rows=len(vuln_rows), cols=2)
        cls.populate_two_col_table(vuln_table, vuln_rows)

        cls.add_formatted_paragraph(
            doc,
            text="Steps to Reproduce",
            size_pt=12,
            bold=True,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=14,
            space_after=6,
            style_name="Heading 3",
        )
        cls.add_formatted_paragraph(
            doc,
            text="{{STEPS_TO_REPRODUCE}}",
            size_pt=12,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=0,
            space_after=10,
        )

        cls.add_formatted_paragraph(
            doc,
            text="Proof of Concept",
            size_pt=12,
            bold=True,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=12,
            space_after=6,
            style_name="Heading 3",
        )
        cls.add_formatted_paragraph(
            doc,
            text="Bukti pengujian (Proof of Concept) berupa rincian paket HTTP Request/Response yang telah disanitasi serta rekomendasi perbaikan kode:",
            size_pt=12,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=0,
            space_after=6,
        )
        cls.add_formatted_paragraph(
            doc,
            text="{{POC_EVIDENCE}}",
            size_pt=11,
            align=WD_ALIGN_PARAGRAPH.LEFT,
            space_before=0,
            space_after=12,
        )

        cls.add_formatted_paragraph(
            doc,
            text="{{ADDITIONAL_FINDINGS_SECTION}}",
            size_pt=12,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=0,
            space_after=0,
        )

        cls.add_formatted_paragraph(
            doc,
            text="Kesimpulan",
            size_pt=14,
            bold=True,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=14,
            space_after=6,
            style_name="Heading 1",
        )
        cls.add_formatted_paragraph(
            doc,
            text="{{KESIMPULAN_PARAGRAF}}",
            size_pt=12,
            align=WD_ALIGN_PARAGRAPH.JUSTIFY,
            space_before=0,
            space_after=12,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc.save(str(output_path))
        return output_path

    @classmethod
    def build_all_templates(cls, templates_dir):
        templates_dir.mkdir(parents=True, exist_ok=True)
        built = []
        for preset_id, cfg in PRESET_CATALOG.items():
            out_file = templates_dir / cfg.template_filename
            cls.build_preset_template(cfg, out_file)
            built.append(out_file)

        custom_path = templates_dir / "csirt_vdp_formal_template.docx"
        cls.build_preset_template(PRESET_CATALOG["nusatech"], custom_path)
        built.append(custom_path)
        return built
