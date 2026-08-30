import unittest
import os
import tempfile
from tools.file_tools import ReadFileTool, WriteFileTool, CreateDirectoryTool, ListDirectoryTool, SearchFilesTool
from tools.web import FetchURLTool
from tools.report_tools import ExportMarkdownTool, ExportPDFTool, ExportDocxTool
from tools.document_tools import ReadPDFTool, ReadMarkdownTool, ParseJSONTool

class TestCoreTools(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for safe testing
        self.test_dir = tempfile.mkdtemp(dir=os.getcwd())
        self.test_file = os.path.join(self.test_dir, "test.txt")
        self.test_md = os.path.join(self.test_dir, "test.md")
        self.test_pdf = os.path.join(self.test_dir, "test.pdf")
        self.test_docx = os.path.join(self.test_dir, "test.docx")

    def tearDown(self):
        # Cleanup
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_write_and_read_file(self):
        writer = WriteFileTool()
        reader = ReadFileTool()
        
        write_res = writer.execute(path=self.test_file, content="Hello Tools")
        self.assertIn("Successfully", write_res)
        
        read_res = reader.execute(path=self.test_file)
        self.assertEqual(read_res, "Hello Tools")

    def test_directory_tools(self):
        creator = CreateDirectoryTool()
        lister = ListDirectoryTool()
        new_dir = os.path.join(self.test_dir, "new_folder")
        
        creator.execute(path=new_dir)
        self.assertTrue(os.path.exists(new_dir))
        
        list_res = lister.execute(path=self.test_dir)
        self.assertIn("new_folder", list_res)

    def test_search_files(self):
        writer = WriteFileTool()
        writer.execute(path=os.path.join(self.test_dir, "target_file.json"), content="{}")
        searcher = SearchFilesTool()
        
        # Searching relative to the test directory name since base_dir is cwd
        dir_name = os.path.basename(self.test_dir)
        res = searcher.execute(pattern="*.json", directory=dir_name)
        self.assertIn("target_file.json", res)

    def test_export_markdown(self):
        md_exporter = ExportMarkdownTool()
        md_reader = ReadMarkdownTool()
        
        md_exporter.execute(path=self.test_md, content="# Title\\nContent")
        read_md = md_reader.execute(path=self.test_md)
        self.assertIn("# Title", read_md)

    def test_export_pdf(self):
        pdf_exporter = ExportPDFTool()
        pdf_reader = ReadPDFTool()
        
        pdf_exporter.execute(path=self.test_pdf, content="PDF Content", title="Test PDF")
        self.assertTrue(os.path.exists(self.test_pdf))
        
        read_pdf = pdf_reader.execute(path=self.test_pdf)
        self.assertIn("PDF Content", read_pdf)

    def test_export_docx(self):
        docx_exporter = ExportDocxTool()
        docx_exporter.execute(path=self.test_docx, content="DOCX Content", title="Test DOCX")
        self.assertTrue(os.path.exists(self.test_docx))

    def test_parse_json(self):
        parser = ParseJSONTool()
        res = parser.execute(json_string='{"key": "value"}')
        self.assertIn('"key": "value"', res)
        
        bad_res = parser.execute(json_string='invalid')
        self.assertIn("Invalid JSON", bad_res)

    def test_fetch_url(self):
        # We will test a known safe URL and expect a timeout or valid response without crashing
        fetcher = FetchURLTool()
        res = fetcher.execute(url="http://example.com")
        self.assertTrue("Status Code" in res or "Error" in res)

if __name__ == '__main__':
    unittest.main()
