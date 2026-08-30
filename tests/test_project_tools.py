import unittest
import os
from tools.project_tools import CreateProjectTool, ArchiveProjectTool

class TestProjectTools(unittest.TestCase):
    def setUp(self):
        self.project_name = "test_engagement_123"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.project_name, ignore_errors=True)
        if os.path.exists(self.project_name + ".zip"):
            os.remove(self.project_name + ".zip")

    def test_create_and_archive_project(self):
        creator = CreateProjectTool()
        archiver = ArchiveProjectTool()

        # Create
        res = creator.execute(project_name=self.project_name)
        self.assertIn("initialized", res)
        self.assertTrue(os.path.exists(os.path.join(self.project_name, "recon")))
        self.assertTrue(os.path.exists(os.path.join(self.project_name, "vulns")))

        # Archive
        arch_res = archiver.execute(project_name=self.project_name)
        self.assertIn("archived", arch_res)
        self.assertTrue(os.path.exists(self.project_name + ".zip"))

if __name__ == '__main__':
    unittest.main()
