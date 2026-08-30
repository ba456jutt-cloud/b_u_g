import unittest
from tools.memory_tools import SaveMemoryTool, RetrieveMemoryTool

class TestMemoryTools(unittest.TestCase):
    def test_memory_save_and_retrieve(self):
        saver = SaveMemoryTool()
        retriever = RetrieveMemoryTool()

        test_key = "test_memory_key_999"
        test_val = "This is a memory test."

        save_res = saver.execute(key=test_key, value=test_val)
        self.assertIn("Saved", save_res)

        ret_res = retriever.execute(key=test_key)
        self.assertEqual(ret_res, test_val)

if __name__ == '__main__':
    unittest.main()
