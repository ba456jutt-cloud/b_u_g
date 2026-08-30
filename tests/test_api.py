import unittest
from fastapi.testclient import TestClient
from api.main import app

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_read_root(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("status", response.json())
        self.assertEqual(response.json()["status"], "Active")

    def test_list_agents(self):
        response = self.client.get("/agents")
        self.assertEqual(response.status_code, 200)
        self.assertIn("agents", response.json())

    def test_submit_task(self):
        payload = {"task": "test this task", "workflow": "default"}
        response = self.client.post("/tasks", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "Task Queued")
        self.assertEqual(response.json()["task"], "test this task")

    def test_get_memory_stats(self):
        # Even if DB is empty, it should return 200 and a dict of counts
        response = self.client.get("/memory")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Memory System Online", response.json()["status"])

    def test_get_knowledge_base(self):
        response = self.client.get("/knowledge")
        self.assertEqual(response.status_code, 200)
        self.assertIn("RAG System Online", response.json()["status"])

if __name__ == '__main__':
    unittest.main()
