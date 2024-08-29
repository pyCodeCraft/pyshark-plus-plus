import unittest
from unittest.mock import patch, MagicMock
from pyshark_plus_plus import TsharkWrapper

MODULE_PATH = "pyshark_plus_plus.pyshark_plus_plus"


class TestTsharkWrapper(unittest.TestCase):

    @patch(f"{MODULE_PATH}.os.path.exists")
    def test_init_with_invalid_file_path(self, mock_exists):
        mock_exists.return_value = False
        with self.assertRaises(Exception) as context:
            TsharkWrapper(file_path="invalid/path.pcap")
        self.assertIn("Path invalid/path.pcap does not exist", str(context.exception))

    @patch(f"{MODULE_PATH}.os.path.exists")
    def test_init_with_valid_file_path(self, mock_exists):
        mock_exists.return_value = True
        wrapper = TsharkWrapper(file_path="valid/path.pcap")
        self.assertEqual(wrapper.file_path, "valid/path.pcap")

    @patch(f"{MODULE_PATH}.subprocess.run")
    def test_list_interfaces(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "1. eth0\n2. wlan0\n"
        mock_run.return_value = mock_result

        wrapper = TsharkWrapper()
        interfaces = wrapper.list_interfaces()
        self.assertIn("1. eth0", interfaces)
        self.assertIn("2. wlan0", interfaces)

    @patch(f"{MODULE_PATH}.subprocess.Popen")
    def test_start_capture(self, mock_popen):
        mock_process = MagicMock()
        mock_process.communicate.return_value = ("", "")
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        wrapper = TsharkWrapper(interface="1", file_path="capture.pcap")
        returncode = wrapper.start_capture(duration=10)
        self.assertEqual(returncode, 0)

    @patch("subprocess.run")
    def test_read_pcap(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Packet data"
        mock_run.return_value = mock_result

        wrapper = TsharkWrapper()
        data = wrapper.read_pcap("capture.pcap")
        self.assertEqual(data, "Packet data")

    @patch(f"{MODULE_PATH}.subprocess.run")
    def test_apply_filter(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Filtered packet data"
        mock_run.return_value = mock_result

        wrapper = TsharkWrapper()
        filtered_data = wrapper.apply_filter("capture.pcap", "tcp")
        self.assertEqual(filtered_data, "Filtered packet data")

    @patch(f"{MODULE_PATH}.subprocess.run")
    def test_get_statistics(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "IO statistics"
        mock_run.return_value = mock_result

        with patch(f"{MODULE_PATH}.parse_io_statistics", return_value={"packets": 100}):
            wrapper = TsharkWrapper(file_path="capture.pcap")
            stats = wrapper.get_statistics()
            self.assertEqual(stats, {"packets": 100})

    @patch(f"{MODULE_PATH}.threading.Thread")
    def test_start_thread(self, mock_thread):
        mock_thread_obj = MagicMock()
        mock_thread.return_value = mock_thread_obj
        wrapper = TsharkWrapper()
        wrapper.start_thread()
        mock_thread_obj.start.assert_called_once()
        self.assertTrue(wrapper._thread.is_alive())

    @patch(f"{MODULE_PATH}.subprocess.Popen")
    def test_stop_thread(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        wrapper = TsharkWrapper()
        wrapper.start_thread()
        wrapper._process_capture = mock_process
        wrapper.stop_thread()
        mock_process.terminate.assert_called_once()
        mock_process.wait.assert_called_once()
        self.assertTrue(wrapper._event.is_set())


if __name__ == '__main__':
    unittest.main()
