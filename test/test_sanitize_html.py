import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

import utils


class SanitizeHtmlTests(unittest.TestCase):
    def test_legacy_cleaner_is_not_shared_between_concurrent_requests(self):
        barrier = threading.Barrier(2)

        class ConcurrentCleaner:
            def __init__(self, **kwargs):
                self.lock = threading.Lock()
                self.active = 0

            def clean(self, text):
                with self.lock:
                    self.active += 1
                try:
                    barrier.wait(timeout=5)
                    with self.lock:
                        if self.active > 1:
                            raise RuntimeError("Cleaner shared between requests")
                    return text
                finally:
                    with self.lock:
                        self.active -= 1

        shared_cleaner = ConcurrentCleaner()
        with mock.patch.object(utils, "_USE_CSS_SANITIZER", False), \
             mock.patch.object(utils, "_CLEANER", shared_cleaner, create=True), \
             mock.patch.object(utils, "Cleaner", ConcurrentCleaner, create=True):
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(utils.sanitize_html, ["<p>one</p>", "<p>two</p>"]))
        self.assertEqual(results, ["<p>one</p>", "<p>two</p>"])

    def test_html_sanitization_still_removes_unsafe_markup(self):
        html = '<p class="ok" onclick="alert(1)">hello<script>alert(2)</script></p>'
        result = utils.sanitize_html(html)
        self.assertIn('<p class="ok">', result)
        self.assertNotIn("<script", result)
        self.assertNotIn("onclick", result)

    def test_concurrent_sanitization_matches_sequential_results(self):
        fragments = [
            '<div><p>report-{}</p><ul><li>one</li><li>two</li></ul></div>'.format(i)
            for i in range(60)
        ]
        expected = [utils.sanitize_html(fragment) for fragment in fragments]
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(utils.sanitize_html, fragments))
        self.assertEqual(results, expected)


if __name__ == "__main__":
    unittest.main()
