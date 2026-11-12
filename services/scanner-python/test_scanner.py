import unittest

import httpx

from scanner_service.main import fingerprint, javascript_facts


class FingerprintTest(unittest.TestCase):
    def test_detects_wappalyzer_style_categories_and_versions(self) -> None:
        html = """
        <html>
          <head>
            <meta property="og:title" content="Example">
            <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/tailwindcss@3.4.17/index.css">
            <script src="https://unpkg.com/@iconify/iconify@1.0.7/dist/iconify.min.js"></script>
            <script src="https://static.cloudflareinsights.com/beacon.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
          </head>
          <body><a href="https://wa.me/621234">Chat</a></body>
        </html>
        """
        response = httpx.Response(
            200,
            headers={"server": "cloudflare", "cf-ray": "fixture", "alt-svc": 'h3=":443"'},
            text=html,
            request=httpx.Request("GET", "https://app.example.com/"),
            extensions={"http_version": b"HTTP/2"},
        )

        facts = fingerprint(response)

        indexed = {fact["name"]: fact for fact in facts}
        self.assertEqual("CDN", indexed["Cloudflare"]["category"])
        self.assertEqual("3.4.17", indexed["Tailwind CSS"]["version"])
        self.assertEqual("1.0.7", indexed["Iconify"]["version"])
        self.assertEqual("3.7.1", indexed["jQuery"]["version"])
        self.assertEqual("RUM", indexed["Cloudflare Browser Insights"]["category"])
        self.assertEqual("Live chat", indexed["WhatsApp Business Chat"]["category"])
        self.assertIn("Open Graph", indexed)
        self.assertIn("HTTP/3", indexed)

    def test_generic_javascript_filename_does_not_create_false_react_fingerprint(self) -> None:
        self.assertEqual([], javascript_facts("https://app.example.com/app.js", "console.log('ready')"))


if __name__ == "__main__":
    unittest.main()
