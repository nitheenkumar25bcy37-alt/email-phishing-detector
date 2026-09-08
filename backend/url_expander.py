"""Safe, bounded URL-shortener expansion using HTTP HEAD requests only."""

from typing import Any, Dict
from urllib.parse import urljoin, urlparse

import requests


class URLExpander:
    @staticmethod
    def expand(url: str, timeout: float = 3.0, max_redirects: int = 5) -> Dict[str, Any]:
        original = str(url or "")
        current = original
        chain = []
        session = requests.Session()
        session.headers.update({"User-Agent": "NETRA-Mail-URL-Analyzer/1.0"})

        try:
            for _ in range(max_redirects + 1):
                parsed = urlparse(current)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    return {"original_url": original, "final_url": current, "redirect_chain": chain, "expanded": False, "error": "unsupported_url"}

                response = session.head(
                    current,
                    allow_redirects=False,
                    timeout=timeout,
                )
                chain.append({"url": current, "status_code": response.status_code})
                location = response.headers.get("Location")
                if response.status_code not in {301, 302, 303, 307, 308} or not location:
                    return {"original_url": original, "final_url": current, "redirect_chain": chain, "expanded": current != original}
                current = urljoin(current, location)

            return {"original_url": original, "final_url": current, "redirect_chain": chain, "expanded": current != original, "error": "redirect_limit_exceeded"}
        except requests.RequestException as exc:
            return {"original_url": original, "final_url": current, "redirect_chain": chain, "expanded": False, "error": type(exc).__name__}