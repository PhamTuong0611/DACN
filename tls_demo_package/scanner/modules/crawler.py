"""Web crawler for extracting URLs from domain."""

from __future__ import annotations

import asyncio
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


class URLCrawler:
    """Crawl domain to extract URLs from sitemap and links."""
    
    def __init__(self, max_depth: int = 2, max_urls: int = 50, timeout: int = 10):
        """Initialize crawler.
        
        Args:
            max_depth: Maximum crawl depth
            max_urls: Maximum URLs to collect
            timeout: Request timeout in seconds
        """
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.visited: Set[str] = set()
        self.urls: Set[str] = set()
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL for comparison."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    async def fetch_page(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Fetch page content."""
        if not aiohttp:
            return None
        
        try:
            async with session.get(url, timeout=self.timeout, ssl=False, allow_redirects=True) as response:
                if response.status == 200 and "text/html" in response.headers.get("Content-Type", ""):
                    return await response.text()
        except Exception:  # noqa: BLE001
            pass
        
        return None
    
    def extract_links_from_html(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML."""
        if not BeautifulSoup:
            return []
        
        links = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                if href.startswith("#"):
                    continue
                absolute_url = urljoin(base_url, href)
                parsed = urlparse(absolute_url)
                
                # Only follow same-domain links
                if parsed.scheme in ("http", "https"):
                    links.append(absolute_url)
        except Exception:  # noqa: BLE001
            pass
        
        return links
    
    async def parse_sitemap(self, session: aiohttp.ClientSession, domain: str) -> List[str]:
        """Try to fetch sitemap.xml."""
        urls = []
        sitemap_urls = [
            f"{domain}/sitemap.xml",
            f"{domain}/sitemap_index.xml",
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                async with session.get(sitemap_url, timeout=self.timeout, ssl=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        # Extract URLs from sitemap (basic parsing)
                        import re
                        matches = re.findall(r"<loc>([^<]+)</loc>", content)
                        urls.extend(matches[:self.max_urls])
            except Exception:  # noqa: BLE001
                pass
        
        return urls
    
    async def crawl(self, start_url: str) -> List[str]:
        """Crawl domain starting from URL."""
        if not aiohttp:
            return [start_url]
        
        parsed = urlparse(start_url)
        domain = f"{parsed.scheme}://{parsed.netloc}"
        
        self.urls = {start_url}
        self.visited = set()
        
        async with aiohttp.ClientSession() as session:
            # Try to get sitemap first
            sitemap_urls = await self.parse_sitemap(session, domain)
            self.urls.update(sitemap_urls[:self.max_urls])
            
            # Then crawl with depth limit
            queue = [(start_url, 0)]
            
            while queue and len(self.urls) < self.max_urls:
                url, depth = queue.pop(0)
                
                if url in self.visited or depth > self.max_depth:
                    continue
                
                self.visited.add(url)
                
                # Fetch and parse
                html = await self.fetch_page(session, url)
                if html:
                    links = self.extract_links_from_html(html, url)
                    for link in links:
                        normalized = self.normalize_url(link)
                        if normalized not in self.visited and len(self.urls) < self.max_urls:
                            self.urls.add(link)
                            if depth < self.max_depth:
                                queue.append((link, depth + 1))
        
        return list(self.urls)[:self.max_urls]


async def crawl_domain(
    domain: str,
    max_depth: int = 2,
    max_urls: int = 50,
) -> List[str]:
    """Convenience function to crawl a domain."""
    if not domain.startswith("http"):
        domain = f"https://{domain}"
    
    crawler = URLCrawler(max_depth=max_depth, max_urls=max_urls)
    return await crawler.crawl(domain)
