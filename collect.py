import feedparser
import requests
from typing import List, Dict, Any, Set

class Collector:
    rss_url = "https://www.cert.ssi.gouv.fr/avis/feed/"
    timeout = 5

    @staticmethod
    def get_rss_entries(url) -> feedparser.util.FeedParserDict:
        rss_feed = feedparser.parse(url)
        return rss_feed.entries

    @staticmethod
    def fetch_json(url: str) -> Dict[str, Any]:
        r = requests.get(url, timeout=Collector.timeout)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def fetch_mitre(cve_id: str) -> Dict[str, Any]:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        r = requests.get(url, timeout=Collector.timeout)
        r.raise_for_status()
        return r.json()

    @staticmethod
    def fetch_epss(cve_id: str) -> Dict[str, Any]:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        r = requests.get(url, timeout=Collector.timeout)
        r.raise_for_status()
        return r.json()