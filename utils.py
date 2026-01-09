import feedparser
from typing import List, Dict, Any, Set
import requests

def to_json_url(link: str) -> str:
    return link.rstrip("/") + "/json/"