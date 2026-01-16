from typing import Collection, List, Dict, Any, Set
import requests
import re

from collect import Collector
from utils import to_json_url

class Extractor:
    rss_limit = 5

    @staticmethod    
    def extract_cves(data):
        # 1) CVE référencés via la clé "cves"
        ref_cves = []
        if "cves" in data:
            ref_cves = list(data["cves"])  # liste de dict {name, url}

        # 2) Extraction via regex (comme dans l'extrait)
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list = list(set(re.findall(cve_pattern, str(data))))

        print(type(ref_cves), type(cve_list))
        return ref_cves, cve_list

    @staticmethod
    def extract_cves_from_bulletin(data: Dict[str, Any]) -> List[str]:
        cves: Set[str] = set()

        # Method 1: explicit CVE list
        if "cves" in data:
            for x in data["cves"]:
                if isinstance(x, dict) and "name" in x:
                    cves.add(x["name"])

        # Method 2: regex fallback
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        for c in re.findall(cve_pattern, str(data)):
            cves.add(c)

        return sorted(cves)

    @staticmethod  
    def extract_cves_from_rss(entries) -> List[str]:
        print("Nombre d'entrées RSS :", len(entries))

        all_cves: Set[str] = set()

        for entry in entries[: Extractor.rss_limit]:
            print("\nBulletin :", entry.title)
            print("Lien :", entry.link)

            json_url = to_json_url(entry.link)
            print("JSON :", json_url)

            try:
                data = Collector.fetch_json(json_url)
            except Exception as e:
                print("Erreur JSON :", e)
                continue

            cves = Extractor.extract_cves_from_bulletin(data)
            print("CVE trouvées :", cves)

            all_cves.update(cves)

        return sorted(all_cves)
