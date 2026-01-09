from typing import List, Dict, Any, Set
import feedparser
import requests
import re
from collect import Collector

class Enrichment:
    """
    Explorer
    --------
    - Extract CVEs from CERT-FR RSS feeds
    - Enrich CVEs with MITRE & EPSS data
    """

    def __init__(
        self,
        enrich_limit: int = 10,
        timeout: int = 10,
    ) -> None:
        self.enrich_limit = enrich_limit
        self.timeout = timeout

    # ---------------------------
    # Enrichment (MITRE / EPSS)
    # ---------------------------
    
    def enrich_cve(self, cve_id: str) -> Dict[str, Any]:
        description: str = "Non disponible"
        cvss_score: str | float = "Non disponible"
        cwe: str = "Non disponible"
        epss_score: str | float = "Non disponible"

        # --- MITRE ---
        try:
            mitre = Collector.fetch_mitre(cve_id)
            cna = mitre["containers"]["cna"]

            descs = cna.get("descriptions", [])
            if descs:
                description = descs[0].get("value", description)

            metrics = cna.get("metrics", [])
            if metrics:
                m0 = metrics[0]
                if "cvssV3_1" in m0:
                    cvss_score = m0["cvssV3_1"].get("baseScore", cvss_score)
                elif "cvssV3_0" in m0:
                    cvss_score = m0["cvssV3_0"].get("baseScore", cvss_score)

            problemtype = cna.get("problemTypes", [])
            if problemtype and problemtype[0].get("descriptions"):
                cwe = problemtype[0]["descriptions"][0].get("cweId", cwe)

        except Exception:
            pass

        # --- EPSS ---
        try:
            epss = Collector.fetch_epss(cve_id)
            data = epss.get("data", [])
            if data:
                epss_score = data[0].get("epss", epss_score)
        except Exception:
            pass

        return {
            "cve": cve_id,
            "description": description,
            "cvss": cvss_score,
            "cwe": cwe,
            "epss": epss_score,
        }
