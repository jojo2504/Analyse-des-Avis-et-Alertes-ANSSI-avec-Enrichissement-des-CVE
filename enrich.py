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
        severity: str = "Non disponible"
        products: List[Dict[str, Any]] = []

        # --- MITRE ---
        try:
            print(f"    Récupération MITRE pour {cve_id}...")
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
                    severity = m0["cvssV3_1"].get("baseSeverity", severity)
                elif "cvssV3_0" in m0:
                    cvss_score = m0["cvssV3_0"].get("baseScore", cvss_score)
                    severity = m0["cvssV3_0"].get("baseSeverity", severity)

            problemtype = cna.get("problemTypes", [])
            if problemtype and problemtype[0].get("descriptions"):
                cwe = problemtype[0]["descriptions"][0].get("cweId", cwe)

            # Extraction des produits affectés
            affected = cna.get("affected", [])
            for aff in affected:
                vendor = aff.get("vendor", "N/A")
                product = aff.get("product", "N/A")
                versions = []
                for v in aff.get("versions", []):
                    version_str = v.get("version", "")
                    if version_str:
                        versions.append(version_str)
                products.append({
                    "vendor": vendor,
                    "product": product,
                    "versions": versions
                })
            print(f"MITRE récupéré (CVSS: {cvss_score}, Severity: {severity})")

        except Exception as e:
            print(f"Erreur MITRE: {e}")

        # --- EPSS ---
        try:
            print(f"    Récupération EPSS pour {cve_id}...")
            epss = Collector.fetch_epss(cve_id)
            data = epss.get("data", [])
            if data:
                epss_score = data[0].get("epss", epss_score)
            print(f"EPSS récupéré: {epss_score}")
        except Exception as e:
            print(f"Erreur EPSS: {e}")

        return {
            "cve": cve_id,
            "description": description,
            "cvss": cvss_score,
            "severity": severity,
            "cwe": cwe,
            "epss": epss_score,
            "products": products if products else [{"vendor": "N/A", "product": "N/A", "versions": []}],
        }
