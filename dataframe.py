import pandas as pd
from collect import Collector
from extract import Extractor
from enrich import Enrichment

def build_dataframe(rss_url, bulletin_type, enrichment: Enrichment, limit=5):
    rows = []
    entries = Collector.get_rss_entries(rss_url)

    for entry in entries[:limit]:
        cves = Extractor.extract_cves_from_rss(rss_url)

        for cve in cves:
            info = enrichment.enrich_cve(cve)

            products = info["products"] or [{"vendor": "N/A", "product": "N/A", "versions": []}]

            for p in products:
                rows.append({
                    "Titre bulletin (ANSSI)": entry.title,
                    "Type bulletin": bulletin_type,
                    "Date publication": getattr(entry, "published", None),
                    "Identifiant CVE": cve,
                    "Score CVSS": info["cvss"],
                    "Base Severity": info["severity"],
                    "Type CWE": info["cwe"],
                    "Score EPSS": info["epss"],
                    "Lien bulletin (ANSSI)": entry.link,
                    "Description": info["description"],
                    "Éditeur/Vendor": p["vendor"],
                    "Produit": p["product"],
                    "Versions affectées": ", ".join(p["versions"])
                })

    return pd.DataFrame(rows)

if __name__ == "__main__":
    enrichment = Enrichment()
    rss = "https://www.cert.ssi.gouv.fr/avis/feed/"
    df = build_dataframe(rss, "Avis", enrichment)
    df.to_csv("cves_consolidees.csv", index=False)
    print("CSV généré : cves_consolidees.csv")