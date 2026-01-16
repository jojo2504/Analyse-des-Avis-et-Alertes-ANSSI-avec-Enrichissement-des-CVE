import pandas as pd
from collect import Collector
from extract import Extractor
from enrich import Enrichment
from utils import to_json_url

def build_dataframe(rss_url, bulletin_type, enrichment: Enrichment, limit=5):
    rows = []
    entries = Collector.get_rss_entries(rss_url)
    print(f"\nNombre total d'entrées RSS récupérées: {len(entries)}")
    print(f"Limite appliquée: {limit} entrées\n")

    for idx, entry in enumerate(entries[:limit], 1):
        print(f"\n{'='*80}")
        print(f"Traitement du bulletin {idx}/{limit}: {entry.title}")
        print(f"{'='*80}")
        
        # Extraire les CVE pour cette entrée spécifique
        json_url = to_json_url(entry.link)
        print(f"URL JSON: {json_url}")
        
        try:
            print(f"Récupération des données JSON...")
            data = Collector.fetch_json(json_url)
            print(f"Données récupérées")
            
            print(f"Extraction des CVE...")
            cves = Extractor.extract_cves_from_bulletin(data)
            print(f"{len(cves)} CVE trouvées: {cves}")
        except Exception as e:
            print(f"Erreur lors de l'extraction pour {entry.title}: {e}")
            continue

        for cve_idx, cve in enumerate(cves, 1):
            print(f"\n  Enrichissement CVE {cve_idx}/{len(cves)}: {cve}")
            info = enrichment.enrich_cve(cve)
            print(f"  CVE {cve} enrichie (CVSS: {info['cvss']}, EPSS: {info['epss']})")

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

    print(f"\n{'='*80}")
    print(f"✅ Traitement terminé! {len(rows)} lignes générées")
    print(f"{'='*80}\n")
    return pd.DataFrame(rows)