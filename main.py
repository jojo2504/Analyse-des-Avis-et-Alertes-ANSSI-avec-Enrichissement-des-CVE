from dataframe import build_dataframe
from enrich import Enrichment

if __name__ == "__main__":
    enrichment = Enrichment()
    rss = "https://www.cert.ssi.gouv.fr/avis/feed/"
    df = build_dataframe(rss, "Avis", enrichment)
    df.to_csv("cves_consolidees.csv", index=False)
    print("CSV généré : cves_consolidees.csv")