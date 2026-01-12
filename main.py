from dataframe import build_dataframe
from enrich import Enrichment

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🚀 DÉMARRAGE - Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE")
    print("="*80 + "\n")
    
    enrichment = Enrichment()
    rss = "https://www.cert.ssi.gouv.fr/avis/feed/"
    
    print(f"⚙️  Configuration: Limite de 5 bulletins\n")
    
    df = build_dataframe(rss, "Avis", enrichment, limit=5)
    
    print(f"💾 Génération du fichier CSV...")
    df.to_csv("cves_consolidees.csv", index=False)
    print(f"✅ CSV généré : cves_consolidees.csv ({len(df)} lignes)")
    
    print("\n" + "="*80)
    print("✅ TERMINÉ")
    print("="*80 + "\n")