#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI Interactif pour l'analyse des CVE provenant de l'ANSSI, MITRE et FIRST
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from collections import defaultdict


class CVEExplorer:
    """Classe pour charger et explorer les données CVE"""
    
    def __init__(self, data_path: str = "./data"):
        self.data_path = Path(data_path)
        self.cve_data = defaultdict(lambda: {
            "mitre": None,
            "first": None,
            "avis": [],
            "alertes": []
        })
        self.load_all_data()
    
    def load_json_files(self, directory: Path) -> List[tuple]:
        """Charge tous les fichiers JSON d'un répertoire et retourne (filename, content)"""
        data = []
        
        # Vérifier l'existence du répertoire
        if not directory.exists():
            print(f"⚠️  Répertoire non trouvé: {directory.absolute()}")
            return data
        
        # Lister tous les fichiers (pas seulement .json car ils n'ont pas d'extension)
        all_files = [f for f in directory.iterdir() if f.is_file()]
        print(f"   📁 Chemin: {directory.absolute()}")
        print(f"   📄 Fichiers trouvés: {len(all_files)}")
        
        for file in all_files:
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    content = json.load(f)
                    # Le nom du fichier EST le CVE-ID ou CERTFR-ID (sans extension)
                    filename = file.name  # ex: "CVE-2001-1267" ou "CERTFR-2021-ALE-001"
                    data.append((filename, content))
            except json.JSONDecodeError as e:
                # Fichier non-JSON, on ignore
                pass
            except Exception as e:
                print(f"❌ Erreur lors du chargement de {file.name}: {e}")
        
        return data
    
    def load_all_data(self):
        """Charge toutes les données des 4 sources"""
        print("🔄 Chargement des données...")
        
        # Charger les alertes (fichiers nommés CERTFR-YYYY-ALE-XXX.json)
        alertes_dir = self.data_path / "alertes"
        alertes = self.load_json_files(alertes_dir)
        print(f"  ✓ {len(alertes)} alertes chargées")
        
        for filename, alerte in alertes:
            if "cves" in alerte:
                for cve in alerte["cves"]:
                    cve_id = cve["name"]
                    self.cve_data[cve_id]["alertes"].append(alerte)
        
        # Charger les avis (fichiers nommés CERTFR-YYYY-AVI-XXXX.json)
        avis_dir = self.data_path / "avis"
        avis = self.load_json_files(avis_dir)
        print(f"  ✓ {len(avis)} avis chargés")
        
        for filename, avi in avis:
            if "cves" in avi:
                for cve in avi["cves"]:
                    cve_id = cve["name"]
                    self.cve_data[cve_id]["avis"].append(avi)
        
        # Charger les données MITRE (fichiers nommés CVE-YYYY-NNNNN.json)
        mitre_dir = self.data_path / "mitre"
        mitres = self.load_json_files(mitre_dir)
        print(f"  ✓ {len(mitres)} entrées MITRE chargées")
        
        for filename, mitre in mitres:
            # Le nom du fichier est directement le CVE-ID
            cve_id = filename
            self.cve_data[cve_id]["mitre"] = mitre
        
        # Charger les données FIRST/EPSS (fichiers nommés CVE-YYYY-NNNNN.json)
        first_dir = self.data_path / "first"
        firsts = self.load_json_files(first_dir)
        print(f"  ✓ {len(firsts)} fichiers FIRST chargés")
        
        for filename, first in firsts:
            # Le nom du fichier est le CVE-ID
            cve_id = filename
            # Les données EPSS sont dans le champ "data"
            if "data" in first and len(first["data"]) > 0:
                self.cve_data[cve_id]["first"] = first["data"][0]
            else:
                # Si pas de structure "data", on prend le contenu directement
                self.cve_data[cve_id]["first"] = first
        
        print(f"\n✅ Total: {len(self.cve_data)} CVE uniques trouvées\n")
    
    def get_all_cves(self) -> List[str]:
        """Retourne la liste de toutes les CVE disponibles"""
        return sorted(self.cve_data.keys())
    
    def extract_cvss_info(self, mitre_data: dict) -> dict:
        """Extrait les informations CVSS depuis les données MITRE"""
        cvss_info = {
            "score": None,
            "severity": None,
            "vector": None
        }
        
        try:
            if "containers" in mitre_data and "cna" in mitre_data["containers"]:
                metrics = mitre_data["containers"]["cna"].get("metrics", [])
                
                for metric in metrics:
                    if "cvssV3_1" in metric:
                        cvss = metric["cvssV3_1"]
                        cvss_info["score"] = cvss.get("baseScore")
                        cvss_info["severity"] = cvss.get("baseSeverity")
                        cvss_info["vector"] = cvss.get("vectorString")
                        break
                    elif "cvssV3_0" in metric:
                        cvss = metric["cvssV3_0"]
                        cvss_info["score"] = cvss.get("baseScore")
                        cvss_info["severity"] = cvss.get("baseSeverity")
                        cvss_info["vector"] = cvss.get("vectorString")
                        break
                    elif "cvssV2_0" in metric:
                        cvss = metric["cvssV2_0"]
                        cvss_info["score"] = cvss.get("baseScore")
                        cvss_info["vector"] = cvss.get("vectorString")
                        break
        except Exception as e:
            pass  # Silencieux pour ne pas polluer l'affichage
        
        return cvss_info
    
    def extract_cwe_info(self, mitre_data: dict) -> List[str]:
        """Extrait les CWE depuis les données MITRE"""
        cwes = []
        
        try:
            if "containers" in mitre_data and "cna" in mitre_data["containers"]:
                problem_types = mitre_data["containers"]["cna"].get("problemTypes", [])
                
                for pt in problem_types:
                    for desc in pt.get("descriptions", []):
                        cwe_id = desc.get("cweId")
                        if cwe_id:
                            cwes.append(cwe_id)
        except Exception as e:
            pass
        
        return cwes
    
    def display_cve_details(self, cve_id: str):
        """Affiche tous les détails d'une CVE"""
        if cve_id not in self.cve_data:
            print(f"❌ CVE {cve_id} non trouvée dans la base de données")
            return
        
        data = self.cve_data[cve_id]
        
        print("\n" + "="*80)
        print(f"📋 DÉTAILS COMPLETS POUR: {cve_id}")
        print("="*80)
        
        # ===== MITRE =====
        print("\n🔍 DONNÉES MITRE (CVE)")
        print("-" * 80)
        
        if data["mitre"]:
            mitre = data["mitre"]
            
            # Description
            if "containers" in mitre and "cna" in mitre["containers"]:
                descriptions = mitre["containers"]["cna"].get("descriptions", [])
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        print(f"Description: {desc.get('value', 'N/A')}")
                        break
            
            # Date de publication
            if "cveMetadata" in mitre:
                published = mitre["cveMetadata"].get("datePublished", "N/A")
                print(f"Date de publication: {published}")
            
            # CVSS
            cvss_info = self.extract_cvss_info(mitre)
            if cvss_info["score"]:
                print(f"\nScore CVSS: {cvss_info['score']}")
                if cvss_info["severity"]:
                    print(f"Sévérité: {cvss_info['severity']}")
                if cvss_info["vector"]:
                    print(f"Vecteur: {cvss_info['vector']}")
            else:
                print("\nScore CVSS: Non disponible")
            
            # CWE
            cwes = self.extract_cwe_info(mitre)
            if cwes:
                print(f"CWE: {', '.join(cwes)}")
            else:
                print("CWE: Non disponible")
            
            # Produits affectés
            if "containers" in mitre and "cna" in mitre["containers"]:
                affected = mitre["containers"]["cna"].get("affected", [])
                if affected:
                    print("\nProduits affectés:")
                    for aff in affected[:5]:  # Limiter à 5
                        vendor = aff.get("vendor", "N/A")
                        product = aff.get("product", "N/A")
                        versions = aff.get("versions", [])
                        version_str = ", ".join([v.get("version", "") for v in versions[:3]])
                        if version_str:
                            print(f"  • {vendor} {product} ({version_str})")
                        else:
                            print(f"  • {vendor} {product}")
        else:
            print("❌ Pas de données MITRE disponibles")
        
        # ===== FIRST (EPSS) =====
        print("\n📊 DONNÉES FIRST (EPSS)")
        print("-" * 80)
        
        if data["first"]:
            first = data["first"]
            epss = first.get("epss", 0)
            percentile = first.get("percentile", 0)
            date = first.get("date", "N/A")
            
            # Convertir en float si c'est une string
            if isinstance(epss, str):
                epss = float(epss)
            if isinstance(percentile, str):
                percentile = float(percentile)
            
            print(f"Score EPSS: {epss:.6f} ({epss*100:.4f}%)")
            print(f"Percentile: {percentile:.6f} ({percentile*100:.4f}%)")
            print(f"Date: {date}")
            print(f"\n💡 Interprétation: Cette CVE a {epss*100:.4f}% de probabilité")
            print(f"   d'être exploitée dans les 30 prochains jours.")
            
            # Évaluation du risque
            if epss > 0.5:
                print("   ⚠️  RISQUE TRÈS ÉLEVÉ d'exploitation")
            elif epss > 0.1:
                print("   ⚠️  Risque élevé d'exploitation")
            elif epss > 0.01:
                print("   ⚠️  Risque modéré d'exploitation")
            else:
                print("   ✓ Risque faible d'exploitation")
        else:
            print("❌ Pas de données EPSS disponibles")
        
        # ===== ALERTES ANSSI =====
        print("\n🚨 ALERTES CERT-FR (ANSSI)")
        print("-" * 80)
        
        if data["alertes"]:
            for alerte in data["alertes"]:
                print(f"\n🔴 {alerte.get('reference', 'N/A')}")
                print(f"Titre: {alerte.get('title', 'N/A')}")
                
                risks = alerte.get("risks", [])
                if risks:
                    print(f"Risques: {', '.join([r['description'] for r in risks])}")
                
                closed = alerte.get("closed_at")
                if closed:
                    print(f"Clôturée le: {closed}")
                else:
                    print("⚠️  Alerte ACTIVE")
                
                # Systèmes affectés
                affected = alerte.get("affected_systems", [])
                if affected:
                    print("\nSystèmes affectés:")
                    for sys in affected[:3]:
                        vendor = sys.get("product", {}).get("vendor", {}).get("name", "N/A")
                        product = sys.get("product", {}).get("name", "N/A")
                        desc = sys.get("description", "")
                        print(f"  • {vendor} {product}: {desc}")
                
                # Nombre de révisions
                revisions = alerte.get("revisions", [])
                if revisions:
                    print(f"\nNombre de révisions: {len(revisions)}")
                
                print(f"\n🔗 URL: https://www.cert.ssi.gouv.fr/alerte/{alerte.get('reference', '')}/")
        else:
            print("✓ Aucune alerte CERT-FR pour cette CVE")
        
        # ===== AVIS ANSSI =====
        print("\n📢 AVIS CERT-FR (ANSSI)")
        print("-" * 80)
        
        if data["avis"]:
            for avis in data["avis"]:
                print(f"\n🔵 {avis.get('reference', 'N/A')}")
                print(f"Titre: {avis.get('title', 'N/A')}")
                
                risks = avis.get("risks", [])
                if risks:
                    print(f"Risques: {', '.join([r['description'] for r in risks])}")
                
                # Systèmes affectés
                affected = avis.get("affected_systems", [])
                if affected:
                    print("\nSystèmes affectés:")
                    for sys in affected[:3]:
                        vendor = sys.get("product", {}).get("vendor", {}).get("name", "N/A")
                        product = sys.get("product", {}).get("name", "N/A")
                        desc = sys.get("description", "")
                        print(f"  • {vendor} {product}: {desc}")
                
                # Nombre de révisions
                revisions = avis.get("revisions", [])
                if revisions:
                    print(f"\nNombre de révisions: {len(revisions)}")
                
                print(f"\n🔗 URL: https://www.cert.ssi.gouv.fr/avis/{avis.get('reference', '')}/")
        else:
            print("✓ Aucun avis CERT-FR pour cette CVE")
        
        print("\n" + "="*80 + "\n")


def main():
    """Point d'entrée du programme CLI"""
    
    print("""
╔═══════════════════════════════════════════════════════════════════════╗
║                  🛡️  EXPLORATEUR CVE ANSSI/MITRE/FIRST              ║
║                     Analyse de Vulnérabilités                         ║
╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Initialiser l'explorateur
    explorer = CVEExplorer()
    
    if not explorer.cve_data:
        print("❌ Aucune donnée chargée. Vérifiez le chemin du répertoire.")
        print("💡 Le programme recherche les données dans: ./data/")
        print("   avec les sous-dossiers: alertes/, avis/, mitre/, first/")
        return
    
    while True:
        print("\n" + "─" * 80)
        print("🔍 MENU PRINCIPAL")
        print("─" * 80)
        print("1. 📋 Lister toutes les CVE disponibles")
        print("2. 🔎 Rechercher une CVE spécifique")
        print("3. 🎲 Afficher une CVE aléatoire")
        print("4. 📊 Statistiques générales")
        print("5. 🚪 Quitter")
        print()
        
        choix = input("Votre choix (1-5): ").strip()
        
        if choix == "1":
            # Lister toutes les CVE
            cves = explorer.get_all_cves()
            print(f"\n📋 {len(cves)} CVE disponibles:\n")
            
            # Afficher par groupes de 4
            for i, cve in enumerate(cves, 1):
                print(f"  {cve}", end="")
                if i % 4 == 0:
                    print()
                else:
                    print("  ", end="")
            
            if len(cves) % 4 != 0:
                print()
            
            input("\n⏎ Appuyez sur Entrée pour continuer...")
        
        elif choix == "2":
            # Rechercher une CVE
            cve_id = input("\n🔎 Entrez l'identifiant CVE (ex: CVE-2021-20016): ").strip().upper()
            
            if not cve_id.startswith("CVE-"):
                print("❌ Format invalide. Utilisez le format CVE-YYYY-NNNNN")
                continue
            
            explorer.display_cve_details(cve_id)
            input("\n⏎ Appuyez sur Entrée pour continuer...")
        
        elif choix == "3":
            # CVE aléatoire
            import random
            cves = explorer.get_all_cves()
            if cves:
                random_cve = random.choice(cves)
                print(f"\n🎲 CVE aléatoire sélectionnée: {random_cve}")
                explorer.display_cve_details(random_cve)
                input("\n⏎ Appuyez sur Entrée pour continuer...")
            else:
                print("❌ Aucune CVE disponible")
        
        elif choix == "4":
            # Statistiques
            print("\n📊 STATISTIQUES GÉNÉRALES")
            print("=" * 80)
            
            total_cves = len(explorer.cve_data)
            cves_with_mitre = sum(1 for d in explorer.cve_data.values() if d["mitre"])
            cves_with_first = sum(1 for d in explorer.cve_data.values() if d["first"])
            cves_with_alertes = sum(1 for d in explorer.cve_data.values() if d["alertes"])
            cves_with_avis = sum(1 for d in explorer.cve_data.values() if d["avis"])
            
            print(f"\nTotal CVE: {total_cves}")
            print(f"  • Avec données MITRE: {cves_with_mitre} ({cves_with_mitre/total_cves*100:.1f}%)")
            print(f"  • Avec données FIRST (EPSS): {cves_with_first} ({cves_with_first/total_cves*100:.1f}%)")
            print(f"  • Mentionnées dans alertes: {cves_with_alertes} ({cves_with_alertes/total_cves*100:.1f}%)")
            print(f"  • Mentionnées dans avis: {cves_with_avis} ({cves_with_avis/total_cves*100:.1f}%)")
            
            # CVE complètes (présentes dans les 4 sources)
            cves_complete = sum(1 for d in explorer.cve_data.values() 
                               if d["mitre"] and d["first"] and (d["alertes"] or d["avis"]))
            print(f"\n🎯 CVE avec enrichissement complet: {cves_complete}")
            
            input("\n⏎ Appuyez sur Entrée pour continuer...")
        
        elif choix == "5":
            print("\n👋 Au revoir!\n")
            break
        
        else:
            print("❌ Choix invalide. Veuillez choisir entre 1 et 5.")


if __name__ == "__main__":
    main()