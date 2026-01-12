import csv
from django.core.management.base import BaseCommand
from cves.models import CVE
from datetime import datetime
import os

class Command(BaseCommand):
    help = 'Import CVEs from cves_consolidees.csv'

    def handle(self, *args, **options):
        csv_file = 'cves_consolidees.csv'
        
        if not os.path.exists(csv_file):
            self.stdout.write(self.style.ERROR(f'File {csv_file} not found'))
            return
        
        # Clear existing CVEs
        self.stdout.write('Clearing existing CVEs...')
        CVE.objects.all().delete()
        
        imported_count = 0
        seen_cves = set()
        
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                cve_id = row['Identifiant CVE']
                
                # Skip duplicates - only keep first occurrence
                if cve_id in seen_cves:
                    continue
                
                seen_cves.add(cve_id)
                
                # Parse date
                date_str = row['Date publication']
                try:
                    # Parse format: "Mon, 08 Dec 2025 00:00:00 +0000"
                    date_obj = datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S %z')
                    date_publication = date_obj.date()
                except:
                    self.stdout.write(self.style.WARNING(f'Could not parse date for {cve_id}, skipping'))
                    continue
                
                # Create CVE
                CVE.objects.create(
                    identifiant_cve=cve_id,
                    titre_bulletin=row['Titre bulletin (ANSSI)'],
                    date_publication=date_publication,
                    lien_bulletin=row['Lien bulletin (ANSSI)'],
                    base_severity=row['Base Severity'] if row['Base Severity'] != 'Non disponible' else '',
                    description=row['Description'] if row['Description'] != 'Non disponible' else ''
                )
                
                imported_count += 1
        
        self.stdout.write(self.style.SUCCESS(f'Successfully imported {imported_count} unique CVEs'))
