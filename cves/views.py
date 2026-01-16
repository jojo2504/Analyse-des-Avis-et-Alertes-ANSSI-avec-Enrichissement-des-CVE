from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from .models import CVE, EmailGroup
from .serializers import CVESerializer, EmailGroupSerializer
from django.core.mail import EmailMultiAlternatives
from django.conf import settings


class CVEListView(generics.ListAPIView):
    queryset = CVE.objects.all()
    serializer_class = CVESerializer
    permission_classes = [AllowAny]


class CVEDetailView(generics.RetrieveAPIView):
    queryset = CVE.objects.all()
    serializer_class = CVESerializer
    permission_classes = [AllowAny]


class EmailGroupListCreateView(generics.ListCreateAPIView):
    queryset = EmailGroup.objects.all()          # no user filter anymore
    serializer_class = EmailGroupSerializer


class EmailGroupDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = EmailGroup.objects.all()
    serializer_class = EmailGroupSerializer


class SendCVEEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        cve_ids = request.data.get('cve_ids', [])
        emails = request.data.get('emails', [])           # list of strings
        group_ids = request.data.get('group_ids', [])     # list of group pk

        if not cve_ids:
            return Response({'error': 'No CVEs selected'}, status=400)

        # Collect all recipient emails
        all_emails = set(emails)

        for group_id in group_ids:
            try:
                group = EmailGroup.objects.get(id=group_id)
                group_emails = [e.strip() for e in group.emails.split(',') if e.strip()]
                all_emails.update(group_emails)
            except EmailGroup.DoesNotExist:
                continue

        if not all_emails:
            return Response({'error': 'No valid email addresses provided'}, status=400)

        # Get CVEs
        cves = CVE.objects.filter(id__in=cve_ids)
        if not cves.exists():
            return Response({'error': 'No valid CVEs found'}, status=400)

        # Build email content
        subject = "Selected CVE Report"
        
        # Plain text version
        text_content = "Here are the CVEs you requested:\n\n"
        for cve in cves:
            text_content += f"• {cve.identifiant_cve} — {cve.base_severity or 'N/A'}\n"
            text_content += f"  Title: {cve.titre_bulletin}\n"
            text_content += f"  Published: {cve.date_publication.strftime('%Y-%m-%d')}\n"
            text_content += f"  Link: {cve.lien_bulletin}\n"
            text_content += f"  Description: {cve.description[:300]}{'...' if len(cve.description) > 300 else ''}\n\n"

        # HTML version
        severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#28a745',
        }
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }
                h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
                .cve-item { background: #f8f9fa; border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; border-radius: 4px; }
                .cve-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
                .cve-id { font-weight: bold; font-size: 18px; color: #2c3e50; }
                .severity { padding: 4px 12px; border-radius: 4px; color: white; font-weight: bold; font-size: 12px; }
                .cve-title { font-weight: bold; color: #34495e; margin: 8px 0; }
                .cve-meta { color: #7f8c8d; font-size: 14px; margin: 5px 0; }
                .cve-desc { margin-top: 10px; color: #555; }
                a { color: #3498db; text-decoration: none; }
                a:hover { text-decoration: underline; }
                .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #7f8c8d; font-size: 12px; }
            </style>
        </head>
        <body>
            <h1>CVE Security Report</h1>
            <p>Here are the CVE alerts you requested:</p>
        """
        
        for cve in cves:
            severity = (cve.base_severity or 'N/A').upper()
            severity_color = severity_colors.get(severity, '#6c757d')
            
            html_content += f"""
            <div class="cve-item">
                <div class="cve-header">
                    <span class="cve-id">{cve.identifiant_cve}</span>
                    <span class="severity" style="background-color: {severity_color};">{severity}</span>
                </div>
                <div class="cve-title">{cve.titre_bulletin}</div>
                <div class="cve-meta">Published: {cve.date_publication.strftime('%B %d, %Y')}</div>
                <div class="cve-meta"><a href="{cve.lien_bulletin}" target="_blank">View Full Bulletin</a></div>
                <div class="cve-desc">{cve.description[:300]}{'...' if len(cve.description) > 300 else ''}</div>
            </div>
            """
        
        html_content += """
            <div class="footer">
                <p>This is an automated security alert from your CVE monitoring system.</p>
                <p>Stay secure!</p>
            </div>
        </body>
        </html>
        """

        # Send email with logging
        print(f"[EMAIL] Attempting to send to {len(all_emails)} recipients: {all_emails}")
        print(f"[EMAIL] Using SMTP: {settings.EMAIL_HOST}:{settings.EMAIL_PORT}")
        
        try:
            msg = EmailMultiAlternatives(
                subject,
                text_content,
                settings.DEFAULT_FROM_EMAIL,
                list(all_emails)
            )
            msg.attach_alternative(html_content, "text/html")
            msg.send(fail_silently=False)
            print(f"[EMAIL] ✅ Successfully sent email to {len(all_emails)} recipients")
        except Exception as e:
            print(f"[EMAIL] ❌ Failed to send email: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response({
                "success": False,
                "error": f"Failed to send email: {str(e)}"
            }, status=500)

        return Response({
            "success": True,
            "message": f"Email sent to {len(all_emails)} recipient(s)",
            "recipients_count": len(all_emails)
        })