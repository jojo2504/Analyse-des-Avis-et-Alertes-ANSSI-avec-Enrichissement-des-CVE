from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Button, Static, DataTable, Input, RichLog, TabbedContent, TabPane, Label
from textual.binding import Binding
from textual.screen import Screen
import feedparser
import requests
import re
from datetime import datetime
from typing import List, Dict, Any
from time import strftime

class CVEDetailScreen(Screen):
    """Screen to display detailed CVE information"""
    
    BINDINGS = [
        Binding("escape", "back", "Back"),
    ]
    
    def __init__(self, cve_id: str):
        super().__init__()
        self.cve_id = cve_id
        self.cve_data = None
        self.epss_data = None
    
    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="cve-scroll"):
            yield Static(f"Loading CVE details for {self.cve_id}...", id="cve-details")
        yield Footer()
    
    def on_mount(self) -> None:
        self.fetch_cve_details()
    
    def fetch_cve_details(self) -> None:
        try:
            # Fetch CVE details from MITRE
            url = f"https://cveawg.mitre.org/api/cve/{self.cve_id}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            self.cve_data = response.json()
            
            # Fetch EPSS score
            epss_url = f"https://api.first.org/data/v1/epss?cve={self.cve_id}"
            epss_response = requests.get(epss_url, timeout=10)
            self.epss_data = epss_response.json()
            
            self.display_cve_details()
        except Exception as e:
            self.query_one("#cve-details", Static).update(f"[red]Error fetching CVE details: {str(e)}[/red]")
    
    def display_cve_details(self) -> None:
        if not self.cve_data:
            return
        
        try:
            # Extract description
            description = self.cve_data["containers"]["cna"]["descriptions"][0]["value"]
            
            # Extract CVSS score (try different versions)
            cvss_score = "N/A"
            cvss_severity = "N/A"
            metrics = self.cve_data["containers"]["cna"].get("metrics", [])
            if metrics:
                for metric in metrics:
                    if "cvssV3_1" in metric:
                        cvss_score = metric["cvssV3_1"]["baseScore"]
                        cvss_severity = metric["cvssV3_1"].get("baseSeverity", "N/A")
                        break
                    elif "cvssV3_0" in metric:
                        cvss_score = metric["cvssV3_0"]["baseScore"]
                        cvss_severity = metric["cvssV3_0"].get("baseSeverity", "N/A")
                        break
            
            # Extract CWE
            cwe = "Non disponible"
            cwe_desc = "Non disponible"
            problemtype = self.cve_data["containers"]["cna"].get("problemTypes", [])
            if problemtype and "descriptions" in problemtype[0]:
                cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")
            
            # Extract EPSS score
            epss_score = "N/A"
            epss_percentile = "N/A"
            if self.epss_data and self.epss_data.get("data"):
                epss_score = self.epss_data["data"][0]["epss"]
                epss_percentile = self.epss_data["data"][0].get("percentile", "N/A")
            
            # Extract affected products
            affected_products = []
            affected = self.cve_data["containers"]["cna"].get("affected", [])
            for product in affected:
                vendor = product.get("vendor", "Unknown")
                product_name = product.get("product", "Unknown")
                versions = [v["version"] for v in product.get("versions", []) if v.get("status") == "affected"]
                affected_products.append(f"  • {vendor} - {product_name}: {', '.join(versions) if versions else 'All versions'}")
            
            # Determine severity color
            severity_color = "white"
            if cvss_score != "N/A":
                score = float(cvss_score)
                if score >= 9.0:
                    severity_color = "red bold"
                elif score >= 7.0:
                    severity_color = "yellow bold"
                elif score >= 4.0:
                    severity_color = "cyan"
                else:
                    severity_color = "green"
            
            # Build display text
            details_text = f"""[bold cyan]{self.cve_id}[/bold cyan]

[bold]Description:[/bold]
{description}

[bold]Scores:[/bold]
  • CVSS Score: [{severity_color}]{cvss_score}[/{severity_color}] ({cvss_severity})
  • EPSS Score: {epss_score} (Percentile: {epss_percentile})

[bold]CWE Information:[/bold]
  • Type: {cwe}
  • Description: {cwe_desc}

[bold]Affected Products:[/bold]
{''.join([f'\n{p}' for p in affected_products]) if affected_products else '\n  No products listed'}

[dim]Press ESC to go back[/dim]
"""
            
            self.query_one("#cve-details", Static).update(details_text)
        except Exception as e:
            self.query_one("#cve-details", Static).update(f"[red]Error parsing CVE data: {str(e)}[/red]")
    
    def action_back(self) -> None:
        self.app.pop_screen()

class EntryDetailScreen(Screen):
    """Screen to display entry details with extracted CVEs"""
    
    BINDINGS = [
        Binding("escape", "back", "Back"),
    ]
    
    def __init__(self, entry_title: str, entry_link: str):
        super().__init__()
        self.entry_title = entry_title
        self.entry_link = entry_link
        self.cve_list = []
    
    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical():
            yield Static(f"[bold cyan]{self.entry_title}[/bold cyan]", id="entry-title")
            yield Static(f"[dim]{self.entry_link}[/dim]", id="entry-link")
            yield Static("Loading CVEs...", id="cve-status")
            yield DataTable(id="cve-table")
        yield Footer()
    
    def on_mount(self) -> None:
        table = self.query_one("#cve-table", DataTable)
        table.add_columns("CVE ID", "CVSS", "EPSS", "Description")
        table.cursor_type = "row"
        self.fetch_cves()
    
    def fetch_cves(self) -> None:
        try:
            json_url = self.entry_link.rstrip("/") + "/json/"
            response = requests.get(json_url, timeout=10)
            data = response.json()
            
            # Extract CVEs from the 'cves' field
            ref_cves = data.get("cves", [])
            
            # Also extract CVEs using regex
            cve_pattern = r"CVE-\d{4}-\d{4,7}"
            cve_list = list(set(re.findall(cve_pattern, str(data))))
            
            # Combine both lists
            all_cves = set()
            for cve in ref_cves:
                all_cves.add(cve.get("name", ""))
            all_cves.update(cve_list)
            all_cves.discard("")
            
            self.cve_list = sorted(list(all_cves))
            
            status_text = f"Found {len(self.cve_list)} CVE(s)"
            if len(self.cve_list) > 0:
                status_text += " - Click on a row to see details"
            self.query_one("#cve-status", Static).update(status_text)
            
            # Load CVE summary information
            if self.cve_list:
                self.load_cve_summaries()
            else:
                self.query_one("#cve-status", Static).update("[yellow]No CVEs found in this entry[/yellow]")
            
        except Exception as e:
            self.query_one("#cve-status", Static).update(f"[red]Error fetching CVEs: {str(e)}[/red]")
    
    def load_cve_summaries(self) -> None:
        """Load basic info for each CVE"""
        table = self.query_one("#cve-table", DataTable)
        
        for cve_id in self.cve_list:
            try:
                # Fetch basic CVE info
                url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
                response = requests.get(url, timeout=5)
                data = response.json()
                
                # Get CVSS score
                cvss_score = "N/A"
                metrics = data["containers"]["cna"].get("metrics", [])
                if metrics:
                    for metric in metrics:
                        if "cvssV3_1" in metric:
                            cvss_score = str(metric["cvssV3_1"]["baseScore"])
                            break
                        elif "cvssV3_0" in metric:
                            cvss_score = str(metric["cvssV3_0"]["baseScore"])
                            break
                
                # Get EPSS score
                epss_score = "N/A"
                epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
                epss_response = requests.get(epss_url, timeout=5)
                epss_data = epss_response.json()
                if epss_data.get("data"):
                    epss_score = epss_data["data"][0]["epss"]
                
                # Get description (truncated)
                description = data["containers"]["cna"]["descriptions"][0]["value"]
                desc_short = description[:60] + "..." if len(description) > 60 else description
                
                table.add_row(cve_id, cvss_score, epss_score, desc_short)
                
            except Exception as e:
                table.add_row(cve_id, "Error", "Error", f"Failed to load: {str(e)[:30]}")
    
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle CVE selection"""
        table = self.query_one("#cve-table", DataTable)
        row = table.get_row(event.row_key)
        cve_id = row[0]
        
        if cve_id and not cve_id.startswith("Error"):
            self.app.push_screen(CVEDetailScreen(cve_id))
    
    def action_back(self) -> None:
        self.app.pop_screen()

class ANSSIMonitorApp(App):
    """A Textual app to monitor ANSSI security advisories and alerts."""
    
    CSS = """
    #feed-container {
        height: 100%;
        border: solid green;
    }
    
    #cve-container, #cve-scroll {
        height: 100%;
        border: solid cyan;
        padding: 1 2;
    }
    
    DataTable {
        height: 1fr;
    }
    
    #status-log {
        height: 10;
        border: solid yellow;
        margin-top: 1;
    }
    
    .button-row {
        height: auto;
        margin: 1 0;
    }
    
    Button {
        margin: 0 1;
    }
    
    #entry-title {
        margin: 1;
    }
    
    #entry-link {
        margin: 0 1 1 1;
    }
    
    #cve-status {
        margin: 1;
        background: $boost;
        padding: 1;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("c", "clear_log", "Clear Log"),
    ]
    
    # All available ANSSI RSS feeds
    FEED_URLS = {
        "avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
        "alertes": "https://www.cert.ssi.gouv.fr/alerte/feed/",
        "complet": "https://www.cert.ssi.gouv.fr/feed/",
        "actualite": "https://www.cert.ssi.gouv.fr/actualite/feed/",
        "scada": "https://www.cert.ssi.gouv.fr/feed/scada/",
        "cti": "https://www.cert.ssi.gouv.fr/cti/feed/",
        "ioc": "https://www.cert.ssi.gouv.fr/ioc/feed/",
        "dur": "https://www.cert.ssi.gouv.fr/dur/feed/"
    }
    
    def __init__(self):
        super().__init__()
        self.current_feed_type = "complet"
        self.feed_data = []
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with TabbedContent():
            with TabPane("Feed Viewer"):
                with Vertical(id="feed-container"):
                    with Horizontal(classes="button-row"):
                        yield Button("Avis", id="btn-avis", variant="primary")
                        yield Button("Alertes", id="btn-alertes", variant="primary")
                        yield Button("Complet", id="btn-complet", variant="success")
                        yield Button("Actualité", id="btn-actualite", variant="primary")
                    with Horizontal(classes="button-row"):
                        yield Button("SCADA", id="btn-scada", variant="warning")
                        yield Button("CTI", id="btn-cti", variant="warning")
                        yield Button("IOC", id="btn-ioc", variant="warning")
                        yield Button("DUR", id="btn-dur", variant="warning")
                        yield Button("Refresh", id="btn-refresh", variant="default")
                    
                    yield DataTable(id="feed-table")
                    yield RichLog(id="status-log", highlight=True)
            
            with TabPane("CVE Search"):
                with Vertical():
                    with Horizontal(classes="button-row"):
                        yield Label("CVE ID:")
                        yield Input(placeholder="CVE-YYYY-NNNN", id="cve-input")
                        yield Button("Search", id="btn-search-cve", variant="primary")
                    yield ScrollableContainer(
                        Static("Enter a CVE ID to search (e.g., CVE-2023-46805)", id="cve-search-results"),
                    )
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Initialize the data table and load initial feed."""
        table = self.query_one("#feed-table", DataTable)
        table.add_columns("Date", "Type", "Title")
        table.cursor_type = "row"
        
        self.log_message("[cyan]Welcome to ANSSI Monitor![/cyan]")
        self.log_message(f"[dim]Available feeds: {', '.join(self.FEED_URLS.keys())}[/dim]")
        self.load_feed("complet")
    
    def log_message(self, message: str) -> None:
        """Log a message to the status log."""
        status_log = self.query_one("#status-log", RichLog)
        timestamp = datetime.now().strftime("%H:%M:%S")
        status_log.write(f"[{timestamp}] {message}")
    
    def action_clear_log(self) -> None:
        """Clear the status log."""
        status_log = self.query_one("#status-log", RichLog)
        status_log.clear()
        self.log_message("[dim]Log cleared[/dim]")
    
    def action_refresh(self) -> None:
        """Refresh the current feed."""
        self.load_feed(self.current_feed_type)
    
    def load_feed(self, feed_type: str) -> None:
        """Load RSS feed based on type - Using notebook logic"""
        self.current_feed_type = feed_type
        
        url = self.FEED_URLS.get(feed_type)
        if not url:
            self.log_message(f"[red]Unknown feed type: {feed_type}[/red]")
            return
        
        self.log_message(f"Loading feed: [cyan]{feed_type}[/cyan] from {url}")
        
        try:
            # Add headers to mimic a browser request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # Fetch the URL directly
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Parse the feed
            feed = feedparser.parse(response.content)
            
            # Check for parsing errors
            if feed.bozo and feed.bozo_exception:
                self.log_message(f"[yellow]Feed parsing warning: {feed.bozo_exception}[/yellow]")
            
            # Check if we got any entries
            if not feed.entries:
                self.log_message(f"[yellow]No entries found in feed[/yellow]")
                
                # Try to display feed metadata
                if hasattr(feed, 'feed'):
                    self.log_message(f"[dim]Feed title: {feed.feed.get('title', 'N/A')}[/dim]")
                    self.log_message(f"[dim]Feed updated: {feed.feed.get('updated', 'N/A')}[/dim]")
                
                # Clear the table
                table = self.query_one("#feed-table", DataTable)
                table.clear()
                return
            
            self.feed_data = feed.entries
            
            table = self.query_one("#feed-table", DataTable)
            table.clear()
            
            entries_added = 0
            for entry in feed.entries:
                # Extract date with multiple fallback options
                date = "N/A"
                if hasattr(entry, 'published'):
                    date = entry.published[:10] if len(entry.published) >= 10 else entry.published
                elif hasattr(entry, 'updated'):
                    date = entry.updated[:10] if len(entry.updated) >= 10 else entry.updated
                elif hasattr(entry, 'published_parsed') and entry.published_parsed:
                    date = strftime("%Y-%m-%d", entry.published_parsed)
                
                # Determine entry type from link
                entry_type = "OTHER"
                link = ""
                
                if hasattr(entry, 'link'):
                    link = entry.link
                    link_lower = link.lower()
                    if "avis" in link_lower:
                        entry_type = "AVIS"
                    elif "alerte" in link_lower:
                        entry_type = "ALERTE"
                    elif "actualite" in link_lower:
                        entry_type = "ACTU"
                    elif "scada" in link_lower:
                        entry_type = "SCADA"
                    elif "cti" in link_lower:
                        entry_type = "CTI"
                    elif "ioc" in link_lower:
                        entry_type = "IOC"
                    elif "dur" in link_lower:
                        entry_type = "DUR"
                
                # Extract title
                title = "No title"
                if hasattr(entry, 'title'):
                    title = entry.title
                elif hasattr(entry, 'summary'):
                    # Use summary as title if title is missing
                    title = entry.summary[:100] + "..." if len(entry.summary) > 100 else entry.summary
                
                # Only add row if we have at least a title or link
                if title != "No title" or link:
                    table.add_row(date, entry_type, title, key=link if link else f"row_{entries_added}")
                    entries_added += 1
            
            if entries_added > 0:
                self.log_message(f"[green]✓ Successfully loaded {entries_added} entries[/green]")
            else:
                self.log_message(f"[yellow]Parsed feed but found no valid entries[/yellow]")
            
        except requests.exceptions.Timeout:
            self.log_message(f"[red]✗ Timeout error: The server took too long to respond[/red]")
        except requests.exceptions.ConnectionError:
            self.log_message(f"[red]✗ Connection error: Could not connect to the server[/red]")
        except requests.exceptions.HTTPError as e:
            self.log_message(f"[red]✗ HTTP error: {e}[/red]")
        except Exception as e:
            self.log_message(f"[red]✗ Error loading feed: {str(e)}[/red]")
            self.log_message(f"[dim]Feed type: {feed_type}, URL: {url}[/dim]")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button clicks."""
        button_id = event.button.id
        
        if button_id == "btn-avis":
            self.load_feed("avis")
        elif button_id == "btn-alertes":
            self.load_feed("alertes")
        elif button_id == "btn-complet":
            self.load_feed("complet")
        elif button_id == "btn-actualite":
            self.load_feed("actualite")
        elif button_id == "btn-scada":
            self.load_feed("scada")
        elif button_id == "btn-cti":
            self.load_feed("cti")
        elif button_id == "btn-ioc":
            self.load_feed("ioc")
        elif button_id == "btn-dur":
            self.load_feed("dur")
        elif button_id == "btn-refresh":
            self.action_refresh()
        elif button_id == "btn-search-cve":
            self.search_cve()
    
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection in the data table."""
        table = self.query_one("#feed-table", DataTable)
        row_key = event.row_key
        row = table.get_row(row_key)
        
        title = row[2]
        link = str(row_key)
        
        if not link or link == "None" or link.startswith("row_"):
            self.log_message("[yellow]No link available for this entry[/yellow]")
            return
        
        self.log_message(f"[cyan]Selected:[/cyan] {title[:50]}...")
        self.log_message(f"[dim]Opening entry details...[/dim]")
        
        # Open the entry detail screen
        self.push_screen(EntryDetailScreen(title, link))
    
    def search_cve(self) -> None:
        """Search for a specific CVE."""
        input_widget = self.query_one("#cve-input", Input)
        cve_id = input_widget.value.strip().upper()
        
        if not cve_id:
            self.log_message("[yellow]Please enter a CVE ID[/yellow]")
            return
        
        # Validate CVE format
        if not re.match(r"CVE-\d{4}-\d{4,7}", cve_id):
            self.log_message(f"[red]Invalid CVE format: {cve_id}[/red]")
            self.log_message("[dim]Expected format: CVE-YYYY-NNNN (e.g., CVE-2023-46805)[/dim]")
            return
        
        self.log_message(f"[cyan]Searching for {cve_id}...[/cyan]")
        self.push_screen(CVEDetailScreen(cve_id))
    
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in CVE input."""
        if event.input.id == "cve-input":
            self.search_cve()

if __name__ == "__main__":
    app = ANSSIMonitorApp()
    app.run()