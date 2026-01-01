"""
Management command to parse gowitness JSONL files and update database.
Useful when screenshots are taken manually outside of the normal scan flow.

Usage:
    python manage.py parse_screenshots --scan-id 23
    python manage.py parse_screenshots --domain example.com
    python manage.py parse_screenshots --all
"""
import os
import json
import glob
from urllib.parse import urlparse

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings

from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain


class Command(BaseCommand):
    help = 'Parse gowitness JSONL files and update subdomain screenshot paths'

    def add_arguments(self, parser):
        parser.add_argument(
            '--scan-id',
            type=int,
            help='Scan history ID to parse screenshots for'
        )
        parser.add_argument(
            '--domain',
            type=str,
            help='Domain name to parse screenshots for (uses latest scan)'
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Parse all existing JSONL files in scan_results'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be updated without making changes'
        )

    def handle(self, *args, **options):
        scan_id = options.get('scan_id')
        domain_name = options.get('domain')
        parse_all = options.get('all')
        dry_run = options.get('dry_run')

        if not any([scan_id, domain_name, parse_all]):
            raise CommandError('Please provide --scan-id, --domain, or --all')

        results_dir = '/usr/src/scan_results'
        total_updated = 0

        if scan_id:
            # Parse specific scan
            try:
                scan = ScanHistory.objects.get(id=scan_id)
                updated = self.parse_scan_screenshots(scan, results_dir, dry_run)
                total_updated += updated
            except ScanHistory.DoesNotExist:
                raise CommandError(f'Scan with ID {scan_id} not found')

        elif domain_name:
            # Find latest scan for domain
            try:
                domain = Domain.objects.get(name=domain_name)
                scan = ScanHistory.objects.filter(domain=domain).order_by('-start_scan_date').first()
                if not scan:
                    raise CommandError(f'No scans found for domain {domain_name}')
                updated = self.parse_scan_screenshots(scan, results_dir, dry_run)
                total_updated += updated
            except Domain.DoesNotExist:
                raise CommandError(f'Domain {domain_name} not found')

        elif parse_all:
            # Find all JSONL files and parse them
            jsonl_files = glob.glob(f'{results_dir}/**/screenshots/gowitness.jsonl', recursive=True)
            self.stdout.write(f'Found {len(jsonl_files)} JSONL files')
            
            for jsonl_path in jsonl_files:
                # Extract scan info from path
                # Path format: /usr/src/scan_results/domain_scanid/screenshots/gowitness.jsonl
                try:
                    parts = jsonl_path.replace(results_dir, '').strip('/').split('/')
                    scan_dir = parts[0]  # domain_scanid
                    if '_' in scan_dir:
                        scan_id_str = scan_dir.split('_')[-1]
                        scan_id = int(scan_id_str)
                        scan = ScanHistory.objects.get(id=scan_id)
                        updated = self.parse_jsonl_file(jsonl_path, scan, dry_run)
                        total_updated += updated
                except (ValueError, ScanHistory.DoesNotExist) as e:
                    self.stdout.write(self.style.WARNING(f'Skipping {jsonl_path}: {e}'))
                    continue

        action = 'Would update' if dry_run else 'Updated'
        self.stdout.write(self.style.SUCCESS(f'{action} {total_updated} subdomain screenshot paths'))

    def parse_scan_screenshots(self, scan, results_dir, dry_run=False):
        """Parse screenshots for a specific scan."""
        domain_name = scan.domain.name
        scan_dir = f'{results_dir}/{domain_name}_{scan.id}'
        jsonl_path = f'{scan_dir}/screenshots/gowitness.jsonl'

        if not os.path.isfile(jsonl_path):
            # Try to find screenshots directly and match by filename
            screenshots_dir = f'{scan_dir}/screenshots'
            if os.path.isdir(screenshots_dir):
                return self.parse_screenshots_directly(screenshots_dir, scan, dry_run)
            else:
                self.stdout.write(self.style.WARNING(f'No screenshots directory found at {screenshots_dir}'))
                return 0

        return self.parse_jsonl_file(jsonl_path, scan, dry_run)

    def parse_jsonl_file(self, jsonl_path, scan, dry_run=False):
        """Parse a gowitness JSONL file and update database."""
        updated = 0
        self.stdout.write(f'Parsing {jsonl_path} for scan {scan.id}')

        with open(jsonl_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    result = json.loads(line)
                    url = result.get('url', '')
                    screenshot_file = result.get('screenshot_path', '') or result.get('filename', '')
                    
                    if not screenshot_file:
                        continue

                    # Extract subdomain from URL
                    parsed_url = urlparse(url)
                    subdomain_name = parsed_url.netloc
                    if ':' in subdomain_name:
                        subdomain_name = subdomain_name.split(':')[0]

                    # Find matching subdomain
                    subdomain = Subdomain.objects.filter(
                        name=subdomain_name,
                        scan_history=scan
                    ).first()

                    if subdomain:
                        relative_path = screenshot_file.replace('/usr/src/scan_results/', '')
                        if dry_run:
                            self.stdout.write(f'  Would update {subdomain_name}: {relative_path}')
                        else:
                            subdomain.screenshot_path = relative_path
                            subdomain.save()
                            self.stdout.write(f'  Updated {subdomain_name}: {relative_path}')
                        updated += 1

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f'  Error: {e}'))
                    continue

        return updated

    def parse_screenshots_directly(self, screenshots_dir, scan, dry_run=False):
        """Parse screenshot files directly by matching filenames to subdomains."""
        updated = 0
        domain_name = scan.domain.name
        self.stdout.write(f'Parsing screenshots directly from {screenshots_dir}')

        # Get all image files
        for ext in ['*.jpeg', '*.jpg', '*.png']:
            for screenshot_path in glob.glob(f'{screenshots_dir}/{ext}'):
                filename = os.path.basename(screenshot_path)
                
                # gowitness 3.x filename format: https---subdomain-com-443.jpeg
                # Parse the subdomain from filename
                name_part = filename.rsplit('.', 1)[0]  # Remove extension
                
                # Try to extract subdomain
                # Replace --- with :// and other patterns
                if name_part.startswith('https---'):
                    subdomain_name = name_part[8:]  # Remove https---
                elif name_part.startswith('http---'):
                    subdomain_name = name_part[7:]  # Remove http---
                else:
                    subdomain_name = name_part

                # Replace remaining --- with . and remove port
                subdomain_name = subdomain_name.replace('---', '.')
                # Remove port suffix like -443 or -80
                if subdomain_name.endswith('-443') or subdomain_name.endswith('-80'):
                    subdomain_name = subdomain_name.rsplit('-', 1)[0]
                # Replace remaining dashes that were dots
                # This is tricky - we need to match against known subdomains

                # Find matching subdomain in this scan
                subdomains = Subdomain.objects.filter(scan_history=scan)
                matched_subdomain = None
                
                for sub in subdomains:
                    # Check if subdomain name matches the filename pattern
                    expected_pattern = sub.name.replace('.', '-')
                    if expected_pattern in subdomain_name or sub.name in subdomain_name.replace('-', '.'):
                        matched_subdomain = sub
                        break

                if matched_subdomain:
                    relative_path = screenshot_path.replace('/usr/src/scan_results/', '')
                    if dry_run:
                        self.stdout.write(f'  Would update {matched_subdomain.name}: {relative_path}')
                    else:
                        matched_subdomain.screenshot_path = relative_path
                        matched_subdomain.save()
                        self.stdout.write(f'  Updated {matched_subdomain.name}: {relative_path}')
                    updated += 1
                else:
                    self.stdout.write(self.style.WARNING(f'  No match for {filename}'))

        return updated
