from celery import shared_task
from scanner.scan import run_scan

@shared_task()
def run_scan_task(scan_id):
    run_scan(scan_id)