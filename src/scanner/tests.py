# Create your tests here.
from unittest.mock import patch
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from scanner.models import Check, Finding, Scan

def mock_successful_scan(scan_id):
    scan_obj = Scan.objects.get(pk=scan_id)
    check = Check(scan=scan_obj, name="test", service_name="test-name", severity="test-severity")
    check.save()
    findings = [
        Finding(scan_check=check, message="message-one", title="title", resource_name="resource-name", 
                resource_type="resource-type", risk="risk", remediation="remediate"),
        Finding(scan_check=check, message="message-two", title="title", resource_name="resource-name", 
                resource_type="resource-type", risk="risk", remediation="remediate"),
    ]
    Finding.objects.bulk_create(findings)
    scan_obj.status = "completed"
    scan_obj.save()

def mock_failed_scan(scan_id):
    scan_obj = Scan.objects.get(pk=scan_id)
    scan_obj.status = "failed"
    scan_obj.save()

def mock_no_scan(scan_id):
    pass


class SiteTests(APITestCase):
    @patch("scanner.views.run_scan_task.delay", mock_successful_scan)
    def test_create_scan(self):
        """
        Ensure we can create a new scan object.
        """
        url = reverse('scan-list')
        data = {'severities': ['critical', 'high'], 'provider': 'aws'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Scan.objects.count(), 1)
        scan = Scan.objects.get()
        self.assertEqual(scan.status, "completed")
        self.assertEqual(scan.provider, "aws")
        self.assertEqual(scan.severities, ['critical', 'high'])
    
    def test_wrong_provider(self):
        """
        Ensure wrong provider produces a 400 error
        """
        url = reverse('scan-list')
        data = {'severities': [], 'provider': 'facebook'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_wrong_severity(self):
        """
        Ensure wrong provider produces a 400 error
        """
        url = reverse('scan-list')
        data = {'severities': ['chilled'], 'provider': 'azure'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
    
    @patch("scanner.views.run_scan_task.delay", mock_successful_scan)
    def test_empty_severity(self):
        """
        Ensure empty severity means all severities
        """
        url = reverse('scan-list')
        data = {'severities': [], 'provider': 'aws'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Scan.objects.count(), 1)
        scan = Scan.objects.get()
        self.assertEqual(scan.status, "completed")
        self.assertEqual(scan.provider, "aws")
        self.assertEqual(scan.severities, ['critical', 'high', 'informational', 'low', 'medium'])

    @patch("scanner.views.run_scan_task.delay", mock_failed_scan)
    def test_failed_scan(self):
        """
        Ensure status reflects failed scan
        """
        url = reverse('scan-list')
        data = {'severities': [], 'provider': 'gcp'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Scan.objects.count(), 1)
        scan = Scan.objects.get()
        self.assertEqual(scan.status, "failed")

    @patch("scanner.views.run_scan_task.delay", mock_no_scan)
    def test_scan_status(self):
        """
        Ensure status endpoint returns scan status
        """
        url = reverse('scan-list')
        data = {'severities': [], 'provider': 'gcp'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        url = reverse('scan-status', args=[1])
        response = self.client.get(url)
        self.assertEqual(response.data, "pending")
    
    @patch("scanner.views.run_scan_task.delay", mock_successful_scan)
    def test_successful_scan_check_and_findings(self):
        """
        Ensure successful scan returns correct check and find urls and data
        """
        url = reverse('scan-list')
        data = {'severities': ['critical', 'high'], 'provider': 'aws'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        url = reverse('scan-detail', args=[1])
        response = self.client.get(url).data
        check_url = response["checks"][0]
        
        response = self.client.get(check_url).data
        self.assertEqual(response['name'], 'test')
        self.assertEqual(len(response['findings']), 2)

        find_url = response['findings'][0]
        response = self.client.get(find_url).data
        self.assertEqual(response["message"], "message-two")
    
    @patch("scanner.views.run_scan_task.delay", mock_failed_scan)
    def test_failed_scan_check_and_findings(self):
        """
        Ensure no check and findings are created on failure
        """
        url = reverse('scan-list')
        data = {'severities': ['critical', 'high'], 'provider': 'aws'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Scan.objects.count(), 1)
        self.assertEqual(Check.objects.count(), 0)
        self.assertEqual(Finding.objects.count(), 0)