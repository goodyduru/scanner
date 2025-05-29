from rest_framework import serializers
from scanner.models import Scan, Check, Finding, SEVERITIES_CHOICES

class ScanSerializer(serializers.HyperlinkedModelSerializer):
    status = serializers.ReadOnlyField()
    start = serializers.ReadOnlyField()
    end = serializers.ReadOnlyField()
    severities = serializers.MultipleChoiceField(choices=SEVERITIES_CHOICES)
    checks = serializers.HyperlinkedRelatedField(many=True, view_name="check-detail", read_only=True)
    status_url = serializers.HyperlinkedIdentityField(view_name='scan-status')

    class Meta:
        model = Scan
        fields = ['url', 'id', 'status', 'provider', 'severities', 'start', 'end', 'status_url', 'checks']

class CheckSerializer(serializers.HyperlinkedModelSerializer):
    scan = serializers.HyperlinkedRelatedField(source='scan.pk', view_name="scan-detail", read_only=True)
    findings = serializers.HyperlinkedRelatedField(many=True, view_name="finding-detail", read_only=True)

    class Meta:
        model = Check
        fields = ['url', 'id', 'name', 'service_name', 'severity', 'scan', 'findings']

class FindingSerializer(serializers.HyperlinkedModelSerializer):
    check_url = serializers.HyperlinkedRelatedField(source='scan_check.pk', view_name="check-detail", read_only=True)
    scan_check = serializers.ReadOnlyField(source='scan_check.name')
    class Meta:
        model = Finding
        fields = ['url', 'id', 'message', 'title', 'resource_name', 'resource_type', 'risk', 'remediation', 'check_url', 'scan_check']
