from rest_framework import serializers
from scanner.models import Scan, Check, Finding, SEVERITIES_CHOICES

class ScanSerializer(serializers.HyperlinkedModelSerializer):
    status = serializers.ReadOnlyField()
    start = serializers.ReadOnlyField()
    end = serializers.ReadOnlyField()
    severities = serializers.MultipleChoiceField(choices=SEVERITIES_CHOICES)
    checks = serializers.HyperlinkedRelatedField(many=True, view_name="check-detail", read_only=True)

    class Meta:
        model = Scan
        fields = ['url', 'id', 'status', 'provider', 'severities', 'start', 'end', 'checks']

class CheckSerializer(serializers.HyperlinkedModelSerializer):
    scan = serializers.ReadOnlyField(source='scan.pk')
    findings = serializers.HyperlinkedRelatedField(many=True, view_name="finding-detail", read_only=True)

    class Meta:
        model = Check
        fields = ['url', 'id', 'name', 'details', 'scan', 'findings']

class FindingSerializer(serializers.HyperlinkedModelSerializer):
    scan_check = serializers.ReadOnlyField(source='scan_check.name')
    class Meta:
        model = Finding
        fields = ['url', 'id', 'scan_check', 'details']
