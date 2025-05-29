from rest_framework import viewsets
from rest_framework.decorators import action
from scanner.models import Scan, Check, Finding, SEVERITIES
from scanner.serializers import ScanSerializer, CheckSerializer, FindingSerializer
from scanner.scan import run_scan

# Create your views here.
class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer

    @action(detail=True)
    def status(self, request, *args, **kwargs):
        scan = self.get_object()
        return Response(scan.status)

    def perform_create(self, serializer):
        # Scan for all severities when none is set
        if len(serializer.validated_data['severities']) == 0:
            scan = serializer.save(status='pending', severities=set(SEVERITIES))
        else:
            scan = serializer.save(status='pending')
        run_scan(scan)



class CheckViewSet(viewsets.ModelViewSet):
    queryset = Check.objects.all()
    serializer_class = CheckSerializer

class FindingViewSet(viewsets.ModelViewSet):
    queryset = Finding.objects.all()
    serializer_class = FindingSerializer
