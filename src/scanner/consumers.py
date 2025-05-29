import json

from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer

from .models import Scan


class ScanConsumer(WebsocketConsumer):
    def connect(self):
        self.room_name = self.scope["url_route"]["kwargs"]["scan_id"]
        self.room_group_name = f"scan_id_{self.room_name}"
        try:
            scan_id = int(self.room_name)
            scan = Scan.objects.get(pk=scan_id)
        except Exception:
            self.close()
            return

        async_to_sync(self.channel_layer.group_add)(
            self.room_group_name, self.channel_name
        )
        self.accept()

        self.send(text_data=json.dumps({"message": {"status": scan.status}}))

    def disconnect(self, code):
        async_to_sync(self.channel_layer.group_discard)(
            self.room_group_name, self.channel_name
        )
    
    # Send message from channel layer to websocket 
    def chat_message(self, event):
        message = event["message"]
        self.send(text_data=json.dumps({"message": message}))