import asyncio

from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import DataTable, Static, Button, Header, Footer

from Network_scanner import PacketSaver

class SnifferTUI(App):

    def compose(self) -> ComposeResult:
        yield Header()

        with Horizontal():
            yield Button("Start Sniffing", id="start_sniffing")
            yield Button("Stop Sniffing", id="stop_sniffing")

            yield DataTable(id="packet_table")


        yield Footer()


    def on_mount(self):
        self.saver = PacketSaver()
        self.sniffing = False

        packet_table = self.query_one("#packet_table", DataTable)
        packet_table.add_columns("Timestamp", "Source IP", "Destination IP", "Protocol", "Length")

    async def start_sniffing(self):
        self.sniffing = True
        def process_packet(packet):
            if not self.sniffing:
                return
            timestamp = packet.time
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst

                self.call_from_thread(self.update_table, timestamp, src, dst, packet.name, len(packet))
                self.call_from_thread(self.query_one("#packet_table, DataTable".add_row, timestamp, src, dst, "TCP/UDP", ""))

        await asyncio.to_thread(sniff, prn=process_packet, store=False, timeout=5)


    def on_button_pressed(self, event: Button.Pressed):
        button_id = event.button.id
        if button_id == "start_sniffing":
            self.start_sniffing()
        elif button_id == "stop_sniffing":
            self.stop_sniffing()


if __name__ == "__main__" :
    app = SnifferTUI()
    app.run()