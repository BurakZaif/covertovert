from CovertChannelBase import CovertChannelBase
from scapy.all import sniff, IP, TCP,Raw
import time

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()
        self.received_message = ""
        self.final_string = ""
        self.receiver_ip = "172.18.0.3"
        self.receiver_port = 8000
        self.ip = "172.18.0.2"
        self.port = 8000

    def create_tcp_packet(self, src_ip, dst_ip, src_port, dst_port, window_size):

        window_size = max(0, min(window_size, 65535))

        ip_layer = IP(src=src_ip, dst=dst_ip)
        tcp_layer = TCP(
            sport=src_port,
            dport=dst_port,
            flags="S",
            window=window_size
        )

        packet = ip_layer / tcp_layer

        return packet

    def percentage_calculator(self, window_size, previous_window_size):
        return round(((window_size - previous_window_size) / previous_window_size) * 100)

    def percentage_increase(self, window_size, percentage):
        return round(window_size + (window_size * (percentage / 100)))


    def send(self, log_file_name, percentage_1, percentage_2, percentage_3, percentage_4, initial_window_size):
        """
            - In the send function we manipulate the window size of the TCP packet to send the message. 
            - We take 4 different percentages and 1 initial_window_size parameter as input. 
            - We use the encoding_dict to map the bits of the message to the percentage change of previoues window size. 
            - According to the 2 bit of the message, we encode a different percentage value and with this value we increase or decrease the previous_window_size.
            - If the window size is greater than 2 times the initial window size or less than half of the initial window size, I reset the window size to the initial window size.
            - This is because of the too much increase or decrease in the window size.
            - We also add a fake payload to the packet to make it more realistic.
        """

        start_time = time.time()
        payload = self.generate_random_binary_message()
        message = self.generate_random_message(16, 16)
        self.log_message(message, log_file_name)
        
        self.encoding_dict = {
            '00': percentage_1,
            '01': percentage_2,
            '10': percentage_3,
            '11': percentage_4,
        }

        binary_message = ''.join(format(ord(c), '08b') for c in message)
        window_size = initial_window_size
        flag = False
        payload_bits = ''.join(format(ord(c), '08b') for c in payload)
        payload_index = 0

        for i in range(0, len(binary_message), 2):
            bits = binary_message[i:i+2]
            
            if bits in self.encoding_dict:
                temp = self.encoding_dict[bits]
                window_size = self.percentage_increase(window_size, temp)

                if (window_size > initial_window_size * 2 or window_size < initial_window_size/2):
                    flag = True

            if(temp == percentage_2 and flag == True):
                window_size = initial_window_size
                flag = False

            packet = self.create_tcp_packet(
                src_ip=self.ip,
                dst_ip=self.receiver_ip,
                src_port=self.port,
                dst_port=self.receiver_port,
                window_size=window_size
            )

            if payload_index < len(payload_bits):
                packet = packet/payload_bits[payload_index]
                payload_index += 1
                packet = packet/Raw(load=payload_bits[payload_index])

            super().send(packet)

        end_time = time.time()
        transmission_time = end_time - start_time
        print(f"\nTransmission time: {transmission_time:.2f} seconds")



    def receive(self, log_file_name, percentage_1, percentage_2, percentage_3, percentage_4, range, initial_window_size):
        """
            - In the receive function we listen to the packets and decode the message according to the window size changes.
            - We take 4 different percentages, 1 range parameter and 1 initial_window_size parameter as input.
            - These percentage and initial_window_size parameters should be the same as the send function.
            - After we receive the packet, we calculate the window size change percentage according to the previous window_size.
            - After decoding the window size change percentage, we decode the message according to the predetermined bit encoding.
            - We also add a range parameter to the decoding process to prevent the noise in the channel.
            - Percentages should be distinct between them at least 2*(range + 1) 
            - We also add a mechansism to detect that the window size is reset to the initial window size.
        """
        previous_window_size = None

        def receive_loop(packet):
            if not packet.haslayer(TCP):
                return

            nonlocal previous_window_size
            window_size = packet[TCP].window

            if previous_window_size is not None:
                window_size_change = self.percentage_calculator(window_size, previous_window_size)
                
                if window_size == initial_window_size:
                    self.received_message += '01'
                elif percentage_1 - range - 1 < window_size_change <= percentage_1 + range + 1:
                    self.received_message += '00'
                elif percentage_2 - range - 1 < window_size_change <= percentage_2 + range + 1:
                    self.received_message += '01'
                elif percentage_3 - range - 1 < window_size_change <= percentage_3 + range + 1:
                    self.received_message += '10'
                elif percentage_4 - range - 1 < window_size_change <= percentage_4 + range + 1:
                    self.received_message += '11'

                if len(self.received_message) >= 8:
                    char = self.convert_eight_bits_to_character(self.received_message[:8])
                    self.received_message = self.received_message[8:]
                    self.final_string += char
                    if char == '.':
                        self.log_message(self.final_string, log_file_name)
                        return True
            else:
                window_size_change = int(((window_size - initial_window_size) / initial_window_size) * 100)
                
                if 0 < window_size_change <= percentage_1:
                    self.received_message += '00'
                elif percentage_1 < window_size_change <= percentage_2:
                    self.received_message += '01'
                elif percentage_3 < window_size_change <= 0:
                    self.received_message += '10'
                elif percentage_4 < window_size_change <= percentage_3:
                    self.received_message += '11'

            previous_window_size = window_size if window_size != 0 else previous_window_size


        sniff(
            filter=f"tcp and host {self.receiver_ip} and port {self.port}",
            prn=receive_loop,
            store=0,
            stop_filter=lambda x: '.' in self.final_string
        )


