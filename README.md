# COVERTOVERT
Open-source implementation of "network" covert channels.

## Table of Contents
- [What is a Covert Channel?](#what-is-a-covert-channel)
- [Covert Storage Channels](#covert-storage-channels)
- [Our TCP Protocol Field Manipulation - Window Size](#our-tcp-protocol-field-manipulation---window-size)
  - [Sender](#sender)
  - [Receiver](#receiver)
- [Result](#result)
- [Parameter Prerequisites](#parameter-prerequisites)
- [Contributors](#contributors)
- [Installation](#installation)

## What is a Covert Channel?
A covert channel is a method of communication that bypasses normal security controls and is used to transmit information in ways that were not originally intended or authorized. Unlike legitimate communication channels, covert channels exploit side effects or unused portions of a system, such as timing delays, hidden data fields, or unconventional use of protocols, to encode and transfer information between parties. These channels often operate secretly, making them difficult to detect and prevent, and are commonly studied in cybersecurity to understand how sensitive information might be leaked or exfiltrated unnoticed.

Covert channels can be categorized into two types:
1. **Covert Timing Channels:** Information is encoded into the timing between events or messages.
2. **Covert Storage Channels:** Information is embedded into storage fields within a protocol or system.

This project focuses on implementing a covert storage channel.

## Covert Storage Channels
A covert storage channel embeds information within specific fields of a protocol or system, such as headers or metadata, to transmit data covertly. Without altering the system’s behavior, it leverages legitimate storage locations in the packets to transfer secret data to the receiver.

### Protocol Field Manipulation
Protocol field manipulation is a technique where specific fields of a network protocol header—such as the IP identification field, TCP sequence number, or unused flag bits—are modified to encode information. This project uses the TCP Window Size field, which has a 16-bit size, making it an ideal candidate for embedding data. The field is typically used to control the flow of data, ensuring the sender does not overwhelm the receiver. Here, we exploit its wide range to encode messages covertly.

## Our TCP Protocol Field Manipulation - Window Size
In our covert channel, a consensus is built between the sender and receiver. Both sides need to share parameters to decode the message accurately.

### Sender
The sender side takes five parameters:
- **4 percentage parameters**: Representing encoding values for different 2-bit combinations.
- **1 initial window size parameter**: Used as the starting point for encoding.

**Encoding Process:**
1. The sender takes the initial window size and maps the 2-bit chunks of the message to percentage parameters.
2. Depending on the mapped percentage, the window size is adjusted (increased or decreased).
3. If the adjusted window size exceeds twice the initial value or drops below half the initial value, it is reset to the initial value to prevent detection or protocol errors. 
(While doing this, I do not refresh the window_size immediately to make it more undetected. I wait a specific 2 bit combination but if your example do not contain this combination even for once you should change the encoding_dict because you can change the relevant percentage-2bit combination pair form there.)
4. The manipulated window size is inserted into the TCP header.
5. An optional fake payload can be added to make the communication more realistic.

### Receiver
The receiver side takes six parameters:
- **4 percentage parameters**: Must match those used by the sender.
- **1 range parameter**: Adds a tolerance to decode noisy data.
- **1 initial window size parameter**: Must match the sender’s initial value.

**Decoding Process:**
1. The receiver extracts the window size from incoming packets.
2. It calculates the percentage change relative to the previous window size.
3. Using the predefined range and percentage parameters, it decodes the change back to the original 2-bit message chunk.
4. Once 8 bits (1 character) are decoded, they are converted to a character and appended to the final message.
5. The process continues until the end-of-message character (e.g., a period) is reached.

## Result
This implementation achieves covert communication by embedding a secret message into TCP header fields. The channel remains undetected as the data appears normal to external observers. Performance analysis shows:
- A 128-bit message takes minimum takes 3.06 seconds to transmit.
- Maximum covert channel capacity: **41.83 bits/second**.

## Parameter Prerequisites
To ensure stability and correct operation, adhere to the following guidelines:
- **Percentage Parameters:**
  - Each percentage value must differ from others by at least `2*(range + 1)` to avoid overlap. Also any percentage should not be zero. 
  - Give them as integer values.
  - First percentage value should a positive value and third one should be negative. The reason is that at least one of them should be positive and negative. All of should not be positive or negative to not detect. So I choose first and third one to imply this.
- **Initial Window Size:**
  - Range: 8,000 to 25,000 (optimal values to minimize detection risk and errors).
  - Avoid values below 5,000 or above 30,000 as they may cause stability issues.
- **Range Parameter:** Must not exceed 3 to maintain decoding accuracy. Its range is can be 0-3. (This parameter is not necessary for implementation but I define this for ease of use and more guraanteed borders between percentages.)

## Contributors
- Burak Zaifoğlu
- Efe Yılmaz

## Installation
1. Install Docker (and optionally Compose V2 plugin).
2. Install VSCode for code development and debugging.

**Start Docker containers:**
```bash
docker compose up -d
```

**Stop Docker containers:**
```bash
docker compose down
```

**Access sender container:**
```bash
docker exec -it sender bash
```

**Access receiver container:**
```bash
docker exec -it receiver bash
```

**Notes:**
- Work in the `/app` folder within the containers. This folder is synchronized with the `code` directory on your host machine.
- To avoid data loss, push your code to GitHub before shutting down Docker instances.
- The `examples` folder contains a covert timing channel example. Review this example before proceeding.

**Persistent Storage:**
Changes made in the `/app` folder are persistent and synchronized with your local `code` directory. Other directories inside the containers will lose data upon shutdown.
