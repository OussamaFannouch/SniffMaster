![[https://i.ibb.co/xLJxhd3/image.png]]

# SNIFFMASTER - A Simple Network Sniffer

Welcome to SNIFFMASTER, a simple network sniffer tool designed to help you capture and analyze network packets. This tool was created by Fannouch Oussama (D1B).

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Menu Options](#menu-options)
  - [Filtering](#filtering)
- [Dependencies](#dependencies)
- [Contributing](#contributing)
- [License](#license)

## Introduction

SNIFFMASTER is a Python-based network sniffer that captures and displays Ethernet frames, IPv4 packets, UDP, and TCP segments. It provides a command-line interface with options for packet filtering based on IP address, port, HTTP requests, and TCP flags.

## Features

- Capture Ethernet, IPv4, UDP, and TCP packets
- Filter packets by IP address, port, HTTP requests, or TCP flags
- Hexdump of packet payloads
- Color-coded packet information

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/OussamaFannouch/sniffmaster.git
   cd sniffmaster
   ```

2. Ensure you have Python 3 installed on your system.

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the sniffer with the following command:
```bash
./sniffmaster.py <interface> [options]
```

### Menu Options

Upon running the script, you will be presented with a menu:
1. Start sniffing
2. Filter
3. Exit

### Filtering

You can apply filters to capture specific packets:
- Filter by IP address: `ip:<value>`
- Filter by port: `port:<value>`
- Filter by HTTP requests: `http`
- Filter by TCP flags: `flag:<value>`

Example usage:
```bash
./sniffmaster.py eth0 -f port:80
```

## Dependencies

- Python 3
- `ethernet_tools` module
- `colors` module

## Contributing

Feel free to fork this repository, make changes, and submit pull requests. We appreciate any contributions that improve the tool.

## License

This project is licensed under the MIT License.

---

Enjoy using SNIFFMASTER and happy sniffing!

---

**Note:** Replace `OussamaFannouch` in the clone URL with your actual GitHub username if you are hosting the repository.
