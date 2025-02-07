# Flow Chart Generator

## Overview

The **Flow Chart Generator** is a Python script designed to generate flow charts from PCAP (Packet Capture) files. It uses the `pyshark` library to parse PCAP files and extract network communication details, which are then visualized as flow charts using the `mscgen` format. The script also provides a graphical user interface (GUI) built with `tkinter` for ease of use.

The generated flow charts can be viewed in a web browser, and the script supports various protocols such as SIP, Diameter, DNS, and more. Additionally, the script allows users to edit the generated charts, apply filters, and save the charts for later use.

## Features

The Flow Chart Generator includes the following key features:

- **PCAP File Parsing**: Parse PCAP files and extract relevant network communication details.
- **Flow Chart Generation**: Generate flow charts in the `mscgen` format, viewable in a web browser.
- **Protocol Support**: Support for multiple protocols including SIP, Diameter, DNS, HTTP, ISUP, MEGACO, and MAP.
- **Graphical User Interface**: User-friendly GUI for selecting PCAP files, applying filters, and generating flow charts.
- **Filtering**: Apply Wireshark-like filters to focus on specific packets or protocols.
- **Editing**: Edit generated flow charts, including adding or removing nodes, changing message labels, and more.
- **Saving and Loading**: Save generated flow charts and load them later for further editing or viewing.

## Installation

### Prerequisites

Before running the script, ensure you have the following installed:

- **Python 3.x**: The script is written in Python 3
- **pyshark**: A Python wrapper for tshark (Wireshark's command-line tool)
- **tkinter**: A standard Python library for creating GUIs
- **mscgen_js**: A JavaScript library for rendering flow charts (included in the script)

### Installation Steps

1. Clone the Repository:
   ```bash
   git clone https://github.com/yourusername/flow-chart-generator.git
   cd flow-chart-generator
   ```

2. Install Dependencies:
   ```bash
   pip install pyshark
   ```

3. Run the Script:
   ```bash
   python Flow_Chart_Generator.py
   ```

## Usage

### Running the Script

1. Launch the GUI by running:
   ```bash
   python Flow_Chart_Generator.py
   ```

2. Select a PCAP File or Folder:
   - Use the "Choose pcap file" button to select a single PCAP file
   - Use the "Choose pcap folder" button to select a folder containing multiple PCAP files

3. Apply Filters:
   - Enter a Wireshark-like filter string in the "Filter String" field
   - Optionally, use the "Additional text filter" to further filter messages

4. Generate the Flow Chart:
   - Click the "Generate diagram from pcap(s)" button
   - The flow chart will open in your default web browser

### Editing the Flow Chart

The editing window provides several options for customizing your flow charts:

- Add or remove nodes (network entities)
- Modify message labels, protocols, and content
- Change line types (solid, dotted, bidirectional)
- Add notes to specific messages or nodes
- Filter messages based on specific criteria

### Saving and Loading

- Save your flow chart using the "Save chart" button in the editing window
- Load previously saved flow charts using the "Open/Edit saved flowchart" option

### Command-Line Usage

You can also run the script from the command line:

```bash
python Flow_Chart_Generator.py path/to/your/file.pcap
```

## File Structure

- `Flow_Chart_Generator.py`: Main script file
- `resource.js`: mscgen_js library for rendering flow charts
- `hosts.txt`: IP-to-hostname mappings (optional)
- `wireshark_filter.ini`: Predefined Wireshark filters (optional)

## Example Usage

### Sample Scenario

Consider a PCAP file containing SIP messages between endpoints:

1. UE (User Equipment) sends an INVITE to SBC (Session Border Controller)
2. SBC responds with a 100 Trying message
3. SBC sends a Diameter AAR message to PCRF (Policy and Charging Rules Function)
4. PCRF responds with a Diameter AAA message

The script will generate a visual flow chart representing this communication sequence, with appropriate labels and message types.

## Troubleshooting

Common issues and solutions:

- **Missing Dependencies**: Ensure all required packages are installed
- **PCAP File Issues**: Verify that PCAP files are not corrupted and contain valid packets
- **Filter Issues**: Double-check filter syntax if no output is generated

## Contributing

Contributions are welcome! If you find issues or have suggestions for improvements:

1. Open an issue describing the problem or enhancement
2. Submit a pull request with proposed changes
3. Follow existing code style and documentation patterns

## License

This project is licensed under the MIT License. See the LICENSE file for details.
