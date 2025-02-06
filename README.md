# Flow Chart Generator

## Description
The **Flow Chart Generator** is a Python script that processes PCAP files and extracts communication flows between network nodes. It converts these flows into a structured format suitable for generating flowcharts. The script supports various network protocols and offers GUI-based interaction.

## Features
- Extracts communication flows from PCAP files.
- Supports multiple protocols, including SIP, Diameter, HTTP, DNS, ISUP, MAP, and more.
- Provides a graphical user interface (GUI) for ease of use.
- Allows filtering and editing of flowchart data.
- Generates HTML-based visualizations.

## Installation
### Prerequisites
Ensure you have Python installed on your system. The script requires the following dependencies:
- `pyshark`
- `tkinter`
- `windnd`
- `webbrowser`
- `re`
- `datetime`

### Install Dependencies
You can install the required packages using pip:
```sh
pip install pyshark windnd
```
(Note: `tkinter` is included with standard Python installations.)

## Usage
### Running the Script
Run the script using:
```sh
python Flow_Chart_Generator.py
```

### How It Works
1. Load a PCAP file using the GUI.
2. The script processes the file and extracts communication nodes.
3. You can edit, filter, and modify the extracted data.
4. Generate a flowchart in HTML format and visualize it in a web browser.

## Contributing
If you'd like to contribute, feel free to fork this repository and submit pull requests.

## License
This project is licensed under the MIT License.



