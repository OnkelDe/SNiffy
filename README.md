# SNiffy
SNiffy - A simple and intuitive network packet sniffing tool built with Python. SNiffy captures and analyzes network traffic, highlighting suspicious activities in real-time. Ideal for educational purposes and basic network security monitoring.

## Features

Packet Sniffing: Monitors network traffic on a selected interface and categorizes packets by protocol.
Real-time Display: Outputs packet summaries in the GUI, with suspicious activities highlighted.
Protocol Explanation: Provides a quick reference for common network protocols.
Security Summary: Generates a summary of sniffed packets along with security recommendations.
GUI Interface: User-friendly interface built with tkinter.
Installation
Prerequisites
Python 3.x
scapy library
psutil library
Setup
Clone the repository:

bash
Copy code
git clone https://github.com/your-repo/professional-firewall-simulation.git
cd professional-firewall-simulation
Install the required Python libraries:

bash
Copy code
pip install scapy psutil
Run the application:

bash
Copy code
python firewall_simulation.py
Usage
Launch the Application: Running the script will open the GUI.
Select Network Interface: Choose the interface to monitor from the dropdown menu.
Start Sniffing: Click "Start Sniffing" to begin monitoring network traffic.
Stop Sniffing: Click "Stop Sniffing" to halt the packet capture.
View Summary: Click "Show Summary" to get a summary of the packets sniffed and view security tips.
Security Tips Provided by the Application
Monitor frequent ARP requests for potential ARP spoofing.
Investigate any unusual IP addresses communicating with your network.
Be cautious of unexpected protocol activities (e.g., ICMP messages).
Ensure that only authorized devices are connected to your network.
Contributing
If you’d like to contribute to the project:

Fork the repository.
Create a new branch for your feature or bug fix.
Submit a pull request with a detailed explanation of your changes.
License
This project is licensed under the MIT License. See the LICENSE file for more details.

Disclaimer
This tool is designed for educational purposes and should not be used in production environments. The developers are not responsible for any misuse of this application.

Acknowledgements
Special thanks to the developers of the scapy and psutil libraries for providing the necessary tools to build this application.

