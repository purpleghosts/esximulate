# ESXimulate

**ESXimulate** is a Python-based low-interaction honeypot designed to simulate a VMware ESXi environment. It serves fake ESXi web client pages and responds to specific HTTP and HTTPS requests to mimic the behavior of a real ESXi server. It generates self-signed certificates to enhance the illusion and logs login attempts and other interactions for security monitoring. ESXimulate is designed to detect and record unauthorized access attempts while providing minimal information to potential attackers.

## Features

- Simulates VMware ESXi web client interface
- Handles HTTP and HTTPS requests
- Generates self-signed certificates
- Logs login attempts and other interactions
- Provides minimal information to potential attackers
- Redirects HTTP to HTTPS

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/purpleghosts/ESXimulate
    cd ESXimulate
    ```

2. Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run the honeypot, use the following command:

  ```bash
  python ESXimulate.py <common_name> [--force]
  ```
- <common_name>: The common name for the self-signed certificate.
- --force: Regenerate the self-signed certificate.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

ESXimulate is intended for educational and research purposes only. The developers are not responsible for any misuse of this software.
