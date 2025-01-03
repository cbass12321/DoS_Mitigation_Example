# DoS_Mitigation_Example
This project was for class, the goal was to create some locally hosted web server and protect it from a Denial of Service attack. I choose to go with a simple python server and implemented mitigation specifically for the PPs method from the [MHDDoS](https://github.com/MatrixTM/MHDDoS) script.

---

## Features

- Tracks and blocks IPs exceeding a request threshold (`100 requests in 60 seconds`).
- Prevents directory traversal attacks by detecting patterns like `../` and `/etc/passwd`.
- Logs all requests, blocked IPs, and abnormal activities.

---

## Setup

1. Update the IP and port in the script:

   ```bash
     pip install flask flask_sqlalchemy scapy
     ```

3. Install required Python libraries:

   ```bash
     pip install -r requirements.txt
     ```

5. Run the server:

   ```bash
     python Dos-Web-Server.py
     ```
  
