# Web Security Scanner

This project uses a simple Flask application to detect basic security vulnerabilities on a website. The scanning process checks for security issues like `XSS` vulnerabilities, exposed admin panel URLs, and error messages.

## Getting Started

### Requirements

This project uses the following libraries:

- Flask
- Requests
- BeautifulSoup4

Ensure the required libraries are installed before running the project.

### Installation

1. Clone the project to your local machine:

    ```bash
    git clone <repo_link>
    ```

2. Navigate to the project directory:

    ```bash
    cd <project_directory>
    ```

3. Install the required Python libraries by running the following command:

    ```bash
    pip install -r requirements.txt
    ```

### Running the Application

When the project is running, a Flask application will start on `localhost`, which will be accessible from your web browser or an API client.

1. Start the Flask application by running the `run.py` file:

    ```bash
    python run.py
    ```

2. The application will run by default at `http://127.0.0.1:5000/`.

### Usage

1. To initiate a scan, navigate to `http://127.0.0.1:5000/` in your browser.

2. Enter the URL you want to scan in the text field and click "Scan" to start the scan.

3. The results will appear in the `pre` element with the ID `result`. The response will include the scan results in JSON format, showing any vulnerabilities found.

Example response:

```json
{
    "url": "http://example.com",
    "status": "Scan completed",
    "vulnerabilities": [
        "Found <script> tags that could lead to an XSS vulnerability.",
        "Exposed admin panel found: http://example.com/admin"
    ]
}
