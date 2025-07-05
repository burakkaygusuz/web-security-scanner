# Web Security Scanner

This is a Java-based web security scanner designed to identify common web vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), and Sensitive Information Exposure. It crawls a target website, analyzes its pages, and reports any detected vulnerabilities.

## Features

- **SQL Injection Detection**: Identifies potential SQL injection vulnerabilities by injecting various payloads into URL parameters.
- **Cross-Site Scripting (XSS) Detection**: Detects XSS vulnerabilities by injecting XSS payloads into URL parameters and checking for their reflection in the response.
- **Sensitive Information Exposure**: Scans web page content for patterns indicative of sensitive data like email addresses, phone numbers, and API keys.
- **Web Crawler**: Navigates through the target website to discover and scan multiple pages.

## Technologies Used

- **Java**: Core programming language.
- **Maven**: Project management and build automation tool.
- **OkHttp**: For making HTTP requests.
- **JSoup**: For parsing and manipulating HTML.
- **JLine**: For command-line interface interactions.
- **SLF4J**: For logging.

## How to Build

To build the project, navigate to the root directory of the project and run the following Maven command:

```bash
mvn clean install
```

## How to Run

You can run the scanner by providing a target URL as a command-line argument.

**Example Usage:**

To scan a target website (e.g., `http://example.com`):

```bash
mvn exec:java -Dexec.mainClass="io.github.burakkaygusuz.Main" -Dexec.args="http://example.com"
```

**Testing with a Vulnerable Website:**

For testing purposes, you can use a known vulnerable website like `http://testphp.vulnweb.com/`. This will demonstrate the scanner's ability to detect various vulnerabilities.

```bash
mvn exec:java -Dexec.mainClass="io.github.burakkaygusuz.Main" -Dexec.args="http://testphp.vulnweb.com/"
```

The scanner will output detected vulnerabilities directly to the console.
