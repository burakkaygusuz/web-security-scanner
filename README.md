# Web Security Scanner

This is a Java-based web security scanner designed to identify common web vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), and Sensitive Information Exposure. It crawls a target website, analyzes its pages, and reports any detected vulnerabilities.

## Features

- **SQL Injection Detection**: Identifies potential SQL injection vulnerabilities by injecting various payloads into URL parameters.
- **Cross-Site Scripting (XSS) Detection**: Detects XSS vulnerabilities by injecting XSS payloads into URL parameters and checking for their reflection in the response.
- **Sensitive Information Exposure**: Scans web page content for patterns indicative of sensitive data like email addresses, phone numbers, and API keys.
- **Web Crawler**: Navigates through the target website to discover and scan multiple pages.

## Technologies Used

- **Java**: Core programming language.
- **Spring Boot**: Application framework for rapid development, configuration, and dependency injection.
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

**Important:** The scanner CLI is disabled by default for flexibility. To run the scanner from the command line, you must enable it by passing `-Dscanner.cli.enabled=true`.

You can run the scanner by providing a target URL as a command-line argument.

**Example Usage:**

To scan a target website (e.g., `http://example.com`):

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="http://example.com" -Dscanner.cli.enabled=true
```

Or, after building the JAR:

```bash
java -jar target/web-security-scanner-<version>.jar http://example.com --scanner.cli.enabled=true
```

**Testing with a Vulnerable Website:**

For testing purposes, you can use a known vulnerable website like `http://testphp.vulnweb.com/`. This will demonstrate the scanner's ability to detect various vulnerabilities.

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="http://testphp.vulnweb.com" -Dscanner.cli.enabled=true
```

or

```bash
java -jar target/web-security-scanner-<version>.jar http://testphp.vulnweb.com --scanner.cli.enabled=true
```

The scanner will output detected vulnerabilities directly to the console.

## Spring Boot Features

- **Externalized Configuration**: Uses Spring Boot's configuration properties for flexible setup (see `application.yml` or `application.properties`).
- **Dependency Injection**: Leverages Spring's DI for modularity and testability.

## Code Formatting

This project uses Google Java Format to maintain consistent code style.

### Automatic Formatting

Code is automatically formatted during the Maven build process. The formatter runs in the `process-sources` phase.

### Manual Formatting

To manually format all Java files:

```bash
mvn com.spotify.fmt:fmt-maven-plugin:format
```

### Check Formatting

To check if all files are properly formatted without making changes:

```bash
mvn com.spotify.fmt:fmt-maven-plugin:check
```

This command will fail if any files are not properly formatted, which is useful for CI/CD pipelines.

### IDE Integration

For local development, it's recommended to install the Google Java Format plugin for your IDE:

- **IntelliJ IDEA**: Install the "google-java-format" plugin
- **Eclipse**: Install the Google Java Format plugin
- **VS Code**: Install the "Language Support for Java(TM) by Red Hat" extension with Google Java Format support

### Git Hooks (Recommended)

For the best development experience, install Git hooks that automatically handle code formatting:

```bash
./setup-git-hooks.sh
```

This installs two hooks:

- **pre-commit**: Validates formatting before commits
- **pre-push**: Automatically formats and commits code before pushes

**How it works:**

1. When you run `git push`, the pre-push hook automatically runs
2. If your code is not properly formatted, it will be automatically formatted
3. The formatted code is automatically committed with message "chore: auto-format Java code with Google Java Format"
4. The push continues with the newly formatted and committed code
5. No manual intervention required!

### CI/CD

The GitHub Actions workflow automatically checks code formatting before running tests. If code is not properly formatted, the build will fail.
