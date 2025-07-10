# Web Security Scanner


A comprehensive Java-based web security scanner designed to identify common web vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), CSRF vulnerabilities, and Sensitive Information Exposure. Built with Spring Boot for modularity and enterprise-grade features.

## 🚀 Features

- **SQL Injection Detection**: Identifies potential SQL injection vulnerabilities by injecting various payloads into URL parameters and forms
- **Cross-Site Scripting (XSS) Detection**: Detects XSS vulnerabilities by injecting XSS payloads into URL parameters and checking for their reflection in the response
- **CSRF Protection Testing**: Comprehensive CSRF token validation and same-site cookie testing
- **Sensitive Information Exposure**: Scans web page content for patterns indicative of sensitive data like email addresses, phone numbers, SSNs, API keys, and credit card numbers
- **Web Crawler**: Intelligent web crawler that navigates through the target website to discover and scan multiple pages
- **Rate Limiting**: Built-in rate limiting to avoid overwhelming target servers
- **Configurable Scanning**: Flexible configuration system for payloads, patterns, and scan settings
- **Comprehensive Reporting**: Detailed vulnerability reports with color-coded output
- **Database Integration**: Persistent storage of scan results using H2 database
- **Spring Boot Architecture**: Enterprise-grade architecture with dependency injection and configuration management

## 🛠️ Technologies Used

- **Java 21**: Core programming language with modern features
- **Spring Boot 3.2.0**: Enterprise application framework with dependency injection, configuration management, and auto-configuration
- **Spring Data JPA**: Data persistence layer with H2 database
- **Spring Boot Actuator**: Production-ready monitoring and management features
- **Maven**: Project management and build automation tool
- **OkHttp**: High-performance HTTP client for making requests
- **JSoup**: HTML parsing and manipulation library
- **JLine**: Advanced command-line interface interactions
- **SLF4J + Logback**: Comprehensive logging framework
- **Jackson**: JSON processing for configuration and reporting
- **Resilience4j**: Rate limiting and fault tolerance
- **JUnit 5**: Unit testing framework
- **AssertJ**: Fluent assertion library for tests
- **Mockito**: Mocking framework for unit tests

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

**Exit Code Configuration:**

By default, the scanner always exits with code 0 (success) when the scan completes successfully, regardless of whether vulnerabilities are found. This allows the scanner to be used in CI/CD pipelines without failing the build based on vulnerability detection.

To make the scanner exit with a non-zero code when vulnerabilities are found (useful for security gates in CI/CD):

```bash
# Using Maven
mvn spring-boot:run -Dspring-boot.run.arguments="http://example.com" -Dspring-boot.run.jvmArguments="-Dscanner.cli.fail-on-vulnerabilities=true" -Dscanner.cli.enabled=true

# Using JAR
java -jar target/web-security-scanner-<version>.jar http://example.com --scanner.cli.enabled=true --scanner.cli.fail-on-vulnerabilities=true
```

With `fail-on-vulnerabilities=true`:
- Exit code 0: No vulnerabilities found
- Exit code 1: Vulnerabilities found
- Exit code 2: Scan error occurred

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

## 📊 Configuration

The scanner uses Spring Boot's externalized configuration system. You can customize scanning behavior through:

### Application Properties

- **`application.yml`**: Main configuration file with default settings
- **`application-test.yml`**: Test-specific configuration
- **`scanner.cli.enabled`**: Enable/disable CLI mode (default: true)
- **`scanner.cli.fail-on-vulnerabilities`**: Exit with non-zero code when vulnerabilities are found (default: false)

### Configurable Settings

- **SQL Injection Payloads**: Customize SQL injection test payloads
- **XSS Payloads**: Configure XSS detection patterns
- **Sensitive Data Patterns**: Regular expressions for detecting sensitive information
- **Scan Settings**: Max depth, timeout, rate limiting
- **CSRF Settings**: Token validation rules and cookie policies

### Example Configuration

```yaml
scanner:
  cli:
    enabled: true
    auto-shutdown: true
    fail-on-vulnerabilities: false  # Set to true for CI/CD security gates
  scanSettings:
    maxDepth: 3
    timeoutSeconds: 30
    rateLimitRequestsPerSecond: 3
  csrfSettings:
    testForms: true
    checkSameSiteCookies: true
    minimumTokenLength: 16
```

## 🧪 Testing

The project includes comprehensive unit and integration tests.

### Running Tests

```bash
# Run all tests
mvn test

# Run tests with specific profile
mvn test -Dspring.profiles.active=test

# Run specific test class
mvn test -Dtest=ConfigLoaderTest

# Run tests with coverage
mvn test jacoco:report
```

### Test Coverage

- **86 total tests** covering all major components
- **Unit Tests**: Model classes, utilities, configuration
- **Integration Tests**: Full application context, service layer
- **Spring Boot Tests**: Configuration validation, dependency injection

### Test Categories

- **Configuration Tests**: Scanner configuration loading and validation
- **Model Tests**: Vulnerability models, form data, CSRF scenarios
- **Service Tests**: Report generation, data persistence
- **Utility Tests**: URL utilities, helper functions
- **Integration Tests**: End-to-end scanning workflows

## 🔍 Spring Boot Features

- **Externalized Configuration**: Flexible configuration through YAML/Properties files
- **Dependency Injection**: Clean, testable architecture with Spring's IoC container
- **Auto-Configuration**: Automatic setup of components based on classpath
- **Actuator Endpoints**: Health checks, metrics, and monitoring
- **Profile-Based Configuration**: Different settings for development, testing, and production
- **Data Persistence**: JPA-based data access with H2 database
- **Command Line Interface**: Optional CLI mode with JLine integration

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


## 🛡️ Security Considerations

- **Rate Limiting**: Built-in rate limiting prevents overwhelming target servers
- **Configurable Timeouts**: Prevents hanging requests
- **Responsible Disclosure**: Only scan systems you own or have explicit permission to test
- **No Persistent Attacks**: The scanner performs read-only vulnerability detection

## 📈 Performance

- **Concurrent Scanning**: Multi-threaded scanning for improved performance
- **Memory Efficient**: Streaming processing of large responses
- **Configurable Limits**: Adjustable depth and timeout settings
- **Connection Pooling**: Efficient HTTP connection management

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Disclaimer

This tool is intended for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The developers are not responsible for any misuse of this tool.

## 📞 Support

For questions, issues, or contributions:

- 🐛 [Report Issues](https://github.com/burakkaygusuz/web-security-scanner/issues)
- 💬 [Discussions](https://github.com/burakkaygusuz/web-security-scanner/discussions)
- 🔄 [Pull Requests](https://github.com/burakkaygusuz/web-security-scanner/pulls)
