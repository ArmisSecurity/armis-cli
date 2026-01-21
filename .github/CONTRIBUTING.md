# Contributing

Thanks for your interest in contributing to the Armis CLI!

## Table of Contents

- [Scope](#scope)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing](#testing)
- [Contribution Process](#contribution-process)
- [License](#license)

## Scope

This repository contains the open-source CLI client for interacting with
the Armis cloud APIs. Contributions should focus on:

- CLI usability and UX
- Configuration, authentication, and setup
- Output formatting and developer ergonomics
- Performance and reliability of API interactions

Security detection logic, analysis engines, and backend services are
intentionally out of scope.

## Development Setup

### Prerequisites

- Go 1.24 or later
- [golangci-lint](https://golangci-lint.run/welcome/install/) v2.0+
- Make

### Getting Started

```bash
# Clone the repository
git clone https://github.com/ArmisSecurity/armis-cli.git
cd armis-cli

# Install dev tools (gotestsum for better test output)
make tools

# Build the binary
make build

# Run tests
make test

# Run linters
make lint
```

### Available Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build the binary to `bin/armis-cli` |
| `make test` | Run tests with gotestsum (or go test as fallback) |
| `make lint` | Run golangci-lint |
| `make install` | Install binary to `/usr/local/bin` |
| `make clean` | Remove build artifacts |
| `make tools` | Install development tools |
| `make scan` | Run security scan on this repository |

## Code Style

### Formatting

- All code must be formatted with `gofmt`
- Use tabs for indentation (Go standard)
- Run `gofmt -w .` before committing or use editor integration

### Linting

We use [golangci-lint](https://golangci-lint.run/) with the following linters enabled:

| Linter | Purpose |
|--------|---------|
| `errcheck` | Check for unchecked errors |
| `govet` | Report suspicious constructs |
| `ineffassign` | Detect ineffectual assignments |
| `staticcheck` | Advanced static analysis |
| `unused` | Find unused code |
| `gosec` | Security-focused linting |
| `goconst` | Find repeated strings that could be constants |
| `misspell` | Catch common spelling mistakes |

Run `make lint` to check your code before submitting.

### Error Handling

- Always wrap errors with context using `fmt.Errorf("context: %w", err)`
- Provide actionable error messages for user-facing errors
- Don't ignore errors; use `_ = fn()` explicitly if intentional

```go
// Good
if err != nil {
    return fmt.Errorf("failed to read config: %w", err)
}

// Bad
if err != nil {
    return err  // Missing context
}
```

### Comments

- Add package-level comments to all packages
- Document exported functions and types
- Focus on "why" rather than "what" in inline comments

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run with verbose output
go test -v ./...

# Run specific package tests
go test -v ./internal/api/...

# Run with race detection
go test -race ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Writing Tests

- Use table-driven tests for multiple test cases
- Place tests in the same package as the code being tested
- Use meaningful test names that describe the scenario

```go
func TestFormatBytes(t *testing.T) {
    tests := []struct {
        name     string
        bytes    int64
        expected string
    }{
        {"zero bytes", 0, "0B"},
        {"kilobytes", 1024, "1.0KiB"},
        {"megabytes", 1048576, "1.0MiB"},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := formatBytes(tt.bytes)
            if result != tt.expected {
                t.Errorf("got %s, want %s", result, tt.expected)
            }
        })
    }
}
```

### Test Utilities

- HTTP test helpers are available in `internal/testutil/`
- Sample test data is in `test/` directory

## Contribution Process

1. **Fork the repository** and clone it locally

2. **Create a feature branch** from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**:
   - Keep commits focused and atomic
   - Write clear commit messages

4. **Run quality checks**:

   ```bash
   make lint
   make test
   ```

5. **Submit a pull request**:
   - Fill out the PR template completely
   - Link related issues
   - Ensure CI passes

### Commit Messages

Follow conventional commit style:

```text
type: brief description

Longer explanation if needed.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`

### Pull Request Guidelines

- Keep PRs focused on a single change
- Update documentation if behavior changes
- Add tests for new functionality
- Ensure all CI checks pass
- Respond to review feedback promptly

## Reporting Issues

- **Bugs**: Use the [bug report template](https://github.com/ArmisSecurity/armis-cli/issues/new?template=bug_report.md)
- **Features**: Use the [feature request template](https://github.com/ArmisSecurity/armis-cli/issues/new?template=feature_request.md)
- **Security**: See [SECURITY.md](./SECURITY.md) for vulnerability reporting

## License

By submitting a contribution, you agree that your contribution will be
licensed under the Apache License 2.0.

You represent that you have the right to submit the contribution and that
it does not infringe on the rights of any third party.
