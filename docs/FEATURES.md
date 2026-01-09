# Armis CLI Features

## 🎯 Enhanced Output Features

### Interactive Summary Dashboard

The CLI now displays scan results in a clean, box-drawn dashboard format:

```
┌─────────────────────────────────────────────────────────────┐
│  📊 SCAN SUMMARY                                            │
├─────────────────────────────────────────────────────────────┤
│  Total Findings: 15                                         │
│  Filtered (Non-Exploitable): 3                              │
│                                                             │
│  🔴 CRITICAL: 2                                             │
│  🟠 HIGH: 5                                                 │
│  🟡 MEDIUM: 6                                               │
│  🔵 LOW: 2                                                  │
└─────────────────────────────────────────────────────────────┘
```

### Progress Indicators with Context

The CLI shows detailed progress during scans:

- **Creating a compressed archive...** - While packaging your code
- **Uploading archive to Armis Cloud...** - During upload
- **Analyzing code for vulnerabilities...** - While scanning
- **Fetching scan results...** - When retrieving findings

Each stage includes an elapsed timer showing real-time progress.

### Grouping Findings

Group findings by different criteria using the `--group-by` flag:

```bash
# Group by CWE (Common Weakness Enumeration)
armis-cli scan repo . --group-by cwe

# Group by severity level
armis-cli scan repo . --group-by severity

# Group by file
armis-cli scan repo . --group-by file

# No grouping (default)
armis-cli scan repo . --group-by none
```

Example grouped output:

```
┌─────────────────────────────────────────────────────────────┐
│ CWE: CWE-89                                                 │
│ Count: 3                                                    │
└─────────────────────────────────────────────────────────────┘

🔴 CRITICAL

SQL Injection vulnerability detected...
```

### Git Blame Integration

When scanning a git repository, the CLI automatically shows who introduced each vulnerability:

```
Location:    internal/api/client.go:45
Git Blame:   John Doe <j***@e***.com> (2024-11-15, abc1234)
```

Features:
- Automatically detects if directory is a git repository
- Shows author, partially masked email, date, and commit SHA
- Gracefully handles non-git directories
- Caches results to avoid redundant git calls

## 🚫 .armisignore Support

Exclude files and directories from scans using `.armisignore` files.

### Usage

Create a `.armisignore` file in your repository root:

```
# Exclude build outputs
dist/
build/
*.o

# Exclude dependencies
node_modules/
vendor/

# Exclude logs
*.log

# Include specific files (negation)
!important.log
```

### Features

- **Gitignore-compatible syntax** - Uses the same pattern matching as `.gitignore`
- **Nested support** - Place `.armisignore` files in subdirectories
- **Glob patterns** - Support for wildcards (`*.log`, `test_*.py`)
- **Directory exclusions** - Exclude entire directories (`node_modules/`)
- **Negation patterns** - Include files that would otherwise be excluded (`!important.log`)
- **Comments** - Lines starting with `#` are ignored

### How It Works

Files matching `.armisignore` patterns are excluded **before** creating the upload archive, reducing:
- Upload time
- Scan time
- Bandwidth usage
- False positives from generated code

## 📝 Improved Help Text

All CLI flags now include detailed descriptions and examples:

```bash
armis-cli scan repo --help
```

Flags include:
- Clear descriptions of what each flag does
- Default values
- Valid options and ranges
- Environment variable alternatives

## 🧪 Testing

All new features include comprehensive unit tests:

```bash
# Run all tests
go test ./...

# Run specific test suites
go test ./internal/scan/repo/...
go test ./internal/output/...
```

## 🎨 Cross-Platform Compatibility

- Uses simple ASCII box characters (┌─┐│└┘) for maximum compatibility
- Works across all operating systems and CI/CD environments
- Gracefully handles terminals without emoji support
- Respects `NO_COLOR` and `TERM=dumb` environment variables

## 📊 Example Workflows

### Basic Scan with Grouping

```bash
armis-cli scan repo . \
  --group-by cwe \
  --format human
```

### Scan with Custom Exclusions

```bash
# Create .armisignore
echo "test/" > .armisignore
echo "*.generated.go" >> .armisignore

# Run scan
armis-cli scan repo .
```

### CI/CD Integration

```bash
# Fail on HIGH or CRITICAL findings
armis-cli scan repo . \
  --fail-on HIGH,CRITICAL \
  --no-progress \
  --format sarif > results.sarif
```

### Development Workflow

```bash
# Include test files and non-exploitable findings
armis-cli scan repo . \
  --include-tests \
  --include-non-exploitable \
  --group-by file
```

## 🔧 Configuration

### Environment Variables

- `ARMIS_API_TOKEN` - API authentication token
- `ARMIS_TENANT_ID` - Tenant identifier
- `ARMIS_FORMAT` - Default output format
- `ARMIS_PAGE_LIMIT` - Results pagination size

### Default Behavior

- Test files are **excluded** by default (use `--include-tests` to include)
- Non-exploitable findings are **filtered** by default (use `--include-non-exploitable` to include)
- Progress indicators are **enabled** by default (use `--no-progress` to disable)
- Grouping is **disabled** by default (use `--group-by` to enable)

## 🚀 Performance Tips

1. **Use .armisignore** - Exclude unnecessary files to speed up uploads
2. **Adjust timeout** - Increase `--timeout` for large repositories
3. **Optimize page limit** - Adjust `--page-limit` based on finding count
4. **Disable progress** - Use `--no-progress` in CI/CD for cleaner logs

## 📖 Additional Resources

- See `.armisignore.example` for a comprehensive ignore file template
- Check `docs/ci-examples/` for CI/CD integration examples
- Run `armis-cli --help` for full command reference
