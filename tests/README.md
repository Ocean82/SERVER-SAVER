# Tests

This directory contains unit tests for the SERVER-SAVER project.

## Running Tests

### Run all tests:
```bash
python -m pytest tests/
```

Or using unittest:
```bash
python -m unittest discover tests
```

### Run specific test file:
```bash
python -m unittest tests.test_server_monitor
```

### Run with coverage:
```bash
pip install pytest-cov
pytest --cov=server_monitor tests/
```

## Test Structure

- `test_server_monitor.py` - Tests for main monitoring functionality
- `test_example.py` - Example test template

## Writing Tests

When adding new features, add corresponding tests:

1. Create test file: `tests/test_feature_name.py`
2. Import the module you're testing
3. Use `unittest.mock` to mock AWS services
4. Test both success and failure cases
5. Run tests before committing

## Mocking AWS Services

Example:
```python
from unittest.mock import patch, Mock

@patch('boto3.client')
def test_aws_feature(self, mock_boto):
    mock_client = Mock()
    mock_boto.return_value = mock_client
    # Your test code
```

## Continuous Integration

Tests run automatically on:
- Pull requests
- Pushes to main branch
- Scheduled runs (see `.github/workflows/`)

---

**Note:** Some tests require AWS credentials or mocking. Use mocks for unit tests to avoid requiring real AWS access.

