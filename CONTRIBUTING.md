# Contributing to NetSentinel

We welcome contributions to NetSentinel! To maintain code quality, ensure compatibility, and prevent regressions, please follow these guidelines when submitting pull requests.

---

## Contribution Workflow

### 1. Set Up Your Environment
Follow the instructions in the [README.md](README.md) to set up your Python virtual environment and database:
```bash
python -m venv .venv
# Activate virtual environment
# Install dependencies
pip install -r requirements.txt
```

### 2. Create a Feature Branch
Always base your changes on the `develop` branch and name your feature branch descriptively:
```bash
git checkout develop
git checkout -b feature/your-feature-name
```

### 3. Coding Guidelines
- **Modularity**: Keep new features, database repositories, and API views separated in their respective directories.
- **PennyLane Compilation**: Keep quantum circuit qubit count variables constrained to `(2, 4, 6, 8)` to maintain simulator speed.
- **Database Safety**: Ensure database connections are managed safely. Avoid executing sequential lookup loops inside repositories.
- **Asynchronous Safe Mutex**: Do not block request threads. Read and write global shared telemetry states under locked conditions (`threading.Lock`).

### 4. Testing Your Changes
You must run the complete test suite to ensure all unit and integration tests pass successfully before pushing:
```bash
.venv\Scripts\python.exe -m pytest
```
If you are introducing new features or API endpoints, add corresponding test coverage inside `tests/` (e.g., `tests/test_qnn.py`).

### 5. Commits
Write clear, concise commit messages detailing the changes you are proposing.

### 6. Create a Pull Request
Push your branch to GitHub and open a pull request targeting the `develop` branch. Ensure your pull request description explains what changes were made, how they were tested, and what issue they address.
