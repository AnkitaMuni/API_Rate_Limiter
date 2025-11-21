# API Rate Limiter

**Project ID:** P73  
**Course:** UE23CS341A  
**Academic Year:** 2025  
**Semester:** 5th Sem  
**Campus:** RR  
**Branch:** CSE  
**Section:** B  
**Team:** QuadCore

## 📋 Project Description

A middleware or service that can be used to enforce rate limits on API endpoints to prevent abuse.

This repository contains the source code and documentation for the API Rate Limiter project, developed as part of the UE23CS341A course at PES University.

## 🧑‍💻 Development Team (QuadCore)

- [@AnkitaMuni](https://github.com/AnkitaMuni) - Scrum Master
- [@LIKITHAH](https://github.com/LIKITHAH) - Developer Team
- [@AryaSuresh19](https://github.com/AryaSuresh19) - Developer Team
- [@manasa882](https://github.com/manasa882) - Developer Team

## 👨‍🏫 Teaching Assistant

- [@BlackADer-0069](https://github.com/BlackADer-0069)
- [@Abhigna-D](https://github.com/Abhigna-D)
- [@MDAzeemDhalayat](https://github.com/MDAzeemDhalayat)

## 👨‍⚖️ Faculty Supervisor

- *No valid faculty GitHub username found*


## 🚀 Getting Started

### Prerequisites
- Python
- Git
- Code Editor 
- Redis(https://github.com/microsoftarchive/redis/releases)
- Node.js
- npm

### Installation
1. Clone the repository
   ```bash
   git clone https://github.com/pestechnology/PESU_RR_CSE_B_P73_API_Rate_Limiter_QuadCore.git
   cd PESU_RR_CSE_B_P73_API_Rate_Limiter_QuadCore
   ```

2. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

   ```bash
   npm install
   ```


3. Setting Environment 
   ```bash
   $env:REDIS_URL = "redis://localhost:6379"
   ```

4. Run the application
   ```bash
   python -m waitress --host=127.0.0.1 --port=5000 src.main_server:app
   ```

5. Monitoring Redis
    ```bash
   python src/monitor_redis.py
   ```

## 📁 Project Structure

```
PESU_RR_CSE_B_P73_API_Rate_Limiter_QuadCore/
├── src/                 # Source code
├── docs/               # Documentation
├── tests/              # Test files
├── .github/            # GitHub workflows and templates
├── README.md          # This file
└── ...
```

## 🛠️ Development Guidelines

### Branching Strategy
- `main`: Production-ready code
- `develop`: Development branch
- `feature/*`: Feature branches
- `bugfix/*`: Bug fix branches

### Commit Messages
Follow conventional commit format:
- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Test-related changes

### Code Review Process
1. Create feature branch from `develop`
2. Make changes and commit
3. Create Pull Request to `develop`
4. Request review from team members
5. Merge after approval

## 📚 Documentation

- [API Documentation](docs/api.md)
- [User Guide](docs/user-guide.md)
- [Developer Guide](docs/developer-guide.md)

## 🧪 Testing

```bash
# setting environment 
$env:REDIS_URL = "redis://localhost:6379"

# Run tests
npm test

# Run tests with coverage
npm run coverage-run
npm run coverage-report
```

## 🧪 CI/CD Pipeline Development Workflow

Our Continuous Integration and Deployment (CI/CD) pipeline is managed using GitHub Actions and ensures all code meets mandatory quality and security gates before merging or deploying.
The pipeline runs automatically on every push and Pull Request to the main or develop branch.

1. Build  -> Tools Used:=>(pip, npm) Success (Installs all Python (requirements.txt) and Node dependencies.)
2. Test -> Tools Used:=> (unitest, coverage.py) All test must pass (Executes Unit, Integration, and System tests (16+ total))
3. Coverage -> Tools Used:=>(coverage.py) Code Coverage >= 75% (Measures the percentage of source code executed by tests)
4. Lint -> Tools Used :=>(Pylint, Flake8) Pylint Score >= 7.5/10 (Static analysis for code quality, complexity, and style adherence (PEP 8))
5.  Security -> Tools Used:=>(Bandit) No critical vulnerabilities(Scans the Python source code for common security issues (e.g., hardcoded secrets, SQL injection risks).)



Deployment Artifact

Upon successful completion of all 5 stages, a final deployment artifact is generated:

Artifact Name: api-rate-limiter-[SHA_ID].zip

Contents: Contains all source code, configuration files (gunicorn.conf.py, pylintrc, etc.), and all required CI/CD reports (HTML Coverage Report, Bandit JSON Report, Test XML Summary) to prove quality for the next stage.

Run Pipeline Locally

To ensure the pipeline will pass before pushing, run the core checks locally:

# Run all linters (style, quality, security)

```bash
python -m flake8 src/
python -m pylint src/
python -m bandit -r src/
```

## 📄 License

This project is developed for educational purposes as part of the PES University UE23CS341A curriculum.

---

**Course:** UE23CS341A  
**Institution:** PES University  
**Academic Year:** 2025  
**Semester:** 5th Sem
