# GhostNet

## Uncovering Invisible Threats in Modern Networks

GhostNet is a centralized cybersecurity monitoring and threat-detection platform developed as a final-year project. It brings network monitoring, vulnerability assessment, malware analysis, anomaly detection, incident management, and security reporting together in one web-based system.

The project is designed to reduce monitoring blind spots created by isolated security tools. By correlating information from multiple security domains, GhostNet aims to help security teams identify suspicious activity earlier, investigate incidents faster, and maintain a clearer view of their network security posture.

> **Project status:** GhostNet is an academic project under active development. Some integrations, such as Kafka, Nmap, OWASP ZAP, VirusTotal, and honeypot services, require separate local or external configuration before they can be used in a deployment.

## Highlights

- Centralized security dashboard for operational visibility
- JWT-based authentication and role-aware access control
- Network packet capture and traffic monitoring through Pcap4j
- Network alerts, IDS rules, and traffic analysis
- Python-based ML services for anomaly and malware analysis
- YARA-based file scanning
- Vulnerability scanning and CVE data management
- Incident creation, timelines, notes, and statistics
- Honeypot and attacker-interaction management
- File-integrity monitoring
- Windows event-log integration
- REST APIs and STOMP over SockJS WebSocket updates
- PDF vulnerability-report generation
- PostgreSQL persistence
- Optional Kafka-based event processing

## Why GhostNet?

Modern organizations often use separate scanners, intrusion-detection systems, malware-analysis tools, vulnerability platforms, and incident-management tools. When these systems do not share context, related events can be missed and response times increase.

GhostNet addresses this problem with a unified platform that can:

1. Collect security data from multiple sources.
2. Store and organize events, findings, alerts, and incidents.
3. Apply rule-based and machine-learning-based analysis.
4. Correlate suspicious activity across security domains.
5. Present results through a single dashboard.
6. Support investigation, reporting, and operational response.

## Architecture

```text
                           +----------------------+
                           |  React/Vite Frontend  |
                           |      Port 5173        |
                           +----------+-----------+
                                      |
                           REST + JWT | STOMP/SockJS
                                      |
                           +----------v-----------+
                           | Spring Boot Backend  |
                           |      Port 8081       |
                           |       /api            |
                           +----+-------------+---+
                                |             |
                         JPA/JDBC|             | HTTP ML API
                                |             |
                    +-----------v--+     +----v----------------+
                    |  PostgreSQL   |     | Python ML Service  |
                    |    ghostnet   |     |      Port 5000     |
                    +--------------+     +---------------------+
```

### Main components

| Component | Technology | Purpose |
|---|---|---|
| Frontend | React, Vite, STOMP, SockJS | Dashboard, authentication, live updates, reports |
| Backend | Java, Spring Boot, Spring Security, JPA | REST API, business logic, security, persistence |
| Database | PostgreSQL | Users, events, incidents, scans, findings, settings |
| ML service | Python, Flask, NumPy, Pandas, scikit-learn | Anomaly detection and model-backed analysis |
| Malware analysis | YARA and Python model modules | Signature and model-based file analysis |
| Network capture | Pcap4j | Packet capture and traffic inspection |
| Event streaming | Apache Kafka | Optional high-throughput event ingestion |
| Integrations | Nmap, OWASP ZAP, VirusTotal, Cowrie | Vulnerability, web, threat-intelligence, and honeypot data |

## Repository structure

```text
GhostNet/
├── backend/                # Spring Boot API and security platform
├── frontend/               # React/Vite web application
├── Python-ML/              # Flask ML, YARA, malware, and anomaly services
├── Databasescheme.sql      # PostgreSQL schema
├── setup.ps1               # Provision, install, and build the project
├── run-all.ps1             # Provision and start all local services
├── .env                    # Local configuration; keep private
└── .env.local              # Optional alternate local configuration
```

## Requirements

The supported local setup currently targets Windows and requires:

- JDK 25
- Maven
- Node.js and npm
- Python 3.12
- PostgreSQL and the `psql` command-line tool
- Git

Python 3.12 is required for the pinned machine-learning dependencies used by this project. The setup script creates a project-local `.venv` directory and installs the dependencies from [`Python-ML/requirements.txt`](./Python-ML/requirements.txt).

Optional integrations may additionally require:

- Npcap/WinPcap permissions for packet capture
- Apache Kafka
- Nmap installed on the backend host and available on `PATH`; otherwise set `GHOSTNET_NMAP_PATH` to the full path of `nmap.exe`
- OWASP ZAP
- VirusTotal API access
- A controlled honeypot environment such as Cowrie

## Quick start on Windows

1. Clone the repository:

   ```powershell
   git clone <your-repository-url>
   cd GhostNet
   ```

2. Create or update the local environment file. Do not commit passwords, API keys, JWT secrets, or other credentials.

3. Make sure PostgreSQL is running and that the credentials in `.env` can create or access the `ghostnet` database.

4. Run the complete setup and launch script:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\run-all.ps1
   ```

   The launcher:

   - Checks the required tools.
   - Creates the PostgreSQL database when necessary.
   - Applies [`Databasescheme.sql`](./Databasescheme.sql).
   - Creates the Python 3.12 virtual environment.
   - Installs Python and frontend dependencies.
   - Builds the frontend and backend.
   - Starts the Python ML service, Spring Boot backend, and Vite frontend.

5. Open the frontend:

   ```text
   http://localhost:5173
   ```

### Launcher options

Skip database creation and schema application:

```powershell
.\run-all.ps1 -SkipDatabase
```

Skip frontend and backend builds:

```powershell
.\run-all.ps1 -SkipBuild
```

Use both options when dependencies and the database are already prepared:

```powershell
.\run-all.ps1 -SkipDatabase -SkipBuild
```

Service logs are written to the local `logs/` directory:

```text
logs/python-ml.out.log
logs/python-ml.err.log
logs/backend.out.log
logs/backend.err.log
logs/frontend.out.log
logs/frontend.err.log
```

## Service URLs

| Service | URL |
|---|---|
| Frontend | `http://localhost:5173` |
| Backend API | `http://127.0.0.1:8081/api` |
| Backend health | `http://127.0.0.1:8081/api/actuator/health` |
| Python ML health | `http://127.0.0.1:5000/api/health` |
| WebSocket endpoint | `http://127.0.0.1:8081/api/ws` |

The Python ML service protects non-health routes with the `GHOSTNET_ML_API_KEY` value. Configure the same key in the backend and ML service when authenticated ML requests are enabled.

## Manual development commands

### Frontend

```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

Build the production frontend:

```powershell
npm run build
```

### Backend

```powershell
cd backend
mvn spring-boot:run
```

Build and test the backend:

```powershell
mvn clean test
```

### Python ML service

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m pip install -r .\Python-ML\requirements.txt
.\.venv\Scripts\python.exe .\Python-ML\app.py
```

Run the Python tests:

```powershell
.\.venv\Scripts\python.exe -m pytest .\Python-ML\tests
```

## Selected API areas

The backend is mounted below `/api`. Representative API areas include:

- `/api/auth` - login, registration, refresh, logout, and current-user details
- `/api/dashboard` - dashboard metrics and statistics
- `/api/network` - capture controls, traffic, alerts, and IDS rules
- `/api/incidents` - incidents, timelines, notes, and security events
- `/api/malware` - malware scans, uploads, and scan statistics
- `/api/vulnerability` - vulnerability scans, findings, CVE imports, and reports
- `/api/honeypots` - honeypots, interactions, attackers, and statistics
- `/api/ml` - backend access to ML health, anomaly detection, and model retraining
- `/api/operations` - pipeline status, jobs, and operational events
- `/api/reports` - vulnerability reports and synchronization
- `/api/settings` - operational settings

Authentication is handled by JWT tokens. Administrative operations require the appropriate role and should only be exposed in a trusted development or production environment.

## Configuration and security

Configuration is loaded from environment variables and local environment files. Before running the project:

- Replace all development passwords and secrets.
- Use a long, random JWT secret.
- Set a strong PostgreSQL password.
- Configure `GHOSTNET_ML_API_KEY` when the ML service is exposed.
- Restrict `GHOSTNET_SCAN_ROOTS` to controlled directories.
- Do not expose the ML service, database, honeypot, or packet-capture interfaces directly to the public internet.
- Run honeypots only in an isolated, monitored environment.
- Keep `.env`, `.env.local`, model artifacts, uploads, logs, and generated build directories out of source control.

This project is intended for authorized security testing, academic research, and controlled defensive environments. Only scan systems and files for which you have explicit permission.

## Testing status

The project has been validated with:

- Frontend production build
- Frontend test suite
- Backend Maven tests
- Python model and integration tests
- Python syntax checks
- Transactional PostgreSQL schema validation

Before publishing a deployment, run the relevant tests again in the target environment and verify all optional integrations independently.

## Project team and academic credits

### Created by

- **Divya Kumari** — `1JS23IS043`
- **Arnitha P** — `1JS23IS018`
- **Aishwarya Girani** — `1JS23IS008`
- **Arun Prasad** — `1JS23IS019`

### Institution

**Department of Information Science and Engineering**  
JSS Academy of Technical Education  
JSSATE Campus, Dr. Vishnuvardhana Main Road  
Bengaluru – 560060

### Academic project

- **Course:** Final Year Project Work (BIS786)
- **Academic year:** 2025–26
- **Project guide:** Dr. Sreenath M, Associate Professor
- **Project coordinators:** Dr. Sreenatha M, Associate Professor; Dr. Supriya B N, Associate Professor; Mrs. Deepa Konnur, Assistant Professor
- **Head of Department:** Dr. Nagamani N Purohit, Associate Professor

## Research direction

The project is motivated by research into real-time industrial threat detection, embedded AI, distributed cyber-threat intelligence, cloud threat-intelligence integration, web-data mining, anomaly detection, darknet threats, and automated attack-graph construction.

The planned evaluation areas include:

- Detection accuracy
- False-positive rate
- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- Processing latency
- Resource usage under increasing traffic volume

## Contributions

Contributions, bug reports, and suggestions are welcome. Please open an issue with:

1. A concise description of the problem.
2. Reproduction steps.
3. Relevant logs with secrets removed.
4. Environment details such as Windows version, Java, Python, Node.js, and PostgreSQL versions.

For security vulnerabilities, do not publish exploit details in a public issue. Contact the maintainers privately through the repository's configured security-reporting channel.

## License

No license has been declared yet. Until a license is added to this repository, all rights remain with the project authors and JSS Academy of Technical Education. Please request permission before redistributing or reusing the source code.
