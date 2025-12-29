### Coding Standards

**Style & Structure**
- Prefer longer, explicit code over compact one-liners
- Always include docstrings for functions/classes + inline comments
- Strongly prefer OOP-style code (classes over functional/nested functions)
- Strong typing throughout (dataclasses, TypedDict, Enums, type hints)
- Value future-proofing and expanded usage insights

**Data Design**
- Use dataclasses for internal data modeling
- Typed JSON structures
- Functions return fully typed objects (no loose dicts)
- Snapshot files in JSON or YAML
- Human-readable fields (e.g., `sql_injection`, `xss_attempt`)

**Templates & UI**
- Don't mix large HTML/CSS blocks in Python code
- Prefer Jinja templates for HTML rendering
- Clean CSS, minimal inline clutter, readable template logic

**Writing & Documentation**
- Markdown documentation
- Clear section headers
- Roadmap/Phase/Feature-Session style documents

**Logging**
- Use singleton for logging found in `src\logger.py`
- Setup logging at app start: 
    ```
    initialize_logging()
    app_logger = get_app_logger()
    access_logger = get_access_logger()
    credential_logger = get_credential_logger()
    ```

**Preferred Pip Packages**
- API/Web Server: Simple Python
- HTTP: Requests
- SQLite: Sqlalchemy
- Database Migrations: Alembic

### Error Handling
- Custom exception classes for domain-specific errors
- Consistent error response formats (JSON structure)
- Logging severity levels (ERROR vs WARNING)

### Configuration
- `.env` for secrets (never committed)
- Maintain `.env.example` in each component for documentation
- Typed config loaders using dataclasses
- Validation on startup

### Containerization & Deployment
- Explicit Dockerfiles
- Production-friendly hardening (distroless/slim when meaningful)
- Use git branch as tag

### Dependency Management
- Use `requirements.txt` and virtual environments (`python3 -m venv venv`)
- Use path `venv` for all virtual environments
- Pin versions to version ranges (or exact versions if pinning a particular version)
- Activate venv before running code (unless in Docker)

### Testing Standards
- Manual testing preferred for applications
- **tests:** Use shell scripts with curl/httpie for simulation and attack scripts.
- tests should be located in `tests` directory

### Git Standards

**Branch Strategy:**
- `master` - Production-ready code only
- `beta` - Public pre-release testing
- `dev` - Main development branch, integration point

**Workflow:**
- Feature work branches off `dev` (e.g., `feature/add-scheduler`)
- Merge features back to `dev` for testing
- Promote `dev` → `beta` for public testing (when applicable)
- Promote `beta` (or `dev`) → `master` for production

**Commit Messages:**
- Use conventional commit format: `feat:`, `fix:`, `docs:`, `refactor:`, etc.
- Keep commits atomic and focused
- Write clear, descriptive messages

**Tagging:**
- Tag releases on `master` with semantic versioning (e.g., `v1.2.3`)
- Optionally tag beta releases (e.g., `v1.2.3-beta.1`)