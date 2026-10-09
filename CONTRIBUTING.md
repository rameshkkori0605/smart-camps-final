# Contributing to Smart Campus Solutions (SNPSU)

Thank you for your interest in contributing to the **Sapthagiri NPS University Smart Campus Solutions** platform!

## Code of Conduct
We are committed to providing a friendly, safe, and welcoming environment for all contributors. Please treat all community members with respect.

## Getting Started
1. **Fork the Repository**:
   ```bash
   git clone https://github.com/rameshkkori0605/smart-campus.git
   cd smart-campus
   ```
2. **Install Dependencies**:
   ```bash
   npm install
   ```
3. **Run Automated Test Suite**:
   ```bash
   npm test
   ```
   All 25 unit and integration tests must pass with 0 failures before opening a pull request.

4. **Start Local Development Server**:
   ```bash
   npx serve .
   # or
   python -m http.server 8000
   ```

## Development Guidelines
- **File Size Constraint**: Every file must strictly remain below **10MB** (`10,485,760 bytes`). Large media files must be compressed.
- **Security Standards**:
  - Always sanitize user input using `Security.sanitizeHTML()` and `Security.sanitizeUrl()`.
  - Enforce Role-Based Access Control (RBAC) via `Security.authorize(role, allowedRoles)`.
  - Maintain CSP (Content Security Policy) compliance.
- **Accessibility (WCAG 2.1 AA)**:
  - Ensure all clickable interactive elements have descriptive `aria-label` or visible text labels.
  - Maintain color contrast ratios of at least 4.5:1.
  - Test keyboard navigation across all modals and search bars.

## Pull Request Process
1. Create a feature branch: `git checkout -b feature/your-feature-name`.
2. Commit changes with clear, descriptive commit messages.
3. Verify that `npm test` passes completely (25/25 assertions).
4. Run `powershell -ExecutionPolicy Bypass -File check-size.ps1` to verify file size constraints.
5. Push your branch and open a Pull Request against `main`.
