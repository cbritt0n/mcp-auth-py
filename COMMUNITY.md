# Community Guidelines & Contribution Guide

## Welcome to mcp-auth-py Community! 🎉

mcp-auth-py is an open-source authentication framework for FastAPI and ASGI applications. We welcome contributions from developers of all skill levels.

## 🚀 Quick Start for Contributors

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/[your-username]/mcp-auth-py.git
cd mcp-auth-py

# Install with development dependencies
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install

# Run tests to ensure everything works
pytest -v
```

### Project Structure
```
mcp_auth/                    # Core authentication framework
├── providers/               # Authentication providers (Google, AWS, Azure, etc.)
├── rbac/                   # Role-Based Access Control extension
├── tests/                  # Test suite and development utilities
├── middleware.py           # FastAPI/ASGI middleware
├── models.py              # Data models and schemas
├── caching.py             # Redis-based caching system
├── audit.py               # Audit logging and analytics
├── realtime.py            # WebSocket real-time features
└── settings.py            # Configuration management

examples/                   # Real-world usage examples
docs/                      # Comprehensive documentation
tests/                     # Test suite with 97+ tests
```

## 🤝 How to Contribute

### Types of Contributions
- **🐛 Bug Reports**: Found an issue? Help us improve!
- **✨ Feature Requests**: Ideas for new features or improvements
- **📖 Documentation**: Improve guides, examples, or API docs
- **🔧 Code Contributions**: Bug fixes, new features, or optimizations
- **🧪 Testing**: Add tests or improve test coverage
- **🎨 Examples**: Share real-world usage patterns

### Contribution Workflow
1. **Open an Issue**: Discuss your idea or bug report
2. **Fork & Branch**: Create a feature branch from `main`
3. **Implement**: Write code with tests and documentation
4. **Test**: Ensure all tests pass (`pytest -v`)
5. **Submit PR**: Open a pull request with clear description

### Code Standards
- **Code Style**: We use `black`, `isort`, and `ruff` for formatting
- **Type Hints**: Add type annotations for better code quality
- **Tests**: Write tests for new features (aim for >90% coverage)
- **Documentation**: Update docs for API changes
- **Commit Messages**: Use clear, descriptive commit messages

### Testing Guidelines
```bash
# Run all tests
pytest -v

# Run specific test categories
pytest -m "unit"           # Unit tests only
pytest -m "integration"    # Integration tests
pytest -m "redis"          # Redis-dependent tests
pytest -m "rbac"           # RBAC functionality tests

# Run with coverage
pytest --cov=mcp_auth --cov-report=html
```

## 🎯 Current Focus Areas

### High Priority
- **Provider Ecosystem**: New OAuth2 providers (GitHub, Discord, etc.)
- **Enterprise Features**: Multi-tenancy, advanced RBAC
- **Performance**: Optimization and benchmarking
- **Documentation**: More examples and guides

### Medium Priority
- **Compliance**: GDPR, HIPAA, SOX compliance features
- **Monitoring**: Metrics and observability integration
- **Security**: Advanced threat detection
- **Developer Experience**: CLI tools and debugging

### Community Requests
See our [GitHub Issues](https://github.com/cbritt0n/mcp-auth-py/issues) for current community requests and discussions.

## 🏆 Recognition

### Contributors
We recognize all contributors in our README and release notes. Major contributors may be invited to join the maintainer team.

### Contributor Benefits
- **Early Access**: Preview upcoming features
- **Direct Impact**: Shape the future of the project
- **Learning**: Work with modern Python, FastAPI, and security
- **Networking**: Connect with the authentication community

## 📞 Getting Help

### Community Channels
- **GitHub Discussions**: [Ask questions and share ideas](https://github.com/cbritt0n/mcp-auth-py/discussions)
- **Issues**: [Report bugs and request features](https://github.com/cbritt0n/mcp-auth-py/issues)
- **Email**: For security issues, contact the maintainers privately

### Documentation Resources
- **[README.md](README.md)**: Overview and quick start
- **[docs/](docs/)**: Comprehensive guides
- **[examples/](examples/)**: Real-world usage patterns
- **[API Reference](https://github.com/cbritt0n/mcp-auth-py/wiki)**: Detailed API documentation

## 🎪 Community Events

### Monthly Virtual Meetups
- **Demo Day**: Show off projects using mcp-auth-py
- **Technical Deep Dives**: Advanced features and patterns
- **Q&A Sessions**: Get help from maintainers and experts

### Conference Presence
- **PyCon**: We present at Python conferences
- **Security Conferences**: Auth and security best practices
- **FastAPI Events**: Framework-specific talks

## 🛡️ Security

### Reporting Security Issues
Please **do not** report security vulnerabilities publicly. Instead:
1. Email maintainers directly with details
2. Use GitHub Security Advisories for coordination
3. Allow reasonable time for fixes before disclosure

### Security Best Practices
- Regular dependency updates
- Automated security scanning (Bandit, GitHub Security)
- Comprehensive test coverage for security features
- Following OWASP authentication guidelines

## 📜 Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors, regardless of background, identity, or experience level.

### Our Standards
- **Be Respectful**: Treat others with kindness and respect
- **Be Inclusive**: Welcome diverse perspectives and experiences
- **Be Collaborative**: Work together towards common goals
- **Be Professional**: Maintain professional communication
- **Be Patient**: Help others learn and grow

### Enforcement
Community guidelines are enforced by project maintainers. Violations may result in temporary or permanent exclusion from community spaces.

---

**Ready to contribute?** Start by exploring our [Issues](https://github.com/cbritt0n/mcp-auth-py/issues) or join the conversation in [Discussions](https://github.com/cbritt0n/mcp-auth-py/discussions)!

*This community guide is living document. Suggest improvements via pull request.*
