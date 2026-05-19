def test_package_imports():
    import security_scanner  # noqa: F401
    import security_scanner.agent  # noqa: F401
    import security_scanner.observability  # noqa: F401
    import security_scanner.shared  # noqa: F401
    import security_scanner.skill  # noqa: F401
