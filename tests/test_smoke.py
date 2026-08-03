def test_import():
    """Smoke test pour valider que le module se charge et que les constantes sont là."""
    import vt_scanner
    assert vt_scanner.BASE_URL == "https://www.virustotal.com/api/v3"
    assert vt_scanner.MAX_FILE_SIZE_BYTES > 0
