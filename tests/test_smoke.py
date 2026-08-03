def test_import():
    """Smoke test pour valider que le module se charge et que les constantes sont là."""
    # L'import à l'intérieur est intentionnel : il valide le chargement dynamique du module.
    import vt_scanner  # pylint: disable=import-outside-toplevel
    assert vt_scanner.BASE_URL == "https://www.virustotal.com/api/v3"
    assert vt_scanner.MAX_FILE_SIZE_BYTES > 0
