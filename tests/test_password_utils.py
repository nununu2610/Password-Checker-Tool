from password_checker.password_utils import calculate_entropy, password_strength

def test_entropy():
    assert calculate_entropy("abc") > 0
    assert calculate_entropy("ABC123!") > calculate_entropy("abc")

def test_strength_keys():
    result = password_strength("StrongPass123!")
    assert "length" in result
    assert "entropy" in result
    assert "time_to_crack" in result
    assert "pwned" in result
