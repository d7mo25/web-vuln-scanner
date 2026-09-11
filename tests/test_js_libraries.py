import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.js_libraries import VERSION_PATTERN, _parse_version


def test_version_pattern_matches_common_cdn_paths():
    assert VERSION_PATTERN.search("jquery-3.4.1.min.js")
    assert VERSION_PATTERN.search("cdn.jsdelivr.net/lodash/4.17.15/lodash.min.js")


def test_version_pattern_no_match_without_version():
    assert VERSION_PATTERN.search("main.js") is None


def test_parse_version_tuple_comparison():
    v1 = _parse_version("3", "4", "1")
    v2 = _parse_version("3", "5", "0")
    assert v1 < v2
