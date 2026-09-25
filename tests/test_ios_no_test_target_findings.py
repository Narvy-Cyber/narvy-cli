"""iOS source mode skips XCTest / Swift Testing files."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from narvy.ios import source_analyzer


def test_test_target_dir_suffix_is_skipped():
    """Directory names ending in Tests/UITests must be skipped, however prefixed."""
    assert source_analyzer._is_extra_skip_path("Modules/Tests/SampleProcessorsTests/Foo.swift")
    assert source_analyzer._is_extra_skip_path("MyAppTests/LoginTests.swift")
    assert source_analyzer._is_extra_skip_path("MyAppUITests/LaunchTests.swift")
    assert source_analyzer._is_extra_skip_path("Tests/Fixtures/canned.swift")


def test_real_app_dirs_not_skipped():
    """Must not over-match: real app-code directories must still scan."""
    assert not source_analyzer._is_extra_skip_path("Sources/NetworkKit/Networking.swift")
    assert not source_analyzer._is_extra_skip_path("App/Login/LoginViewController.swift")
    # "...Testing" is a different word from "...Tests".
    assert not source_analyzer._is_extra_skip_path("App/ABTesting/Experiment.swift")


def test_collect_source_files_excludes_test_target(tmp_path=None):
    """A synthetic repo: only the app file comes back, not the test-target one."""
    with tempfile.TemporaryDirectory() as d:
        app_dir = os.path.join(d, "App")
        test_dir = os.path.join(d, "MyAppTests")
        os.makedirs(app_dir)
        os.makedirs(test_dir)
        with open(os.path.join(app_dir, "Networking.swift"), "w") as f:
            f.write("class Networking {}\n")
        with open(os.path.join(test_dir, "NetworkingTests.swift"), "w") as f:
            f.write("class NetworkingTests {}\n")

        swift_files, objc_files, skipped = source_analyzer._collect_source_files(d)
        basenames = {os.path.basename(p) for p in swift_files}
        assert "Networking.swift" in basenames
        assert "NetworkingTests.swift" not in basenames
        assert skipped >= 1


if __name__ == "__main__":
    test_test_target_dir_suffix_is_skipped()
    test_real_app_dirs_not_skipped()
    test_collect_source_files_excludes_test_target()
    print("PASS: iOS source scan correctly skips XCTest/UITests target directories")
