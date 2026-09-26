"""TTY gets the spinner; piped stderr gets plain status lines."""
import narvy.main as m


class _RecordingConsole:
    def __init__(self):
        self.lines = []

    def print(self, text=""):
        self.lines.append(text)


def test_plain_progress_emits_each_distinct_description_once():
    rec = _RecordingConsole()
    p = m._PlainProgress(rec)
    with p:
        t = p.add_task("[cyan]Running passive Nuclei scan...", total=None)
        p.update(t, advance=1)  # bare advance: no new line
        p.update(t, description="[cyan]Running passive Nuclei scan...")  # dup: no line
        p.update(t, completed=1, description="[green]Scan complete.")
    assert rec.lines == [
        "[cyan]Running passive Nuclei scan...",
        "[green]Scan complete.",
    ]


def test_scan_progress_is_plain_when_not_a_tty(monkeypatch):
    # FORCE_COLOR makes rich's console.is_terminal True even when piped; the real
    # fd check must still route to the plain, non-animated presenter.
    monkeypatch.setattr(m, "_STDERR_IS_TTY", False)
    assert isinstance(m.scan_progress(), m._PlainProgress)


def test_scan_progress_is_rich_on_a_real_tty(monkeypatch):
    from rich.progress import Progress
    monkeypatch.setattr(m, "_STDERR_IS_TTY", True)
    obj = m.scan_progress()
    assert isinstance(obj, Progress)


def test_print_raw_tool_output_is_silent_when_empty():
    rec = _RecordingConsole()
    orig = m.console
    m.console = rec
    try:
        m._print_raw_tool_output("nuclei", "")
        m._print_raw_tool_output("nuclei", None)
        assert rec.lines == []
        m._print_raw_tool_output("nuclei", "boom")
        assert any("raw nuclei output" in ln for ln in rec.lines)
    finally:
        m.console = orig
