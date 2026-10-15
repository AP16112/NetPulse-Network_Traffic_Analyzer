from streamlit.testing.v1 import AppTest
from pathlib import Path


def test_dashboard_demo_filters_and_clear():
    app = AppTest.from_file(Path(__file__).resolve().parents[1] / "app.py", default_timeout=60).run()
    assert not app.exception
    assert app.metric[3].value == "2"
    app.multiselect[0].set_value(["DNS"]).run()
    assert not app.exception
    app.text_input[0].set_value("no-such-host").run()
    assert not app.exception
    next(button for button in app.button if button.label == "Clear session").click().run()
    assert not app.exception
    assert any("Start a capture" in element.value for element in app.info)
