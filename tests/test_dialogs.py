"""Dialog markup: pressing Enter in a dialog's field must press its confirm
button. A <form method="dialog"> treats its first submit button as the default
button, so a Cancel button that is a plain submit button and comes before the
confirm button turns Enter into Cancel."""

import html.parser
import os
import unittest

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "web")


class Forms(html.parser.HTMLParser):

    def __init__(self):
        html.parser.HTMLParser.__init__(self)
        self.dialog = None
        self.buttons = {}              # dialog id -> [(type, value)]

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "dialog":
            self.dialog = a.get("id") or "(unnamed)"
            self.buttons[self.dialog] = []
        elif tag == "button" and self.dialog:
            self.buttons[self.dialog].append(
                (a.get("type", "submit"), a.get("value")))

    def handle_endtag(self, tag):
        if tag == "dialog":
            self.dialog = None


def read(name):
    with open(os.path.join(WEB, name), encoding="utf-8") as fh:
        return fh.read()


class DialogDefaults(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        parser = Forms()
        parser.feed(read("index.html"))
        cls.dialogs = parser.buttons

    def test_no_cancel_button_is_a_submit_button(self):
        for dialog, buttons in self.dialogs.items():
            for kind, value in buttons:
                if value == "cancel":
                    self.assertEqual(kind, "button", dialog)

    def test_the_first_submit_button_of_each_dialog_is_not_a_cancel(self):
        for dialog, buttons in self.dialogs.items():
            submits = [v for k, v in buttons if k == "submit"]
            if submits:
                self.assertNotEqual(submits[0], "cancel", dialog)

    def test_the_script_closes_a_dialog_when_its_cancel_is_clicked(self):
        js = read("app.js")
        self.assertIn("button[value=\"cancel\"]", js)
        self.assertIn(".close('cancel')", js)


if __name__ == "__main__":
    unittest.main()
