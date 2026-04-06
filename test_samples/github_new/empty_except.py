"""File with empty except blocks."""
import json


def load_config():
    """Load config."""
    try:
        with open('config.json') as f:
            return json.load(f)
    except:
        pass


def process_data(data):
    """Process data."""
    try:
        return int(data)
    except:
        pass


def read_file(path):
    """Read file."""
    try:
        with open(path) as f:
            return f.read()
    except:
        pass


def parse_json(text):
    """Parse JSON."""
    try:
        return json.loads(text)
    except:
        pass


class Config:
    """Config class."""

    def load(self):
        """Load config."""
        try:
            self.data = {'key': 'value'}
        except:
            pass
