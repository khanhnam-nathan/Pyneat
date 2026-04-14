"""Sample code for testing phantom package detection.

This file contains examples of code that should trigger phantom package warnings.
AI often hallucinates package names that don't exist on PyPI.
"""

# BAD: Suspiciously short package names
import foo
import bar
import util


# BAD: Generic AI-style package names
import ai_package
import ml_module
from dl_library import model
from nn_framework import network


# BAD: Fake custom packages
import my_custom_api
import custom_utils
from fake_helper import helper_function
from mock_module import something


# GOOD: Real packages
import requests
import json
from typing import List, Dict
