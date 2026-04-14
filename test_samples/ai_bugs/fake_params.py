"""Sample code for testing fake parameter detection.

This file contains examples of code that should trigger fake parameter warnings.
AI often invents parameter names that don't exist in the actual function signature.
"""

# BAD: Fake parameter names
def call_with_fake_params():
    result = process_data(
        fake_param=True,
        dummy='value',
        mock_data='test'
    )


# BAD: param1, param2 style
def call_with_numbered_params():
    response = api_call(
        param1='username',
        param2='password',
        param3='token'
    )


# BAD: undefined parameters
def process_with_undefined():
    return calculator.compute(
        undefined='value',
        null=None,
        placeholder='data'
    )


# BAD: temp/tmp parameters
def process_with_temp_params():
    return transform(
        temp_value='ignored',
        tmp_data='unused',
        fake='not_real'
    )


# GOOD: Real parameters
def call_with_real_params():
    result = process_data(
        timeout=30,
        retry=True,
        validate=True
    )
