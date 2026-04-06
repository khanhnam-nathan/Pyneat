"""Code with redundant expressions."""
def check_flag(flag):
    """Check flag."""
    if flag == True:
        return "yes"
    if flag == False:
        return "no"
    return "unknown"


def check_none(value):
    """Check none."""
    if value is not None:
        return True
    return False


def string_conversion(x):
    """Convert string."""
    return str(str(x))


def list_conversion(items):
    """Convert list."""
    return list([1, 2, 3])


def tuple_conversion(items):
    """Convert tuple."""
    return tuple((1, 2, 3))


def redundant_check(x):
    """Redundant check."""
    if x == True:
        return True
    else:
        return False
