"""File with dead code."""
import os


def used_function():
    """This is used."""
    return "used"


def unused_helper():
    """This is never called."""
    return "unused"


def another_unused():
    """Also never called."""
    return "also unused"


class UsedClass:
    """This class is used."""

    def method(self):
        return "used"


class UnusedClass:
    """This class is never used."""

    def method(self):
        return "unused"


class AnotherUnused:
    """Also never used."""

    def method(self):
        return "unused"


def main():
    """Main function."""
    obj = UsedClass()
    print(obj.method())
    print(used_function())


if __name__ == "__main__":
    main()
