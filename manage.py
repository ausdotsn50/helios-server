#!/usr/bin/env python
import os
import sys

"""
My understanding:
manage.py asks to execute from command line
"shell" --> Django built-in shell --> starts a Python interpreter with the Django app already fully loaded (settings, DB connection, all installed apps' models importable).
Then, within shell you execute python/any command you want

Note: Usage of Django ORM here for helios models
"""
if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
