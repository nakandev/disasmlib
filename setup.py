#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import codecs
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

def read(*parts):
    with codecs.open(os.path.join(here, *parts), 'r') as fp:
        return fp.read()

def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")

with open('README.rst') as f:
    long_description = f.read()

setup(name='disasmlib',
      version=find_version('disasmlib', '__init__.py'),
      description='Simple ELF & Disassembly code analyzer',
      long_description=long_description,
      author='nakandev',
      author_email='nakandev.s@gmail.com',
      url='https://github.com/nakandev/disasmlib',
      license='MIT',
      install_requires=[],
      platforms='any',
      packages=find_packages(),
      package_data={},
      namespace_packages=['disasmlib'],
      )
