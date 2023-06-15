from setuptools import *

setup(
    name="pycloaking",
    version="1.0",
	entry_points = {
		"console_scripts": [
		    "cloak  = pycloaking.mains:main_cloak",
		    "uncloak = pycloaking.mains:main_uncloak",
		]
	},
    url="https://github.com/texadactyl/Cloaking.py",
    author="Richard Elkins",
    author_email="richard.elkins@gmail.com",
    description="Cloak Sensitive Files",
    long_description=open("README.md").read(),
    packages=find_packages(),
    setup_requires=open("requirements.txt").read(),
    tests_require=open("requirements_test.txt").read(),
)
