from setuptools import *

setup(
    name="pycloaking",
    version="1.0",
    url="https://github.com/texadactyl/pycloaking",
    author="Richard Elkins",
    author_email="richard.elkinsr@gmail.com",
    description="Cloak/Uncloak Sensitive Files",
    long_description=open("README.md").read(),
    packages=find_packages(),
    setup_requires=["pytest-runner"],
    tests_require=["pytest"],
	install_requires=["pycrypto"],
)
