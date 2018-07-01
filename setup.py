from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

setup(name="pycloaking",
    version="1.0",
    description="Cloak/Uncloak Sensitive Files",
    long_description=readme(),
    url="https://github.com/texadactyl/pycloaking",
    author="Richard Elkins",
    author_email="richard.elkinsr@gmail.com",
	license="MIT",
    packages=["pycloaking"],
	install_requires=['pycrypto'],
    zip_safe=False)

