from setuptools import setup, find_packages

setup(
    name="itl",
    version="0.1",
    description="A utility for patching binaries to use different linkers.",
    url="https://github.com/guyinatuxedo/itl",
    author="guyinatuxedo",
    packages=["itl"],
    entry_points = {
            'console_scripts': [
                    'itl = itl.itl:main'
                ]
        }
)
