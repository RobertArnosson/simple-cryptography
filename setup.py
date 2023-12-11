from setuptools import setup, find_packages

with open('README.md') as readme_file:
    readme = readme_file.read()

setup(
    name="simple-crypto",
    version="0.0.1",
    description="Your goto simple cryptography library",
    url="https://github.com/RobertArnosson/Simple-Crypto",
    author="Robert Arnorsson",
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Build Tools",
        "License :: OSI Approved :: Apache License",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3 :: Only",
    ],
    long_description=readme,
    long_description_content_type="text/markdown",
    keywords = 'simple cryptography symmetric asymmetric hash encrypt decrypt rsa aes sha md5',
    packages=find_packages(),
    install_requires= [
        "cryptography",
        "argon2-cffi",
        "uuid"
    ],
    python_requires=">=3.9",
    project_urls={
        "Documentation": "https://github.com/RobertArnosson/Simple-Crypto/wiki",
        "Bug Reports": "https://github.com/RobertArnosson/Simple-Crypto/issues",
        "Source": "https://github.com/RobertArnosson/Simple-Crypto",
    },
)