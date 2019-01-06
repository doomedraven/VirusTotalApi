from setuptools import setup, find_packages

setup(
    name='vt',
    version='3.1.3.7',
    description='VirusTotal Full API',
    license='For fun :)',
    packages=find_packages(),
    url='https://github.com/doomedraven/VirusTotalApi',
    author='Andriy Brukhovetskyy - doomedraven',
    #author_email='Twitter -> @D00m3dR4v3n',
    entry_points={
        'console_scripts': [
            'vt = vt.__main__:main',
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Natural Language :: English",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Security",
    ],
    keywords=(
        "virustotal vt automated malware analysis threat "
        "intelligence cert soc"
    ),
    #long_description=open("README.md", "rb").read(),
    install_requires=[
        "requests >= 2.5.0",
        "python-dateutil >= 1.5",
        "olefile >= 0.42",
        "texttable",
        "HTMLParser",
        "six",
    ],
)
