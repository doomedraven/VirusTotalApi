from setuptools import setup, find_packages

setup(
    name='vt',
    version='2.0.9.1',
    description='VirusTotal Full API',
    license='For fun :)',
    packages=find_packages(),
    url='https://github.com/doomedraven/VirusTotalApi',
    author='Andriy Brukhovetskyy - doomedraven',
    author_email='Twitter -> @D00m3dR4v3n',
    entry_points={
        'console_scripts': [
            'vt = vt.__main__:main',
        ],
    },
    install_requires=[
        "requests >= 2.5.0",
        "texttable >= 0.8.1",
        "python-dateutil >= 1.5"
    ],
)
