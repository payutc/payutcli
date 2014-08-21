from setuptools import setup


install_requires = [x.strip() for x in open('requirements.txt').readlines() if x.strip() and x[:2] != '-r']

setup(
    name='payutcli',
    version='0.0.1',
    url='http://github.com/payutc/payutcli',
    author='payutc dev\' team',
    author_email='thomas@recouvreux.com',
    description='Simple payutc client enhanced with an interactive shell',
    long_description=open('README.md').read(),
    platforms='all',
    install_requires=install_requires,
    classifiers=[
        'Intended Audience :: Developers',
        'Programming Language :: Python',
    ],
    entry_points={
        'console_scripts': [
            'payutcli = payutcli:main',
        ],
    },
)
