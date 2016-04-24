from distutils.core import setup

setup(
    name='dispatch',
    version='0.9',
    author='NYU OSIRIS Lab',
    url='https://github.com/isislab/dispatch',
    description='Programmatic disassembly and patching from NYU\'s OSIRIS lab',
    packages=['dispatch', 'dispatch.util', 'dispatch.formats', 'dispatch.analysis'],
    install_requires=[
        'pyelftools==0.23',
        'pefile==1.2.10.post114',
        'capstone>3.0',
        'macholib'
    ]
)