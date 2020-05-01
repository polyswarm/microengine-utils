from setuptools import find_packages, setup


def parse_requirements():
    with open('requirements.txt', 'r') as f:
        return f.read().splitlines()


setup(
    name='microengineutils',
    version='1.0.0',
    description='Library for Polyswarm Microengine Utility Package',
    author='PolySwarm Developers',
    author_email='info@polyswarm.io',
    url='https://github.com/polyswarm/microengine-utils',
    license='MIT',
    install_requires=parse_requirements(),
    include_package_data=True,
    packages=['microengineutils'],
    package_dir={
          'microengineutils': 'src/microengineutils',
    }
)
