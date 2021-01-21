from setuptools import find_packages, setup

# The README.md will be used as the content for the PyPi package details page on the Python Package Index.
with open('README.md', 'r') as readme:
    long_description = readme.read()


setup(
    name='microengine-utils',
    version='1.4.1',
    description='Library for Polyswarm Microengine Utility Package',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='PolySwarm Developers',
    author_email='info@polyswarm.io',
    url='https://github.com/polyswarm/microengine-utils',
    license='MIT',
    python_requires='>=3.6,<4',
    install_requires=[
        'datadog~=0.36.0',
        'polyswarm-artifact~=1.4.2',
        'polyswarm-client',
        'pydantic~=1.6.1',
        'requests~=2.22.0',
    ],
    tests_require=[
        'pytest~=5.4.2',
    ],
    include_package_data=True,
    packages=find_packages('src'),
    package_dir={'': 'src'},
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: Implementation :: PyPy',
    ]
)
