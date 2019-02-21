from setuptools import setup

setup(
    name='powerio',
    version='1.0.0',

    packages=['powerio'],

    url='https://thepower.io',

    license='MIT',

    author='',
    author_email='',

    description='PowerIO API.',

    classifiers=[
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',

        # Pick your license as you wish
        'License :: OSI Approved :: MIT License',

        # Python versions supported.
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7'
    ],

    # project_urls={
    #     'Sources': '',
    #     'Bug Reports': '',
    # },

    install_requires=['msgpack', 'ecdsa', 'requests'],
)
