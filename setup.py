from setuptools import setup

setup(
    name='webotron-80',
    version='0.1',
    author='gruums',
    author_email='xuerong@gmail.com',
    description='Webotron 80 is a tool to deploy static websites to AWS.',
    license='GPLv3+',
    packages=['webotron'],
    url='https://https://github.com/gruums/python-script-aws',
    install_requires=[
        'click',
        'boto3'
    ],
    entry_points='''
        [console_scripts]
        webotron=webotron.webotron:cli
    '''
)