#!/usr/bin/python3 -u

# python example that prints something using cowsay and then drops into a python console.
# config:
# :python:python_example:srv.py:120:/challenge:list:nosuid:nocopy:

# note that you will need to install the necessary dependencies for this example to work.
# (see example Dockerfile)

import cowsay
cowsay.milk("Hello, this is a python example challenge.\nNow dropping into python console ...")

import code
code.interact(local=locals())
