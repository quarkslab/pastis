# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.

import os
import sys
import datetime
import sphinx_fontawesome

sys.path.insert(0, os.path.abspath('../libpastis'))

# -- Project information -----------------------------------------------------

project = 'PASTIS'
copyright = '2023, Quarkslab'
author = 'Quarkslab'

# The full version, including alpha/beta/rc tags
release = '0.2'


# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
language = 'en'

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'monokai'  # also monokai, friendly, colorful


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.todo',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    'sphinx.ext.githubpages',
    'sphinx_fontawesome',
    "nbsphinx",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store', '**.ipynb_checkpoints']


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "sphinx_rtd_theme"

html_theme_options = {
    # If False, expand all TOC entries
    'globaltoc_collapse': False,
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['figs']

autodoc_default_flags = ['members', 'inherited-members']

# For internationalization
locale_dirs = ['locale/']   # path is example but recommended.
gettext_compact = False     # optional.



autoclass_content = "both"  # Comment class with both class docstring and __init__ docstring

autodoc_typehints = "signature"

autodoc_type_aliases = {

}

intersphinx_mapping = {'python': ('https://docs.python.org/3', None),
                       'lief': ('https://lief-project.github.io/doc/latest/', None)}
