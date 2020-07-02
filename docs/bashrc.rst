Bash Resource file  ~/.bashrc
=============================

Setting a customized prompt and terminal options

.. code-blocks:: shell

  # ~/.bashrc

  # If not running interactively, don't do anything
  [[ $- != *i* ]] && return

  # git simple branch prompt
  export PS1='$(__git_branch)\[\e[0;34m\]\t \[\e[0;10m\][\[\e[0;31m\]\!:\[\e[0;34m\]$(pwd)\[\e[0;10m\]]\[\e[0;37m\] \$ \[\e[0;20m\]'

  # Various BASH options
  shopt -s autocd
  shopt -s direxpand
  shopt -s histverify

  # continue with the general profile settings file
  [ -f ~/.profile ] && . ~/.profile
