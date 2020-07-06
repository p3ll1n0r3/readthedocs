Bash Resource file  ~/.bashrc
=============================

Setting a customized prompt and terminal options

.. code-block:: shell

  # ~/.bashrc

  __git_branch() {
    _GITSTATUS=$(git symbolic-ref HEAD --short 2>/dev/null | sed 's/\(.*\)/(&)/')
    echo $_GITSTATUS
  }

  function __stat() {
    if [ $? -eq 0 ]; then
        echo -en "\033[0;32m✔ $Color_Off "
    else
        echo -en "\033[0;31m✘ $Color_Off "
    fi
  }


  # If not running interactively, don't do anything
  [[ $- != *i* ]] && return

  # set prompt
  # return code from previous command - time - history_id - current path
  export PS1='$(__stat)$(__git_branch)\[\e[0;34m\]\t \[\e[0;10m\][\[\e[0;31m\]\!:\[\e[0;34m\]$(pwd)\[\e[0;10m\]]\[\e[0;37m\] \$ \[\e[0;20m\]'

  # Various BASH options
  shopt -s autocd
  shopt -s direxpand
  shopt -s histverify

  # continue with the general profile settings file
  [ -f ~/.profile ] && . ~/.profile
