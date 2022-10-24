Bash Resource file  ~/.bashrc
=============================

Setting a customized prompt and terminal options

.. code-block:: shell

  # ~/.bashrc

  # If not running interactively, don't do anything
  [[ $- != *i* ]] && return


  # Distributions where git-prompt.sh exist : SLES
  [ -f /etc/bash_completion.d/git-prompt.sh ] && . /etc/bash_completion.d/git-prompt.sh

  # Distributions where git-prompt.sh exist : RHEL
  [ -f /usr/share/git-core/contrib/completion/git-prompt.sh ] && . /usr/share/git-core/contrib/completion/git-prompt.sh

  __stat() {
    if [ $? -eq 0 ]; then
        echo -en "\033[0;32m✔ \e[m"
    else
        echo -en "\033[0;31m✘ \e[m"
    fi
  }

  # set prompt
  # return code from previous command - time - hostname - (history_id) - current path
  # export PS1='$(__stat)$(__git_branch)\[\e[0;34m\]\t $(hostname -s) (\[\e[0;34m\]\!) \[\e[0;33m\]$(pwd) :\[\e[0;37m\] \$ \[\e[0;20m\]'
  
  export PS1='$(__stat)\[\e[0;33m\][\!]\[\e[38;5;186m\]$(__git_ps1 "[%s]")\[\e[38;5;141m\][\t]\[\e[38;5;81m\][\u\[\e[38;5;141m\]@\[\e[38;5;154m\]$(hostname -s)]\[\e[38;5;141m\]:\[\e[38;5;197m\]$(pwd)\[\e[0m\] \$ '

  # Various BASH options
  shopt -s autocd
  shopt -s direxpand
  shopt -s histverify

  # continue with the general profile settings file
  [ -f ~/.profile ] && . ~/.profile
