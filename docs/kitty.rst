Kitty Resource file  ~/.config/kitty/kitty.rst
==============================================

KITTY is the best, configurable and fastest terminal in Linux

.. code-block:: shell
  
  font_family      Fira Code Regular
  bold_font        auto
  italic_font      auto
  bold_italic_font auto
  font_size 16.0
  force_ltr no
  adjust_line_height  0
  adjust_column_width 0
  disable_ligatures never
  font_features none
  box_drawing_scale 0.001, 1, 1.5, 2
  cursor_shape block
  cursor_beam_thickness 1.5
  cursor_underline_thickness 2.0
  cursor_blink_interval -1
  cursor_stop_blinking_after 15.0
  scrollback_lines -1
  scrollback_pager less --chop-long-lines --RAW-CONTROL-CHARS +INPUT_LINE_NUMBER
  scrollback_pager_history_size 0
  wheel_scroll_multiplier 5.0
  touch_scroll_multiplier 1.0
  mouse_hide_wait 3.0
  url_color #0087bd
  url_style curly
  open_url_modifiers kitty_mod
  open_url_with default
  url_prefixes http https file ftp
  detect_urls no
  copy_on_select yes
  strip_trailing_spaces never
  rectangle_select_modifiers ctrl+alt
  terminal_select_modifiers shift
  select_by_word_characters @-./_~?&=%+#
  click_interval -1.0
  focus_follows_mouse no
  pointer_shape_when_grabbed arrow
  default_pointer_shape beam
  pointer_shape_when_dragging beam
  repaint_delay 10
  input_delay 3
  sync_to_monitor yes
  enable_audio_bell no
  visual_bell_duration 0.0
  window_alert_on_bell yes
  bell_on_tab yes
  command_on_bell none
  remember_window_size  yes
  initial_window_width  640
  initial_window_height 400
  enabled_layouts *
  window_resize_step_cells 2
  window_resize_step_lines 2
  #window_border_width 0.5pt
  draw_minimal_borders yes
  window_margin_width 0
  single_window_margin_width -1
  window_padding_width 0
  placement_strategy center
  active_border_color #00ff00
  inactive_border_color #cccccc
  bell_border_color #ff5a00
  inactive_text_alpha 1.0
  hide_window_decorations yes
  resize_debounce_time 0.1
  resize_draw_strategy static
  resize_in_steps no
  confirm_os_window_close 0

  tab_bar_style powerline
  # tab_bar_style fade
  tab_bar_background none
  tab_bar_edge top
  tab_bar_margin_width 0.0
  tab_bar_min_tabs 2
  tab_switch_strategy previous
  tab_fade 1
  # tab_separator " ┇"
  tab_powerline_style slanted
  tab_activity_symbol 🔻
  # tab_activity_symbol none
  # tab_title_template "{index}"

  active_tab_title_template none
  active_tab_foreground   #000
  active_tab_background   #eee
  active_tab_font_style   bold-italic

  inactive_tab_foreground #444
  inactive_tab_background #999
  inactive_tab_font_style normal

  background_opacity 1.0
  background_image none
  background_image_layout tiled
  background_image_linear no

  dynamic_background_opacity no
  background_tint 0.0
  dim_opacity 0.1

  # cursor #cccccc
  # cursor #c7c7c7
  cursor #d9e5f1

  # cursor_text_color #111111
  cursor_text_color #feffff

  # foreground #dddddd
  # foreground #c8c8c8
  foreground #d9e5f1

  # background #000000
  # background #323232
  background #0d1925

  # selection_foreground #000000
  # selection_foreground #3e3e3e
  selection_foreground #0d1925

  # selection_background #c1ddff
  # selection_background #fffacd
  selection_background #d9e6f2

  # color0 #000000
  # color8 #767676
  # color1 #cc0403
  # color9 #f2201f
  # color2  #19cb00
  # color10 #23fd00
  # color3  #cecb00
  # color11 #fffd00
  # color4  #0d73cc
  # color12 #1a8fff
  # color5  #cb1ed1
  # color13 #fd28ff
  # color6  #0dcdcd
  # color14 #14ffff
  # color7  #dddddd
  # color15 #ffffff

  # color0     #252525
  # color8     #555555
  # color1     #be7472
  # color9     #ff9900
  # color2     #709772
  # color10    #97bb98
  # color3     #989772
  # color11    #fefdbc
  # color4     #7199bc
  # color12    #9fbdde
  # color5     #727399
  # color13    #989abc
  # color6     #719899
  # color14    #6fbbbc
  # color7     #7f7f7f
  # color15    #feffff

  color0 #000000
  color8 #252525
  color1 #b87979
  color9 #dabdbd
  color2 #79b879
  color10 #bddabd
  color3 #b8b879
  color11 #dadabd
  color4 #7979b8
  color12 #bdbdda
  color5 #b879b8
  color13 #dabdda
  color6 #79b8b8
  color14 #bddada
  color7 #d9d9d9
  color15 #ffffff

  mark1_foreground black
  mark1_background #98d3cb
  mark2_foreground black
  mark2_background #f2dcd3
  mark3_foreground black
  mark3_background #f274bc
  shell .
  editor .
  close_on_child_death no
  allow_remote_control no
  listen_on none
  update_check_interval 0
  startup_session none
  clipboard_control write-clipboard write-primary
  allow_hyperlinks yes
  term xterm-kitty
  macos_titlebar_color system
  macos_option_as_alt no
  macos_hide_from_tasks no
  macos_quit_when_last_window_closed no
  macos_window_resizable yes
  macos_thicken_font 0
  macos_traditional_fullscreen no
  macos_show_window_title_in all
  macos_custom_beam_cursor no
  linux_display_server auto
  kitty_mod ctrl+shift
  clear_all_shortcuts no
  map kitty_mod+c copy_to_clipboard
  map kitty_mod+v  paste_from_clipboard
  map kitty_mod+s  paste_from_selection
  map shift+insert paste_from_selection
  map kitty_mod+o  pass_selection_to_program
  map kitty_mod+up        scroll_line_up
  map kitty_mod+k         scroll_line_up
  map kitty_mod+down      scroll_line_down
  map kitty_mod+j         scroll_line_down
  map shift+page_up   scroll_page_up
  map page_up         scroll_page_up
  map shift+page_down scroll_page_down
  map page_down       scroll_page_down
  map shift+home      scroll_home
  map shift+end       scroll_end
  map kitty_mod+h         show_scrollback
  map kitty_mod+enter new_window
  map kitty_mod+n new_os_window
  map kitty_mod+w close_window
  map kitty_mod+] next_window
  map kitty_mod+[ previous_window
  map kitty_mod+f move_window_forward
  map kitty_mod+b move_window_backward
  map kitty_mod+` move_window_to_top
  map kitty_mod+r start_resizing_window
  map kitty_mod+1 first_window
  map kitty_mod+2 second_window
  map kitty_mod+3 third_window
  map kitty_mod+4 fourth_window
  map kitty_mod+5 fifth_window
  map kitty_mod+6 sixth_window
  map kitty_mod+7 seventh_window
  map kitty_mod+8 eighth_window
  map kitty_mod+9 ninth_window
  map kitty_mod+0 tenth_window
  map shift+right     next_tab
  map shift+left      previous_tab
  map shift+down      new_tab
  map kitty_mod+q     close_tab
  map kitty_mod+.     move_tab_forward
  map kitty_mod+,     move_tab_backward
  map kitty_mod+alt+t set_tab_title
  map kitty_mod+l next_layout
  map ctrl+page_up         change_font_size all +2.0
  map ctrl+page_down       change_font_size all -2.0
  map ctrl+backspace       change_font_size all 0
  map kitty_mod+e kitten hints
  map kitty_mod+p>f kitten hints --type path --program -
  map kitty_mod+p>shift+f kitten hints --type path
  map kitty_mod+p>l kitten hints --type line --program -
  map kitty_mod+p>w kitten hints --type word --program -
  map kitty_mod+p>h kitten hints --type hash --program -
  map kitty_mod+p>n kitten hints --type linenum
  map kitty_mod+p>y kitten hints --type hyperlink
  map kitty_mod+f11    toggle_fullscreen
  map kitty_mod+f10    toggle_maximized
  map kitty_mod+u      kitten unicode_input
  map kitty_mod+f2     edit_config_file
  map kitty_mod+escape kitty_shell window
  map kitty_mod+a>m    set_background_opacity +0.1
  map kitty_mod+a>l    set_background_opacity -0.1
  map kitty_mod+a>1    set_background_opacity 1
  map kitty_mod+a>d    set_background_opacity default
  map kitty_mod+delete clear_terminal reset active


