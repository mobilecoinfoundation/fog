# Set GEM_HOME so bundler doesn't install gems in a system directory
if which ruby >/dev/null && which gem >/dev/null; then
    export GEM_HOME="$(ruby -r rubygems -e "puts Gem.user_dir")"
    PATH="$GEM_HOME/bin:$PATH"
fi
