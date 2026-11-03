# Used by the GitHub Actions build (.github/workflows/pages.yml) and for local previews:
#   bundle install && bundle exec jekyll serve --livereload
source "https://rubygems.org"

gem "jekyll", "~> 4.3"
gem "jekyll-remote-theme", "~> 0.4"
gem "jekyll-feed", "~> 0.17"
gem "jekyll-seo-tag", "~> 2.8"
gem "jekyll-sitemap", "~> 1.4"
gem "jekyll-include-cache", "~> 0.2"
gem "webrick", "~> 1.8"

# Windows and JRuby do not include zoneinfo files
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end
