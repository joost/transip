# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'transip/version'

Gem::Specification.new do |s|
  s.name = %q{transip}
  s.version = Transip::VERSION

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Joost Hietbrink", "Richard Bronkhorst"]
  s.date = %q{2013-09-10}
  s.description = s.summary = %q{Ruby gem to use the full TransIP API (v4.2).}
  s.add_dependency('savon', '>= 2.3.0')
  s.add_dependency('curb', '>= 0.8.4')
  s.add_dependency('facets', '>= 2.9.3')

  s.extra_rdoc_files = [
    "MIT-LICENSE",
    "README.rdoc"
  ]
  s.files = [
     "MIT-LICENSE",
     "README.rdoc",
     "VERSION.yml",
     "Gemfile",
     "Gemfile.lock",
     "lib/transip.rb"
  ]
  s.homepage = %q{http://github.com/joost/transip}
  s.has_rdoc = true
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
end
