# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{transip}
  s.version = "0.2.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Joost Hietbrink"]
  s.date = %q{2011-03-13}
  s.description = s.summary = %q{Ruby gem to use the full TransIP API (v2).}
  s.add_dependency('savon', '>= 0.9.1')
  s.add_dependency('curb', '>= 0.7.15')
  s.email = %q{joost@joopp.com}
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
     "init.rb",
     "lib/transip.rb"
  ]
  s.homepage = %q{http://github.com/joost/transip-api}
  s.has_rdoc = true
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
end