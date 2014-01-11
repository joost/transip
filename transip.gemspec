# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'transip/version'

Gem::Specification.new do |spec|
  spec.name          = %q{transip}
  spec.version       = Transip::VERSION
  spec.authors       = ["Joost Hietbrink", "Richard Bronkhorst"]
  spec.email         = ["joost@joopp.com"]
  spec.description   = %q{Ruby gem to use the full TransIP API (v5.0).}
  spec.summary       = %q{Ruby gem to use the full TransIP API (v5.0).}
  spec.homepage      = %q{http://github.com/joost/transip}
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.require_paths = ["lib"]

  spec.add_dependency('savon', '>= 2.3.0')
  spec.add_dependency('curb', '>= 0.8.4')
  spec.add_dependency('facets', '>= 2.9.3')

  spec.extra_rdoc_files = [
    "MIT-LICENSE",
    "README.rdoc"
  ]
  spec.has_rdoc       = true
  spec.rdoc_options   = ["--charset=UTF-8"]
end
