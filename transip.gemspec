# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'transip/version'

Gem::Specification.new do |spec|
  spec.name          = 'transip'
  spec.version       = Transip::VERSION
  spec.authors       = ['Joost Hietbrink', 'Richard Bronkhorst', 'Jean Mertz']
  spec.email         = %w(joost@joopp.com jean@mertz.fm)
  spec.description   = 'Ruby gem to use the full TransIP API (v5.0).'
  spec.summary       = 'Ruby gem to use the full TransIP API (v5.0).'
  spec.homepage      = 'http://github.com/joost/transip'
  spec.license       = 'MIT'

  spec.required_ruby_version = '>= 1.9'

  spec.files         = `git ls-files`.split($INPUT_RECORD_SEPARATOR)
  spec.require_paths = ['lib']

  spec.add_dependency 'savon', '~> 2.7.2'

  spec.add_development_dependency 'bundler', '~> 1.3'
  spec.add_development_dependency 'rubocop', '~> 0.26'
end
