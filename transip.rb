require "rubygems"
require "bundler/setup"

require 'savon'
require 'curb'
require 'digest/md5'
#
# Implements the www.transip.nl API (v2). For more info see: https://www.transip.nl/g/api/
#
# Usage:
#  transip = Transip.new('username', '12.34.12.3') # will use readonly mode
#  transip = Transip.new('username', '12.34.12.3', :readwrite) # use this in production
#  transip.generate_hash('your_api_password') # Use this to generate a authentication hash
#  transip.hash = 'your_hash' # Or use this to directly set the hash (so you don't have to use your password in your code)
#  transip.actions # => [:check_availability, :get_whois, :get_domain_names, :get_info, :get_auth_code, :get_is_locked, :register, :cancel, :transfer_with_owner_change, :transfer_without_owner_change, :set_nameservers, :set_lock, :unset_lock, :set_dns_entries, :set_owner, :set_contacts]
#  transip.request(:get_domain_names)
#  transip.request(:get_info, :domain_name => 'yelloyello.be')
#
# Credits:
#  Savon Gem - See: http://savonrb.com/. Wouldn't be so simple without it!
class Transip

  WSDL = 'https://api.transip.nl/wsdl/?service=DomainService'

  attr_accessor :login, :ip, :mode, :hash
  attr_reader :response

  # Example:
  #  transip = Transip.new('username', '12.34.12.3') # will use readonly mode
  #  transip = Transip.new('username', '12.34.12.3', 'readwrite') # use this in production
  def initialize(login, ip, mode = :readonly)
    @login = login
    @ip = ip
    @mode = mode
  end

  # Generates the needed authentication hash.
  # 
  # NOTE: The password is NOT your general TransIP password
  # but one specially for the API. Configure it in the Control
  # Panel.
  def generate_hash(password)
    digest_string = "#{login}:#{password}@#{ip}"
    digest = Digest::MD5.hexdigest(digest_string)
    @hash = digest
  end

  # Used as authentication
  def cookie
    raise StandardError, "Don't have an authentication hash yet. Please set a hash using generate_hash('your_api_password') or hash= method." if hash.blank?
    "login=#{login}; hash=#{hash}; mode=#{mode}; "
  end

  # Same as client method but initializes a brand new fresh client.
  # You have to use this one when you want to re-set the mode (readwrite, readonly),
  # or authentication details of your client.
  def client!
    @client = Savon::Client.new do
      wsdl.document = WSDL
    end
    @client.http.headers["Cookie"] = cookie
    return @client
  end

  # Returns a Savon::Client object to be used in the connection.
  # This object is re-used and cached as @client.
  def client
    @client ||= client!
  end

  # Returns Array with all possible SOAP WSDL actions.
  def actions
    client.wsdl.soap_actions
  end

  # Returns the response.to_hash (raw Savon::SOAP::Response is also stored in @response).
  # Examples:
  #  hash_response = transip.request(:get_domain_names)
  #  hash_response[:get_domain_names_response][:return][:item] # => ["your.domain", "names.list"]
  # For more info see the Transip API docs.
  # Be sure to rescue all the errors.. since it is hardcore error throwing.
  def request(action, options = nil)
    if options.nil?
      @response = client.request(action)
    elsif options.is_a?(Hash)
      @response = client.request(action) do 
        soap.body = options
      end
    else
      raise ArgumentError, "Expected options to be nil or a Hash!"
    end
    @response.to_hash
  end

end