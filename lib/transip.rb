require "rubygems"
require "bundler/setup"

require 'savon'
require 'curb'
require 'digest/md5'
#
# Implements the www.transip.nl API (v2). For more info see: https://www.transip.nl/g/api/
#
# Usage:
#  transip = Transip.new(:username => 'api_username') # will try to determine IP (will not work behind NAT) and uses readonly mode
#  transip = Transip.new(:username => 'api_username', :ip => '12.34.12.3', :mode => 'readwrite') # use this in production
#  transip.actions # => [:check_availability, :get_whois, :get_domain_names, :get_info, :get_auth_code, :get_is_locked, :register, :cancel, :transfer_with_owner_change, :transfer_without_owner_change, :set_nameservers, :set_lock, :unset_lock, :set_dns_entries, :set_owner, :set_contacts]
#  transip.request(:get_domain_names)
#  transip.request(:get_info, :domain_name => 'yelloyello.be')
#  transip.request_with_ip4_fix(:check_availability, :domain_name => 'yelloyello.be')
#  transip.request_with_ip4_fix(:get_info, :domain_name => 'one_of_your_domains.com')
#  transip.request(:get_whois, :domain_name => 'google.com')
#  transip.request(:set_dns_entries, :domain_name => 'bdgg.nl', :dns_entries => [Transip::DnsEntry.new('test', 5.minutes, 'A', '74.125.77.147')])
#  transip.request(:register, Transip::Domain.new('newdomain.com', nil, nil, [Transip::DnsEntry.new('test', 5.minutes, 'A', '74.125.77.147')]))
#
# Some other methods:
#  transip.generate_hash # Use this to generate a authentication hash
#  transip.hash = 'your_hash' # Or use this to directly set the hash (so you don't have to use your password in your code)
#  transip.client! # This returns a new Savon::Client. It is cached in transip.client so when you update your username, password or hash call this method!
#
# Credits:
#  Savon Gem - See: http://savonrb.com/. Wouldn't be so simple without it!
class Transip

  WSDL = 'https://api.transip.nl/wsdl/?service=DomainService'

  attr_accessor :username, :password, :ip, :mode, :hash
  attr_reader :response

  # Following Error needs to be catched in your code!
  class ApiError < RuntimeError

    IP4_REGEXP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

    # Returns true if we have a authentication error and gets ip from error msg.
    # "Wrong API credentials (bad hash); called from IP 213.86.41.114"
    def ip4_authentication_error?
      self.message.to_s =~ /called from IP\s(#{IP4_REGEXP})/ # "Wrong API credentials (bad hash); called from IP 213.86.41.114"
      @error_msg_ip = $1
      !@error_msg_ip.nil?
    end

    # Returns the ip coming from the error msg.
    def error_msg_ip
      @error_msg_ip || ip4_authentication_error? && @error_msg_ip
    end

  end

  # Following subclasses are actually not needed (as you can also
  # do the same by just creating hashes..).

  class TransipStruct < Struct

    # See Rails' underscore method.
    def underscore(string)
      string.gsub(/([A-Z]+)([A-Z][a-z])/,'\1_\2').
        gsub(/([a-z\d])([A-Z])/,'\1_\2').
        tr("-", "_").
        downcase
    end

    # Converts Transip::DnsEntry into :dns_entry
    def class_name_to_sym
      self.underscore(self.class.name.split('::').last).to_sym
    end

    # Gyoku.xml (see: https://github.com/rubiii/gyoku) is used by Savon.
    # It calls to_s on unknown Objects. We use it to convert 
    def to_s
      Gyoku.xml(self.to_hash)
    end

    # See what happens here: http://snippets.dzone.com/posts/show/302
    def members_to_hash
      Hash[*members.collect {|m| [m, self.send(m)]}.flatten]
    end

    def to_hash
      { self.class_name_to_sym => self.members_to_hash }
    end

  end

  # name - String (Eg. '@' or 'www')
  # expire - Integer (1.day)
  # type - String (Eg. A, AAAA, CNAME, MX, NS, TXT, SRV)
  # content - String (Eg. '10 mail', '127.0.0.1' or 'www')
  class DnsEntry < TransipStruct.new(:name, :expire, :type, :content)
  end

  # hostname - string
  # ipv4 - string
  # ipv6 - string (optional)
  class Nameserver < TransipStruct.new(:name, :ipv4, :ipv6)
  end

  # type - string
  # first_name - string
  # middle_name - string
  # last_name - string
  # company_name - string
  # company_kvk - string
  # company_type - string ('BV', 'BVI/O', 'COOP', 'CV'..) (see WhoisContact.php)
  # street - string
  # number - string (streetnumber)
  # postal_code - string
  # city - string
  # phone_number - string
  # fax_number - string
  # email - string
  # country - string (one of the ISO country abbrevs, must be lowercase) ('nl', 'de', ) (see WhoisContact.php)
  class WhoisContact < TransipStruct.new(:type, :first_name, :middle_name, :last_name, :company_name, :company_kvk, :company_type, :street, :number, :postal_code, :city, :phone_number, :fax_number, :email, :country)
  end

  # company_name - string
  # support_email - string
  # company_url - string
  # terms_of_usage_url - string
  # banner_line1 - string
  # banner_line2 - string
  # banner_line3 - string
  class DomainBranding < TransipStruct.new(:company_name, :support_email, :company_url, :terms_of_usage_url, :banner_line1, :banner_line2, :banner_line3)
  end

  # name - String
  # nameservers - Array of Transip::Nameserver
  # contacts - Array of Transip::WhoisContact
  # dns_entries - Array of Transip::DnsEntry
  # branding - Transip::DomainBranding
  class Domain < TransipStruct.new(:name, :nameservers, :contacts, :dns_entries, :branding)
  end

  # Options:
  # * username 
  # * ip
  # * password
  # * mode
  #
  # Example:
  #  transip = Transip.new(:username => 'api_username') # will try to determine IP (will not work behind NAT) and uses readonly mode
  #  transip = Transip.new(:username => 'api_username', :ip => '12.34.12.3', :mode => 'readwrite') # use this in production
  def initialize(options = {})
    @username = options[:username]
    raise ArgumentError, "The :username options is required!" if @username.nil?
    @ip = options[:ip] || self.class.local_ip
    @mode = options[:mode] || :readonly
    if options[:password]
      @password = options[:password]
      self.generate_hash
    end

    # By default we don't want to debug!
    self.turn_off_debugging!
  end

  # By default we don't want to debug!
  # Changing might impact other Savon usages.
  def turn_off_debugging!
    Savon.configure do |config|
      config.log = false            # disable logging
      config.log_level = :info      # changing the log level
    end
  end

  # Make Savon log. 
  # Changing might impact other Savon usages.
  def turn_on_debugging!
    Savon.configure do |config|
      config.log = true
      config.log_level = :debug
    end
  end

  # Make Savon log to Rails.logger and turn_off_debugging!
  def use_with_rails!
    Savon.configure do |config|
      if Rails.env.production?
        self.turn_off_debugging!
      # else
      #   self.turn_on_debugging!
      end
      config.logger = Rails.logger  # using the Rails logger
    end
  end

  # Generates the needed authentication hash.
  # 
  # NOTE: The password is NOT your general TransIP password
  # but one specially for the API. Configure it in the Control
  # Panel.
  def generate_hash
    raise StandardError, "Need username and password to (re)generate the authentication hash." if self.username.nil? || self.password.nil?
    digest_string = "#{self.username}:#{self.password}@#{self.ip}"
    digest = Digest::MD5.hexdigest(digest_string)
    self.hash = digest
  end

  # Used as authentication
  def cookie
    raise StandardError, "Don't have an authentication hash yet. Please set a hash using generate_hash or hash= method." if hash.blank?
    "login=#{self.username}; hash=#{self.hash}; mode=#{self.mode}; "
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
    elsif options.class < Transip::TransipStruct
      # If we call request(:register, Transip::Domain.new('newdomain.com')) we turn the Transip::Domain into a Hash.
      @response = client.request(action) do 
        soap.body = options.to_hash
      end
    else
      raise ArgumentError, "Expected options to be nil or a Hash!"
    end
    @response.to_hash
  rescue Savon::SOAP::Fault => e
    raise ApiError.new(e), e.message.sub(/^\(\d+\)\s+/,'') # We raise our own error (FIXME: Correct?).
    # TODO: Curl::Err::HostResolutionError, Couldn't resolve host name
  end

  # This is voodoo. Use it only if you know voodoo kung-fu.
  #
  # The method fixes the ip that is set. It uses the error from
  # Transip to set the ip and re-request an authentication hash.
  #
  # It only works if you set password (via the password= method)!
  def request_with_ip4_fix(*args)
    self.request(*args)
  rescue ApiError => e
    if e.ip4_authentication_error?
      if !(@ip == e.error_msg_ip) # If not the same IP we try it with this IP..
        self.ip = e.error_msg_ip
        self.generate_hash # Generate a new authentication hash.
        self.client! # Update the client with the new authentication hash in the cookie!
        return self.request(*args)
      end
    end
    raise # If we haven't returned anything.. we raise the ApiError again.
  end

private

  # Find my local_ip..
  def self.local_ip
    orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true  # turn off reverse DNS resolution temporarily

    UDPSocket.open do |s|
      s.connect('74.125.77.147', 1) # Connects to a Google IP '74.125.77.147'.
      s.addr.last
    end
  ensure
    Socket.do_not_reverse_lookup = orig
  end

end