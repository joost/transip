require "rubygems"
require "bundler/setup"
require 'securerandom'
require 'savon'
require 'curb'
require 'facets'
require 'digest/sha2'
require 'base64'
#
# Implements the www.transip.nl API (v4.2). For more info see: https://www.transip.nl/g/api/
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
#  transip.hash = 'your_hash' # Or use this to directly set the hash (so you don't have to use your password in your code)
#  transip.client! # This returns a new Savon::Client. It is cached in transip.client so when you update your username, password or hash call this method!
#
# Credits:
#  Savon Gem - See: http://savonrb.com/. Wouldn't be so simple without it!
class Transip
  SERVICE = 'DomainService'
  WSDL = 'https://api.transip.nl/wsdl/?service=DomainService'
  API_VERSION = '4.2'

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
    @key = options[:key]
    @username = options[:username]
    raise ArgumentError, "The :username and :key options are required!" if @username.nil? or @key.nil?
    @ip = options[:ip] || self.class.local_ip
    @mode = options[:mode] || :readonly
    @endpoint = options[:endpoint] || 'api.transip.nl'
    if options[:password]
      @password = options[:password]
    end
    @savon_options = {
      :wsdl => WSDL,
    }
    # By default we don't want to debug!
    self.turn_off_debugging!
  end

  # By default we don't want to debug!
  # Changing might impact other Savon usages.
  def turn_off_debugging!
      @savon_options[:log] = false            # disable logging
      @savon_options[:log_level] = :info      # changing the log level
  end


  # Make Savon log to Rails.logger and turn_off_debugging!
  def use_with_rails!
    if Rails.env.production?
      self.turn_off_debugging!
    end
    @savon_options[:logger] = Rails.logger  # using the Rails logger
  end

  # yes, i know, it smells bad
  def convert_array_to_hash(array)
    result = {}
    array.each_with_index do |value, index|
      result[index] = value
    end
    result
  end

  # does all the techy stuff to calculate transip's sick authentication scheme:
  # a hash with all the request information is subsequently:
  # URL encoded
  # SHA512 digested
  # asn1 header added
  # private key encrypted
  # Base64 encoded
  # URL encoded
  # I think the guys at transip were trying to use their entire crypto-toolbox!
  def signature(method, parameters, time, nonce)
    formatted_method = method.to_s.lower_camelcase
    parameters ||= {} 
    input = convert_array_to_hash(parameters.values)
    options = {
      '__method' => formatted_method,
      '__service' => SERVICE,
      '__hostname' => @endpoint,
      '__timestamp' => time,
      '__nonce' => nonce
  
    }
    input.merge!(options)
    puts input.inspect
    raise "Invalid RSA key" unless @key =~ /-----BEGIN RSA PRIVATE KEY-----(.*)-----END RSA PRIVATE KEY-----/sim
    encoded_input = URI.encode_www_form(input)
    digest = Digest::SHA512.new.digest(encoded_input)
    asn_header = "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"
    asn = asn_header + digest
    
    private_key = OpenSSL::PKey::RSA.new(@key)
    encrypted_asn = private_key.private_encrypt(asn)
    readable_encrypted_asn = Base64.encode64(encrypted_asn)
    URI.encode_www_form_component(readable_encrypted_asn)
  end

  def to_cookies(content)
    content.map do |item|
      HTTPI::Cookie.new item
    end
  end

  # Used for authentication
  def cookies(method, parameters)
    time = Time.new.to_i
    #strip out the -'s because transip requires the nonce to be between 6 and 32 chars
    nonce = SecureRandom.uuid.gsub("-", '')
    to_cookies [ "login=#{self.username}",
                 "mode=#{self.mode}",
                 "timestamp=#{time}",
                 "nonce=#{nonce}",
                 "clientVersion=#{API_VERSION}",
                 "signature=#{signature(method, parameters, time, nonce)}"

               ]

  end

  # Same as client method but initializes a brand new fresh client.
  # You have to use this one when you want to re-set the mode (readwrite, readonly),
  # or authentication details of your client.
  def client!
    @client = Savon::Client.new(@savon_options) 
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
    formatted_action = action.to_s.lower_camelcase
    parameters = {
      # for some reason, the transip server wants the body root tag to be
      # the name of the action.
      :message_tag => formatted_action
    }
    if options.is_a? Transip::TransipStruct
      options = options.to_hash 
    elsif options.is_a? Hash
      options = options
    elsif options.nil?
      #no work here!
    else
      raise "Invalid parameter format (should be nil, hash or TransipStruct"
    end
    parameters[:message] = options
    parameters[:cookies] = cookies(action, options)
    @response = client.call(action, parameters)
    @response.to_hash
  rescue Savon::SOAPFault => e
    raise ApiError.new(e), e.message.sub(/^\(\d+\)\s+/,'') # We raise our own error (FIXME: Correct?).
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