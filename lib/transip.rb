require "rubygems"
require "bundler/setup"
require 'securerandom'
require 'savon'
require 'curb'
require 'facets/string'
require 'digest/sha2'
require 'base64'
require 'ipaddr'

require File.expand_path '../transip/version', __FILE__
#
# Implements the www.transip.nl API (v4.2). For more info see: https://www.transip.nl/g/api/
#
# The transip API makes use of public/private key encryption. You need to use the TransIP
# control panel to give your server access to the api, and to generate a key. You can then
# use the key together with your username to gain access to the api
# Usage:
#  transip = Transip.new(:username => 'api_username', :key => private_key, :ip => '12.34.12.3', :mode => 'readwrite') # use this in production
#  transip.actions # => [:check_availability, :get_whois, :get_domain_names, :get_info, :get_auth_code, :get_is_locked, :register, :cancel, :transfer_with_owner_change, :transfer_without_owner_change, :set_nameservers, :set_lock, :unset_lock, :set_dns_entries, :set_owner, :set_contacts]
#  transip.request(:get_domain_names)
#  transip.request(:get_info, :domain_name => 'example.com')
#  transip.request(:get_whois, :domain_name => 'example.com')
#  transip.request(:set_dns_entries, :domain_name => 'example.com', :dns_entries => [Transip::DnsEntry.new('test', 5.minutes, 'A', '74.125.77.147')])
#  transip.request(:register, Transip::Domain.new('example.com', nil, nil, [Transip::DnsEntry.new('test', 5.minutes, 'A', '74.125.77.147')]))
#
class Transip
  SERVICE = 'DomainService'
  WSDL = 'https://api.transip.nl/wsdl/?service=DomainService'
  API_VERSION = '4.2'

  attr_accessor :username, :password, :ip, :mode, :hash
  attr_reader :response

  # Following Error needs to be catched in your code!
  class ApiError < RuntimeError
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
      Gyoku.xml(self.members_to_hash)
    end

    # See what happens here: http://snippets.dzone.com/posts/show/302
    def members_to_hash
      Hash[*members.collect {|m| [m, self.send(m)]}.flatten]
    end

    def to_hash
      { self.class_name_to_sym => self.members_to_hash }
    end

    def self.get_type(hash)
      type = hash[:'@xsi:type'].split(":").last
      raise "No type definition found in hash" if type.nil?
      klass = Transip.const_get(type) rescue nil
      raise "Invalid transipStruct #{type}" unless klass < TransipStruct
      klass
    end

    def self.from_hash(hash)
      begin
        result = get_type(hash).new
      rescue
        return hash
      end
      hash.each do |key, value|
        next if key[0] == '@'
        result.send(:"#{key}=", from_soap(value))
      end
      result
    end

    def self.from_soap(input)
      if input.is_a? Array
        result = input.map {|value| from_soap(value)}
      elsif input.is_a? Hash

        if input.keys.first == :item
          result = from_soap(input[:item])
        elsif input[:'@xsi:type'] == 'xsd:string'
          result = ''
        else
          result = TransipStruct.from_hash(input)
        end
        # this is not a transip struct
        if result.is_a? Hash
          result.each do |key, value|
            result[key] = from_soap(value)
          end
        end
      else
        result = input
      end
      result
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
  class Nameserver < TransipStruct.new(:hostname, :ipv4, :ipv6)
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
  # auth_code - String
  # is_locked - boolean
  # registration_date - DateTime
  # renewal_date - DateTime
  class Domain < TransipStruct.new(:name, :nameservers, :contacts, :dns_entries, :branding, :auth_code, :is_locked, :registration_date, :renewal_date)
  end


  # name - String
  # price - number
  # renewal_price - number
  # capabilities - Array of strings
  # registration_period_length - number
  # cancel_time_frame - number
  class Tld < TransipStruct.new(:name, :price, :renewal_price, :capabilities, :registration_period_length, :cancel_time_frame)
  end

  # Options:
  # * username
  # * ip
  # * key
  # * mode
  #
  # Example:
  #  transip = Transip.new(:username => 'api_username', :ip => '12.34.12.3', :key => mykey, :mode => 'readwrite') # use this in production
  def initialize(options = {})
    @key = options[:key]
    @username = options[:username]
    @ip = options[:ip]
    raise ArgumentError, "The :username, :ip and :key options are required!" if @username.nil? or @key.nil?

    @mode = options[:mode] || :readonly
    @endpoint = options[:endpoint] || 'api.transip.nl'
    if options[:password]
      @password = options[:password]
    end
    @savon_options = {
      :wsdl => WSDL
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

  def urlencode(input)
    output = URI.encode_www_form_component(input)
    output.gsub!('+', '%20')
    output.gsub!('%7E', '~')
    output
  end

  def serialize_parameters(parameters, key_prefix=nil)
    parameters = parameters.to_hash.values.first if parameters.is_a? TransipStruct
    parameters = convert_array_to_hash(parameters) if parameters.is_a? Array
    if not parameters.is_a? Hash
      return urlencode(parameters)
    end

    encoded_parameters = []
    parameters.each do |key, value|
      next if key.to_s == '@xsi:type'
      encoded_key = (key_prefix.nil?) ? urlencode(key) : "#{key_prefix}[#{urlencode(key)}]"
      if value.is_a? Hash or value.is_a? Array or value.is_a? TransipStruct
        encoded_parameters << serialize_parameters(value, encoded_key)
      else
        encoded_value = urlencode(value)
        encoded_parameters << "#{encoded_key}=#{encoded_value}"
      end
    end

    encoded_parameters = encoded_parameters.join("&")
    #puts encoded_parameters.split('&').join("\n")
    encoded_parameters
  end


  # does all the techy stuff to calculate transip's sick authentication scheme:
  # a hash with all the request information is subsequently:
  # serialized like a www form
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
    raise "Invalid RSA key" unless @key =~ /-----BEGIN RSA PRIVATE KEY-----(.*)-----END RSA PRIVATE KEY-----/sim
    serialized_input = serialize_parameters(input)

    digest = Digest::SHA512.new.digest(serialized_input)
    asn_header = "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"
    asn = asn_header + digest
    private_key = OpenSSL::PKey::RSA.new(@key)
    encrypted_asn = private_key.private_encrypt(asn)
    readable_encrypted_asn = Base64.encode64(encrypted_asn)
    urlencode(readable_encrypted_asn)
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
    result = to_cookies [ "login=#{self.username}",
                 "mode=#{self.mode}",
                 "timestamp=#{time}",
                 "nonce=#{nonce}",
                 "clientVersion=#{API_VERSION}",
                 "signature=#{signature(method, parameters, time, nonce)}"

               ]
    #puts signature(method, parameters, time, nonce)
    result
  end

  # Same as client method but initializes a brand new fresh client.
  # You have to use this one when you want to re-set the mode (readwrite, readonly),
  # or authentication details of your client.
  def client!
    @client = Savon::Client.new(@savon_options) do
      namespaces(
        "xmlns:enc" => "http://schemas.xmlsoap.org/soap/encoding/"
      )
    end
    return @client
  end

  # Returns a Savon::Client object to be used in the connection.
  # This object is re-used and cached as @client.
  def client
    @client ||= client!
  end

  # Returns Array with all possible SOAP WSDL actions.
  def actions
    client.operations
  end

  # This makes sure that arrays are properly encoded as soap-arrays by Gyoku
  def fix_array_definitions(options)
    result = {}
    options.each do |key, value|
      if value.is_a? Array and value.size > 0
        entry_name = value.first.class.name.split(":").last
        result[key] = {
          'item' => {:content! => value, :'@xsi:type' => "tns:#{entry_name}"},
          :'@xsi:type' => "tns:ArrayOf#{entry_name}",
          :'@enc:arrayType' => "tns:#{entry_name}[#{value.size}]"
        }
      else
        result[key] = value
      end
    end
    result
  end


  # converts the savon response object to something we can return to the caller
  # - A TransipStruct object
  # - An array of TransipStructs
  # - nil
  def process_response(response)
    response = response.to_hash.values.first[:return] rescue nil
    TransipStruct.from_soap(response)

  end

  # This is the main request function
  # throws ApiError
  # returns response object (can be TransipStruct or Array of TransipStruct)
  def request(action, options = nil)
    formatted_action = action.to_s.lower_camelcase
    parameters = {
      # for some reason, the transip server wants the body root tag to be
      # the name of the action.
      :message_tag => formatted_action
    }
    options = options.to_hash  if options.is_a? Transip::TransipStruct

    if options.is_a? Hash
      xml_options = fix_array_definitions(options)
    elsif options.nil?
      xml_options = nil
    else
      raise "Invalid parameter format (should be nil, hash or TransipStruct"
    end
    parameters[:message] = xml_options
    parameters[:cookies] = cookies(action, options)
    #puts parameters.inspect
    response = client.call(action, parameters)

    process_response(response)
  rescue Savon::SOAPFault => e
    raise ApiError.new(e), e.message.sub(/^\(\d+\)\s+/,'') # We raise our own error (FIXME: Correct?).
  end
end
