module Transip

  class Client

    API_VERSION = '5.0'
    API_SERVICE = 'DomainService'

    attr_accessor :username, :password, :ip, :mode, :hash
    attr_reader :response

    def api_version
      # We use self.class:: here to not use parentclass constant.
      @api_version || self.class::API_VERSION
    end

    def api_service
      @api_service || self.class::API_SERVICE
    end

    def wsdl
      "https://api.transip.nl/wsdl/?service=#{api_service}"
    end

    attr_accessor :debug

    # Options:
    # * username - Your login name on the TransIP website.
    # * ip - needed in production
    # * key / key_file - key is one of your private keys (these can be requested via your Controlpanel). key_file is path to file containing key.
    # * mode - :readonly, :readwrite
    #
    # Example:
    #  transip = Transip.new(:username => 'api_username', :ip => '12.34.12.3', :key => mykey, :mode => 'readwrite') # use this in production
    def initialize(options = {})
      @key = options[:key] || (options[:key_file] && File.read(options[:key_file]))
      @username = options[:username]
      @ip = options[:ip]
      @api_version = options[:api_version]
      @api_service = options[:api_service]
      raise ArgumentError, "The :username, :ip and :key options are required!" if @username.nil? or @key.nil?

      @mode = options[:mode] || :readonly
      @endpoint = options[:endpoint] || 'api.transip.nl'
      if options[:password]
        @password = options[:password]
      end
      @savon_options = {
        :wsdl => wsdl
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
      debug_log("serialize_parameters(#{parameters.inspect}, #{key_prefix.inspect}")

      parameters = parameters.to_hash.values.first if parameters.is_a? TransipStruct
      parameters = convert_array_to_hash(parameters) if parameters.is_a? Array
      if not parameters.is_a? Hash
        return urlencode(parameters)
      end
      return "#{key_prefix}=" if parameters.empty?

      encoded_parameters = []
      parameters.each do |key, value|
        next if key.to_s == '@xsi:type'
        encoded_key = (key_prefix.nil?) ? urlencode(key) : "#{key_prefix}[#{urlencode(key)}]"
        if value.is_a?(Hash) or value.is_a?(Array) or value.is_a?(TransipStruct)
          encoded_parameters << serialize_parameters(value, encoded_key)
        else
          encoded_value = urlencode(value)
          encoded_parameters << "#{encoded_key}=#{encoded_value}"
        end
      end

      encoded_parameters = encoded_parameters.join("&")
      debug_log("encoded_parameters:\n#{encoded_parameters.split('&').join("\n")}")
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
        '__service' => api_service,
        '__hostname' => @endpoint,
        '__timestamp' => time,
        '__nonce' => nonce

      }
      input.merge!(options)
      raise "Invalid RSA key" unless @key =~ /-----BEGIN (RSA )?PRIVATE KEY-----(.*)-----END (RSA )?PRIVATE KEY-----/sim
      serialized_input = serialize_parameters(input)

      digest = Digest::SHA512.new.digest(serialized_input)
      asn_header = "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"

      # convert asn_header literal to ASCII-8BIT
      if RUBY_VERSION.split('.')[0] == "2"
        asn = asn_header.b + digest
      else
        asn = asn_header + digest
      end
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
                   "clientVersion=#{api_version}",
                   "signature=#{signature(method, parameters, time, nonce)}"

                 ]
      debug_log("signature:\n#{signature(method, parameters, time, nonce)}")
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
        if value.is_a?(Array) and (value.size > 0)
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
      options = options.to_hash if options.is_a?(Transip::TransipStruct)

      if options.is_a?(Hash)
        xml_options = fix_array_definitions(options)
      elsif options.nil?
        xml_options = nil
      else
        raise "Invalid parameter format (should be nil, hash or TransipStruct)"
      end
      parameters[:message] = xml_options
      parameters[:cookies] = cookies(action, options)
      debug_log("parameters:\n#{parameters.inspect}")
      response = client.call(action, parameters)

      process_response(response)
    rescue Savon::SOAPFault => e
      raise ApiError.new(e), e.message.sub(/^\(\d+\)\s+/,'') # We raise our own error (FIXME: Correct?).
    end

  private

    def debug_log(msg)
      puts msg if @debug
    end

  end

  # 'Aliased' by Transip::Client.
  class DomainClient < Client;end

  # We name it VpsClient instead of VpsService since the latter is already in use by
  # the TransipStruct.
  class VpsClient < Client
    API_SERVICE = 'VpsService'
  end

  class ColocationClient < Client
    API_SERVICE = 'ColocationService'
  end

  class WebhostingClient < Client
    API_SERVICE = 'WebhostingService'
  end

  class ForwardClient < Client
    API_SERVICE = 'ForwardService'
  end

end