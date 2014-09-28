# :no-doc:
module Transip
  # :no-doc:
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
    # * key / key_file - key is one of your private keys (these can be requested
    #   via your Controlpanel). key_file is path to file containing key.
    # * mode - :readonly, :readwrite
    # * proxy - url of proxy through which you want to route API requests. For
    #   example, if you use Quataguard Static on Heroku, use
    #   ENV["QUOTAGUARDSTATIC_URL"]. If not used, leave blank or don't supply it
    #   as a parameter.
    #
    # Example:
    #
    #  transip = Transip.new(:username => 'api_username', :ip => '12.34.12.3',
    #  :key => mykey, :mode => 'readwrite', :proxy => '')
    #
    def initialize(options = {})
      @username = options[:username]
      @key      = options[:key] || (options[:key_file] &&
        File.read(File.expand_path(options[:key_file])))

      unless @username && @key
        fail ArgumentError, 'The :username, :ip and :key options are required!'
      end

      @ip                    = options[:ip]
      @api_version           = options[:api_version]
      @api_service           = options[:api_service]
      @mode                  = options[:mode] || :readonly
      @endpoint              = options[:endpoint] || 'api.transip.nl'
      @password              = options[:password] if options[:password]
      @savon_options         = { wsdl: wsdl }
      @savon_options[:proxy] = options[:proxy] if options[:proxy]

      turn_off_debugging!
    end

    def turn_off_debugging!
      @savon_options[:log]       = false
      @savon_options[:log_level] = :info
    end

    def convert_array_to_hash(array)
      Hash[array.map.with_index { |value, i| [i, value] }]
    end

    def urlencode(input)
      URI.encode_www_form_component(input).gsub('+', '%20').gsub('%7E', '~')
    end

    def serialize_parameters(params, key_prefix = nil)
      debug_log("serialize_parameters(#{params.inspect}, #{key_prefix.inspect}")

      params = params.to_hash.values.first if params.is_a? TransipStruct
      params = convert_array_to_hash(params) if params.is_a? Array

      return urlencode(params) unless params.is_a? Hash
      return "#{key_prefix}=" if params.empty?

      encoded_params = params.each_with_object([]) do |(key, value), array|
        next if key.to_s == '@xsi:type'

        encoded_key = if key_prefix
                        "#{key_prefix}[#{urlencode(key)}]"
                      else
                        urlencode(key)
                      end

        case value
        when Hash, Array, TransipStruct then
          array << serialize_parameters(value, encoded_key)
        else
          array << "#{encoded_key}=#{urlencode(value)}"
        end
      end.join('&')

      debug_log("encoded_parameters:\n#{encoded_params.split('&').join("\n")}")
      encoded_params
    end

    def camelize(string)
      parts = string.to_s.split('_')
      parts.map(&:capitalize!)
      parts[0].downcase!
      parts.join
    end

    #
    # does all the techy stuff to calculate transip's sick authentication
    # scheme:
    #
    # a hash with all the request information is subsequently:
    #
    # * serialized like a www form
    # * SHA512 digested
    # * asn1 header added
    # * private key encrypted
    # * Base64 encoded
    # * URL encoded
    #
    # I think the guys at transip were trying to use their entire crypto-toolbox
    #
    def signature(method, parameters, time, nonce)
      formatted_method = camelize(method.to_s)
      parameters ||= {}
      input        = convert_array_to_hash(parameters.values)

      input.merge!(
        '__method'    => formatted_method,
        '__service'   => api_service,
        '__hostname'  => @endpoint,
        '__timestamp' => time,
        '__nonce'     => nonce
      )

      unless @key =~ /-{5}BEGIN (RSA )?PRIVATE KEY-{5}(.*)/sim
        fails 'Invalid RSA key'
      end

      digest = Digest::SHA512.new.digest(serialize_parameters(input))
      asn_header = "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02" \
                   "\x03\x05\x00\x04\x40"

      # convert asn_header literal to ASCII-8BIT
      header   = RUBY_VERSION.split('.')[0] == '2' ? asn_header.b : asn_header
      asn      = header + digest
      encr_asn = OpenSSL::PKey::RSA.new(@key).private_encrypt(asn)

      urlencode(Base64.encode64(encr_asn))
    end

    def to_cookies(content)
      content.map { |item| HTTPI::Cookie.new(item) }
    end

    # Used for authentication
    #
    def cookies(method, parameters)
      time = Time.new.to_i

      # strip out the -'s because transip requires the nonce to be between 6 and
      # 32 chars.
      nonce   = SecureRandom.uuid.gsub('-', '')
      debug_log("signature:\n#{signature(method, parameters, time, nonce)}")

      to_cookies [
        "login=#{username}",
        "mode=#{mode}",
        "timestamp=#{time}",
        "nonce=#{nonce}",
        "clientVersion=#{api_version}",
        "signature=#{signature(method, parameters, time, nonce)}"]
    end

    # Same as client method but initializes a brand new fresh client. You have
    # to use this one when you want to re-set the mode (readwrite, readonly), or
    # authentication details of your client.
    #
    def client!
      @client = Savon::Client.new(@savon_options) do
        namespaces('xmlns:enc' => 'http://schemas.xmlsoap.org/soap/encoding/')
      end
    end

    # Returns a Savon::Client object to be used in the connection. This object
    # is re-used and cached as @client.
    #
    def client
      @client ||= client!
    end

    # Returns Array with all possible SOAP WSDL actions.
    #
    def actions
      client.operations
    end

    # This makes sure that arrays are properly encoded as soap-arrays by Gyoku
    #
    def fix_array_definitions(options)
      options.each_with_object({}) do |(key, value), hash|
        if value.is_a?(Array) && value.size > 0
          entry_name = value.first.class.name.split(':').last
          hash[key] = {
            'item' => {
              :content! => value,
              :'@xsi:type' => "tns:#{entry_name}" },
            :'@xsi:type' => "tns:ArrayOf#{entry_name}",
            :'@enc:arrayType' => "tns:#{entry_name}[#{value.size}]"
          }
        elsif value.is_a?(Hash)
          hash[key] = fix_array_definitions(value)
        else
          hash[key] = value
        end
      end
    end

    # converts the savon response object to something we can return to the
    # caller:
    #
    # * A TransipStruct object
    # * An array of TransipStructs
    # * nil
    #
    def process_response(response)
      response = response.to_hash.values.first[:return] rescue nil
      TransipStruct.from_soap(response)
    end

    # This is the main request function
    # throws ApiError
    # returns response object (can be TransipStruct or Array of TransipStruct)
    #
    def request(action, options = nil)
      formatted_action = camelize(action.to_s)

      # for some reason, the transip server wants the body root tag to be
      # the name of the action.
      parameters = { message_tag: formatted_action }
      options = options.to_hash if options.is_a?(Transip::TransipStruct)

      if options.is_a?(Hash)
        xml_options = fix_array_definitions(options)
      elsif options.nil?
        xml_options = nil
      else
        fail 'Invalid parameter format (should be nil, hash or TransipStruct)'
      end
      parameters[:message] = xml_options
      parameters[:cookies] = cookies(action, options)
      debug_log("parameters:\n#{parameters.inspect}")
      response = client.call(action, parameters)

      process_response(response)
    rescue Savon::SOAPFault => e
      raise ApiError.new(e), e.message.sub(/^\(\d+\)\s+/, '')
    end

    private

    def debug_log(msg)
      puts msg if @debug
    end
  end

  # 'Aliased' by Transip::Client.
  class DomainClient < Client; end

  # We name it VpsClient instead of VpsService since the latter is already in
  # use by the TransipStruct.
  class VpsClient < Client
    API_SERVICE = 'VpsService'
  end

  # :no-doc:
  class ColocationClient < Client
    API_SERVICE = 'ColocationService'
  end

  # :no-doc:
  class WebhostingClient < Client
    API_SERVICE = 'WebhostingService'
  end

  # :no-doc:
  class ForwardClient < Client
    API_SERVICE = 'ForwardService'
  end
end
