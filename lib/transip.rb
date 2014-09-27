require 'securerandom'
require 'savon'
require 'digest/sha2'
require 'base64'
require 'ipaddr'

require File.expand_path '../transip/version', __FILE__
require File.expand_path '../transip/client', __FILE__
require File.expand_path '../transip/api_error', __FILE__

#
# Implements the www.transip.nl API (v5.0). For more info see: https://www.transip.nl/g/api/
#
# The transip API makes use of public/private key encryption. You need to use the TransIP
# control panel to give your server access to the api, and to generate a key. You can then
# use the key together with your username to gain access to the api
# Usage:
#  transip = Transip::DomainClient.new(:username => 'api_username', :key => private_key, :ip => '12.34.12.3', :mode => 'readwrite') # use this in production
#  transip.actions # => [:check_availability, :get_whois, :get_domain_names, :get_info, :get_auth_code, :get_is_locked, :register, :cancel, :transfer_with_owner_change, :transfer_without_owner_change, :set_nameservers, :set_lock, :unset_lock, :set_dns_entries, :set_owner, :set_contacts]
#  transip.request(:get_domain_names)
#  transip.request(:get_info, :domain_name => 'example.com')
#  transip.request(:get_whois, :domain_name => 'example.com')
#  transip.request(:set_dns_entries, :domain_name => 'example.com', :dns_entries => [Transip::DnsEntry.new('test', 5.minutes, 'A', '74.125.77.147')])
#  transip.request(:set_contacts, :domain_name => 'example.com', :contacts => [Transip::WhoisContact.new('type', 'first', 'middle', 'last', 'company', 'kvk', 'companyType', 'street','number','postalCode','city','phoneNumber','faxNumber','email','country')])
#  transip.request(:register, Transip::Domain.new('example.com', nil, nil, [Transip::DnsEntry.new('test', 5.minutes, 'A', '74.125.77.147')]))
#
module Transip
  # Backwards compatibility with v3.x of the gem.
  # TODO: Remove
  def self.new(*args)
    puts "Transip.new is deprecated. Use Transip::DomainClient.new instead!"
    Client.new(*args)
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

    def member_name_to_camel(name)
      parts = name.to_s.split("_")
      parts.map{|p|p.capitalize!}
      parts[0].downcase!
      parts.join
    end

    # See what happens here: http://snippets.dzone.com/posts/show/302
    def members_to_hash
      Hash[*members.collect {|m| [member_name_to_camel(m), self.send(m)]}.flatten(1)]
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

# VPS related methods
# Available from TransIp v5.0.

  class Vps < TransipStruct.new(:name, :description, :operating_system, :disk_size, :memory_size, :cpus, :status, :ip_address, :vnc_hostname, :vnc_port_number, :vnc_password, :is_blocked, :is_customer_locked)
  end

  class VpsService < TransipStruct.new(:name, :description, :operating_system, :disk_size, :memory_size, :cpus, :status, :ip_address, :vnc_hostname, :vnc_port_number, :vnc_password, :is_blocked, :is_customer_locked)
  end
end
