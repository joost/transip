# TransIP API

Ruby gem to use the full TransIP (www.transip.nl) API (v5.0).

The TransIP API makes use of public/private key encryption. You need to use the
TransIP control panel to give your server access to the API and to generate a
key. You can then use the key together with your username to gain access to the
API.

For more info see:

* **The origin of this code:** https://github.com/joost/transip
* **TransIP API Docs:** https://www.transip.nl/g/api

## Install

Install from rubygems (rubygems.org/gems/transip):

    gem install transip

or add in your Bundle Gemfile:

    gem 'transip'

For the latest version:

    git clone https://github.com/joost/transip.git
    cd transip
    bundle install

## API Credentials

Enable the TransIP API via https://www.transip.nl/cp/mijn-account/#api.

Make sure:

* you enable the API
* add your IP to the access list
* If your host supports ipv6, also add your ipv6 ip!
* create and save your RSA private key

## Usage

For the most up-to-date documentation see the source files.

Setup the API client:

```ruby
Transip::DomainClient.new(username: 'your_username', key: 'your_private_rsa_key', ip: '12.34.12.3', mode: :readwrite)
```

The following classes are available:

* `Transip::DomainClient`
* `Transip::VpsClient`
* `Transip::ColocationClient`
* `Transip::WebhostingClient`
*  `Transip::ForwardClient`

In development you can leave out the ip. To test request use `:readonly` mode.

If you store your private key in a seperate file you can use the `key_file`
option to point to a local file.

### Using a proxy for routing traffic to TransIP

```ruby
Transip::DomainClient.new(username: 'your_username', key: 'your_private_rsa_key', ip: '12.34.12.3', mode: :readwrite, proxy: ENV["QUOTAGUARDSTATIC_URL"])
```

If you want to use a proxy through which you want to route the API calls to
TransIP, you can supply the proxy parameter. For example, I use [QuotaGuard
Static][] on Heroku. First install the addon, you will receive two static IP
addresses. Whitelist these in the TransIP API settings page. Next, supply the
proxy url.

[QuotaGuard Static]: https://addons.heroku.com/quotaguardstatic

### DomainClient

#### Actions

* batch_check_availability
* check_availability
* get_whois
* get_domain_names
* get_info
* batch_get_info
* get_auth_code
* get_is_locked
* register
* cancel
* transfer_with_owner_change
* transfer_without_owner_change
* set_nameservers
* set_lock
* unset_lock
* set_dns_entries
* set_owner
* set_contacts
* get_all_tld_infos
* get_tld_info
* get_current_domain_action
* retry_current_domain_action_with_new_data
* retry_transfer_with_different_auth_code
* cancel_domain_action

#### Examples

```ruby
transip = Transip::DomainClient.new(username: 'your_username', key: 'your_private_rsa_key', ip: '12.34.12.3', mode: :readwrite)

transip.actions #  => [:batch_check_availability, ...]

transip.request(:get_domain_names)
transip.request(:get_info, :domain_name => 'example.com')
transip.request(:get_whois, :domain_name => 'example.com')
transip.request(:set_dns_entries, :domain_name => 'example.com', :dns_entries => [Transip::DnsEntry.new('test', 5.inutes, 'A', '74.125.77.147')])
transip.request(:register, Transip::Domain.new('example.com', nil, nil, [Transip::DnsEntry.new('test', 300, 'A', '74.125.77.147')]))
transip.request(:set_contacts, :domain_name => 'example.com', :contacts => [Transip::WhoisContact.new('type', 'first', 'middle', 'last', 'company', 'kvk', 'companyType', 'street', 'number', 'postalCode', 'city', 'phoneNumber', 'faxNumber', 'email', 'country')])
```

### VpsClient

#### Actions

* get_available_products
* get_available_addons
* get_active_addons_for_vps
* get_available_upgrades
* get_available_addons_for_vps
* get_cancellable_addons_for_vps
* order_vps
* order_addon
* order_private_network
* upgrade_vps
* cancel_vps
* cancel_addon
* cancel_private_network
* get_private_networks_by_vps
* get_all_private_networks
* add_vps_to_private_network
* remove_vps_from_private_network
* get_amount_of_traffic_used
* start
* stop
* reset
* create_snapshot
* revert_snapshot
* remove_snapshot
* get_vps
* get_vpses
* get_snapshots_by_vps
* get_operating_systems
* install_operating_system
* get_ips_for_vps
* get_all_ips
* add_ipv6_to_vps
* update_ptr_record

#### Examples

```ruby
transip_vps = Transip::VpsClient.new(username: 'your_username', key: 'your_private_rsa_key', ip: '12.34.12.3', mode: :readwrite)

transip_vps.actions # => [:get_available_products, ...]

transip_vps.request(:get_available_products)
transip_vps.request(:get_operating_systems)
transip_vps.request(:order_vps, product_name: 'vps-bladevps-x1', addons: nil, operating_system_name: 'ubuntu-12.04.1-transip', hostname: 'my.hostname.com')
```

### ColocationClient, WebhostingClient and ForwardClient

Same as above.

Find out full methods and parameters by going throught the PHP sources of the
TransIP API. You can find them via www.transip.nl.

## Contribute and licence

Please feel free to contribute and send me a pull request via Github!

    The MIT License (MIT)

    Copyright (c) 2014 Joost Hietbrink / Richard Bronkhorst

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.
