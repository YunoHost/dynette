#!/usr/bin/ruby

require 'rubygems'
require 'sinatra'
require 'data_mapper'
require 'json'
require 'base64'
require 'bcrypt'

######################
###  Configuration ###
######################

DataMapper.setup(:default, ENV['DATABASE_URL'] || "postgres://dynette:myPassword@localhost/dynette")
DOMAINS = ["nohost.me", "noho.st"]
ALLOWED_IP = ["127.0.0.1"]


###############
### Classes ###
###############

# Dynette Entry class
class Entry
    include DataMapper::Resource
    include BCrypt

    property :id, Serial
    property :public_key, String

    # for historical reasons, dnssec algo was md5, so we assume that every
    # entry is using md5 while we provide automatic upgrade code inside
    # yunohost to move to sha512 instead (and register new domains using sha512)
    # it would be good to depreciate md5 in the futur but that migh be complicated
    property :key_algo, String, :default => "hmac-md5"

    property :subdomain, String
    property :current_ip, String
    property :created_at, DateTime
    property :recovery_password, Text

    has n, :ips
end

# IP class
class Ip
    include DataMapper::Resource

    property :id, Serial
    property :ip_addr, String

    belongs_to :entry
end

# IP Log class
class Iplog
    include DataMapper::Resource

    property :ip_addr, String, :key => true
    property :visited_at, DateTime
end

# IP ban class
class Ipban
    include DataMapper::Resource

    property :ip_addr, String, :key => true
end


################
### Handlers ###
################

# 404 Error handler
not_found do
    content_type :json
    halt 404, { :error => "Not found" }.to_json
end


##############
### Routes ###
##############

# Common tasks and settings for every route
before do
    # Always return json
    content_type :json

    # Allow CORS
    headers['Access-Control-Allow-Origin'] = '*'

    # Ban IP on flood
    if Ipban.first(:ip_addr => request.ip)
        halt 410, { :error => "Your ip is banned from the service" }.to_json
    end
    unless %w[domains test all ban unban].include? request.path_info.split('/')[1]
        if iplog = Iplog.last(:ip_addr => request.ip)
            if iplog.visited_at.to_time > Time.now - 30
                halt 410, { :error => "Please wait 30sec" }.to_json
            else
                iplog.update(:visited_at => Time.now)
            end
        else
            Iplog.create(:ip_addr => request.ip, :visited_at => Time.now)
        end
    end

end

# Check params
['/test/:subdomain', '/key/:public_key', '/ips/:public_key', '/ban/:ip', '/unban/:ip' ].each do |path|
    before path do
        if params.has_key?("public_key")
            public_key = Base64.decode64(params[:public_key].encode('ascii-8bit'))
            # might be 88
            unless public_key.length == 24 or public_key.length == 32
                halt 400, { :error => "Key is invalid: #{public_key.to_s.encode('UTF-8', {:invalid => :replace, :undef => :replace, :replace => '?'})}" }.to_json
            end
        end
        if params.has_key?("key_algo") and not ["hmac-md5", "hmac-sha512"].include? params[:key_algo]
            halt 400, { :error => "key_algo value is invalid: #{public_key}, it should be either 'hmac-sha512' or 'hmac-md5' (but you should **really** use 'hmac-sha512')" }.to_json
        end
        if params.has_key?("subdomain")
            unless params[:subdomain].match /^([a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)(\.[a-z0-9]{1}([a-z0-9\-]*[a-z0-9])*)*(\.[a-z]{1}([a-z0-9\-]*[a-z0-9])*)$/
                halt 400, { :error => "Subdomain is invalid: #{params[:subdomain]}" }.to_json
            end
            unless DOMAINS.include? params[:subdomain].gsub(params[:subdomain].split('.')[0]+'.', '')
                halt 400, { :error => "Subdomain #{params[:subdomain]} is not part of available domains: #{DOMAINS.join(', ')}" }.to_json
            end
        end
        if params.has_key?("ip")
            unless params[:ip].match /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
                halt 400, { :error => "IP is invalid: #{params[:ip]}" }.to_json
            end
        end
    end
end

# Main page, return some basic text
get '/' do
    content_type 'text/html'
    "Wanna play the dynette ?"
end

# Delete interface for user with recovery password
get '/delete' do
    f = File.open("delete.html", "r")

    content_type 'text/html'
    f.read
end

# Get availables DynDNS domains
get '/domains' do
    DOMAINS.to_json
end

# Check for sub-domain vailability
get '/test/:subdomain' do
    if entry = Entry.first(:subdomain => params[:subdomain])
        halt 409, { :error => "Subdomain already taken: #{entry.subdomain}" }.to_json
    else
        halt 200, "Domain #{params[:subdomain]} is available".to_json
    end
end

# Register a sub-domain
post '/key/:public_key' do
    params[:public_key] = Base64.decode64(params[:public_key].encode('ascii-8bit'))
    # Check params
    halt 400, { :error => "Please indicate a subdomain" }.to_json unless params.has_key?("subdomain")

    # If already exists
    if entry = Entry.first(:subdomain => params[:subdomain])
        halt 409, { :error => "Subdomain already taken: #{entry.subdomain}" }.to_json
    end
    if entry = Entry.first(:public_key => params[:public_key])
        halt 409, { :error => "Key already exists for domain #{entry.subdomain}" }.to_json
    end

    # If user provided a recovery password, hash and salt it before storing it
    if params.has_key?("recovery_password")
        recovery_password = BCrypt::Password.create(params[:recovery_password])
    else
        recovery_password = ""
    end

    if params.has_key?("key_algo")
        key_algo = params[:key_algo]
    else # default until we'll one day kill it
        key_algo = "hmac-md5"
    end

    # Process
    entry = Entry.new(:public_key => params[:public_key], :subdomain => params[:subdomain], :current_ip => request.ip, :created_at => Time.now, :recovery_password => recovery_password, :key_algo => key_algo)
    entry.ips << Ip.create(:ip_addr => request.ip)

    if entry.save
        halt 201, { :public_key => entry.public_key, :subdomain => entry.subdomain, :current_ip => entry.current_ip }.to_json
    else
        halt 412, { :error => "A problem occured during DNS registration" }.to_json
    end
end

# Migrate a key from hmac-md5 to hmac-sha512 because it's 2017
put '/migrate_key_to_sha512/' do
    # TODO check parameters
    params[:public_key_md5] = Base64.decode64(params[:public_key_md5].encode('ascii-8bit'))
    params[:public_key_sha512] = Base64.decode64(params[:public_key_sha512].encode('ascii-8bit'))

    # TODO signing handling

    # TODO check entry exists
    entry = Entry.first(:public_key => params[:public_key_md5],
                        :key_algo => "hmac-md5")

    unless request.ip == entry.current_ip
        entry.ips << Ip.create(:ip_addr => request.ip)
    end
    entry.current_ip = request.ip

    entry.public_key = params[:public_key_sha512]
    entry.key_algo = "hmac-sha512"

    unless entry.save
        halt 412, { :error => "A problem occured during key algo migration" }.to_json
    end

    # need to regenerate bind9 stuff
    `python ./dynette.cron.py`
    # flush this idiotic bind cache because he doesn't know how to do that
    # himself
    `rndc flush`

    halt 201, { :public_key => entry.public_key, :subdomain => entry.subdomain, :current_ip => entry.current_ip }.to_json
end

# Update a sub-domain
put '/key/:public_key' do
    params[:public_key] = Base64.decode64(params[:public_key].encode('ascii-8bit'))
    entry = Entry.first(:public_key => params[:public_key])
    unless request.ip == entry.current_ip
        entry.ips << Ip.create(:ip_addr => request.ip)
    end
    entry.current_ip = request.ip
    if entry.save
        halt 201, { :public_key => entry.public_key, :subdomain => entry.subdomain, :current_ip => entry.current_ip }.to_json
    else
        halt 412, { :error => "A problem occured during DNS update" }.to_json
    end
end

# Delete a sub-domain from key
delete '/key/:public_key' do
    unless ALLOWED_IP.include? request.ip
        halt 403, { :error => "Access denied"}.to_json
    end
    params[:public_key] = Base64.decode64(params[:public_key].encode('ascii-8bit'))
    if entry = Entry.first(:public_key => params[:public_key])
        Ip.first(:entry_id => entry.id).destroy
        if entry.destroy
            halt 200, "OK".to_json
        else
            halt 412, { :error => "A problem occured during DNS deletion" }.to_json
        end
    end
end

# Delete a sub-domain
delete '/domains/:subdomain' do
    unless (ALLOWED_IP.include? request.ip) || (params.has_key?("recovery_password"))
        halt 403, { :error => "Access denied"}.to_json
    end
    if entry = Entry.first(:subdomain => params[:subdomain])

        # For non-admin
        unless (ALLOWED_IP.include? request.ip)
            # If no recovery password was provided when registering domain,
            # or if wrong password is provided, deny access
            if (entry.recovery_password == "") || (BCrypt::Password.new(entry.recovery_password) != params[:recovery_password])
                halt 403, { :error => "Access denied" }.to_json
            end
        end


        Ip.first(:entry_id => entry.id).destroy
        if entry.destroy
            halt 200, "OK".to_json
        else
            halt 412, { :error => "A problem occured during DNS deletion" }.to_json
        end
    end
    halt 404
end

# Get all registered sub-domains
get '/all' do
    unless ALLOWED_IP.include? request.ip
        halt 403, { :error => "Access denied"}.to_json
    end
    Entry.all.to_json
end

# Get all registered sub-domains for a specific DynDNS domain
get '/all/:domain' do
    unless ALLOWED_IP.include? request.ip
        halt 403, { :error => "Access denied"}.to_json
    end
    result = []
    Entry.all.each do |entry|
        result.push(entry) if params[:domain] == entry.subdomain.gsub(entry.subdomain.split('.')[0]+'.', '')
    end
    halt 200, result.to_json
end

# ?
get '/ips/:public_key' do
    params[:public_key] = Base64.decode64(params[:public_key].encode('ascii-8bit'))
    unless ALLOWED_IP.include? request.ip
        halt 403, { :error => "Access denied"}.to_json
    end
    ips = []
    Entry.first(:public_key => params[:public_key]).ips.all.each do |ip|
        ips.push(ip.ip_addr)
    end
    ips.to_json
end

# Ban an IP address for 30 seconds
get '/ban/:ip' do
    unless ALLOWED_IP.include? request.ip
        halt 403, { :error => "Access denied"}.to_json
    end
    Ipban.create(:ip_addr => params[:ip])
    Ipban.all.to_json
end

# Unban an IP address
get '/unban/:ip' do
    unless ALLOWED_IP.include? request.ip
        halt 403, { :error => "Access denied"}.to_json
    end
    Ipban.first(:ip_addr => params[:ip]).destroy
    Ipban.all.to_json
end


#DataMapper.auto_migrate! # Destroy db content
DataMapper.auto_upgrade!
