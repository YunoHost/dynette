#!/usr/bin/ruby

require 'rubygems'
require 'sinatra'
require 'data_mapper'
require 'json'
require 'base64'

set :port, 5000
DataMapper.setup(:default, ENV['DATABASE_URL'] || "postgres://dynette:myPassword@localhost/dynette")
DOMAINS = ["nohost.me", "noho.st"]
ALLOWED_IP = ["127.0.0.1"]

class Entry
    include DataMapper::Resource

    property :id, Serial
    property :public_key, String
    property :subdomain, String
    property :current_ip, String
    property :created_at, DateTime

    has n, :ips
end

class Ip
    include DataMapper::Resource

    property :id, Serial
    property :ip_addr, String

    belongs_to :entry
end

class Iplog
    include DataMapper::Resource

    property :ip_addr, String, :key => true
    property :visited_at, DateTime
end

class Ipban
    include DataMapper::Resource

    property :ip_addr, String, :key => true
end

not_found do
    content_type :json
    halt 404, { :error => "Not found" }.to_json
end

before do
    if Ipban.first(:ip_addr => request.ip)
        halt 410, "Your ip is banned from the service"
    end
    unless %w[domains test all ban unban].include? request.path_info.split('/')[1]
        if iplog = Iplog.last(:ip_addr => request.ip)
            if iplog.visited_at.to_time > Time.now - 30
                halt 410, "Please wait 30sec\n"
            else
                iplog.update(:visited_at => Time.now)
            end
        else
            Iplog.create(:ip_addr => request.ip, :visited_at => Time.now)
        end
    end
    content_type :json
end

# Check params
['/test/:subdomain', '/key/:public_key', '/ips/:public_key', '/ban/:ip', '/unban/:ip' ].each do |path|
    before path do
        if params.has_key?("public_key")
            public_key = Base64.decode64(params[:public_key].encode('ascii-8bit'))
            unless public_key.length == 24
                halt 400, { :error => "Key is invalid: #{public_key.to_s.encode('UTF-8', {:invalid => :replace, :undef => :replace, :replace => '?'})}" }.to_json
            end
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

get '/' do
    "Wanna play the dynette ?"
end

get '/domains' do
    headers['Access-Control-Allow-Origin'] = '*'
    DOMAINS.to_json
end

get '/test/:subdomain' do
    if entry = Entry.first(:subdomain => params[:subdomain])
        halt 409, { :error => "Subdomain already taken: #{entry.subdomain}" }.to_json
    else
        halt 200, "Domain #{params[:subdomain]} is available".to_json
    end
end


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

    # Process
    entry = Entry.new(:public_key => params[:public_key], :subdomain => params[:subdomain], :current_ip => request.ip, :created_at => Time.now)
    entry.ips << Ip.create(:ip_addr => request.ip)
    if entry.save
        halt 201, { :public_key => entry.public_key, :subdomain => entry.subdomain, :current_ip => entry.current_ip }.to_json
    else
        halt 412, { :error => "A problem occured during DNS registration" }.to_json
    end
end

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

delete '/key/:public_key' do
    unless ALLOWED_IP.include? request.ip
        status 403
        return "Access denied"
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

delete '/domains/:subdomain' do
    unless ALLOWED_IP.include? request.ip
        status 403
        return "Access denied"
    end
    if entry = Entry.first(:subdomain => params[:subdomain])
        Ip.first(:entry_id => entry.id).destroy
        if entry.destroy
            halt 200, "OK".to_json
        else
            halt 412, { :error => "A problem occured during DNS deletion" }.to_json
        end
    end
end

get '/all' do
    unless ALLOWED_IP.include? request.ip
        status 403
        return "Access denied"
    end
    Entry.all.to_json
end

get '/all/:domain' do
    unless ALLOWED_IP.include? request.ip
        status 403
        return "Access denied"
    end
    result = []
    Entry.all.each do |entry|
        result.push(entry) if params[:domain] == entry.subdomain.gsub(entry.subdomain.split('.')[0]+'.', '')
    end
    halt 200, result.to_json
end

get '/ips/:public_key' do
    params[:public_key] = Base64.decode64(params[:public_key].encode('ascii-8bit'))
    unless ALLOWED_IP.include? request.ip
        status 403
        return "Access denied"
    end
    ips = []
    Entry.first(:public_key => params[:public_key]).ips.all.each do |ip|
        ips.push(ip.ip_addr)
    end
    ips.to_json
end

get '/ban/:ip' do
    unless ALLOWED_IP.include? request.ip
        status 403
        return "Access denied"
    end
    Ipban.create(:ip_addr => params[:ip])
    Ipban.all.to_json
end

get '/unban/:ip' do
    unless ALLOWED_IP.include? request.ip
        status 403
        return "Access denied"
    end
    Ipban.first(:ip_addr => params[:ip]).destroy
    Ipban.all.to_json
end

#DataMapper.auto_migrate! # Destroy db content
DataMapper.auto_upgrade!
