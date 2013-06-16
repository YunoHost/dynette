#!/usr/bin/ruby

require 'rubygems'
require 'sinatra'
require 'data_mapper'
require 'json'

DataMapper.setup(:default, ENV['DATABASE_URL'] || "postgres://postgres:yayaya@localhost/dynette")
DOMAINS = ["yoyoyo.fr", "yayaya.fr"]
ALLOWED_IP = "82.196.13.142"
#ALLOWED_IP = "127.0.0.1"

class Entry
    include DataMapper::Resource

    property :id, Serial
    property :public_key, String
    property :subdomain, String
    property :current_ip, String

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

before do
    if Ipban.first(:ip_addr => request.ip)
        halt 410, "Your ip is banned from the service"
    end
    pass if %w[domains test all ban unban].include? request.path_info.split('/')[1]
    if iplog = Iplog.last(:ip_addr => request.ip)
        if iplog.visited_at.to_time > Time.now - 30
            halt 410, "Please wait 30sec\n"
        else
            iplog.update(:visited_at => Time.now)
        end
    else
        Iplog.create(:ip_addr => request.ip, :visited_at => Time.now)
    end
    content_type :json

    # Check params
    if params.has_key?("public_key")
        unless params[:public_key].match /^[a-z0-9]{22}==$/i
            halt 400, { :error => "Key is invalid: #{params[:public_key]}" }.to_json
        end
    end
    if params.has_key?("subdomain")
        unless params[:subdomain].match /^([a-zA-Z0-9]{1}([a-zA-Z0-9\-]*[a-zA-Z0-9])*)(\.[a-zA-Z0-9]{1}([a-zA-Z0-9\-]*[a-zA-Z0-9])*)*(\.[a-zA-Z]{1}([a-zA-Z0-9\-]*[a-zA-Z0-9])*)$/
            halt 400, { :error => "Subdomain is invalid: #{params[:subdomain]}" }.to_json
        end
        DOMAIN = params[:subdomain].gsub(params[:subdomain].split('.')[0]+'.', '')
        params[:subdomain] = params[:subdomain].split('.')[0]
    end
    if params.has_key?("ip")
        unless params[:ip].match /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
            halt 400, { :error => "IP is invalid: #{params[:ip]}" }.to_json
        end
    end
end

get '/' do
    "Wanna play the dynette ?"
end

get '/domains' do
    DOMAINS.to_json
end

get '/test/:subdomain' do
    if entry = Entry.first(:subdomain => params[:subdomain])
        halt 409, { :error => "Subdomain already taken: #{entry.subdomain}.#{DOMAIN}" }.to_json
    else
        "Domain #{params[:subdomain]}.#{DOMAIN} is available".to_json
    end
end


post '/:public_key' do
    # Check params
    halt 400, { :error => "Please indicate a subdomain" }.to_json unless params.has_key?("subdomain")

    # If already exists
    if entry = Entry.first(:subdomain => params[:subdomain])
        halt 409, { :error => "Subdomain already taken: #{entry.subdomain}.#{DOMAIN}" }.to_json
    end
    if entry = Entry.first(:public_key => params[:public_key])
        halt 409, { :error => "Key already exists for domain #{entry.subdomain}.#{DOMAIN}" }.to_json
    end

    # Process
    entry = Entry.new(:public_key => params[:public_key], :subdomain => params[:subdomain], :current_ip => request.ip)
    entry.ips << Ip.create(:ip_addr => request.ip)
    if entry.save
        halt 201, { :public_key => entry.public_key, :subdomain => entry.subdomain, :current_ip => entry.current_ip }.to_json
    else
        halt 412, { :error => "A problem occured during DNS registration" }.to_json
    end
end

put '/:public_key' do
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

delete '/:public_key' do
    if entry = Entry.first(:public_key => params[:public_key])
        if entry.destroy
            halt 200, "OK".to_json
        else
            halt 412, { :error => "A problem occured during DNS deletion" }.to_json
        end
    end
end

get '/all' do
    unless request.ip == ALLOWED_IP
        status 403
        return "Access denied"
    end
    Entry.all.to_json
end

get '/:public_key/ips' do
    unless request.ip == ALLOWED_IP
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
    unless request.ip == ALLOWED_IP
        status 403
        return "Access denied"
    end
    Ipban.create(:ip_addr => params[:ip])
    Ipban.all.to_json
end

get '/unban/:ip' do
    unless request.ip == ALLOWED_IP
        status 403
        return "Access denied"
    end
    Ipban.first(:ip_addr => params[:ip]).destroy
    Ipban.all.to_json
end


DataMapper.auto_upgrade!
