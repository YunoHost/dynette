#!/usr/bin/ruby

require 'rubygems'
require 'sinatra'
require 'data_mapper'
require 'json'

DataMapper.setup(:default, ENV['DATABASE_URL'] || "postgres://postgres:yayaya@localhost/dynette")
DOMAIN = "yoyoyo.fr"
ALLOWED_IP = "82.196.13.142"

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

get '/' do
    `whoami`
end

post '/:public_key' do
    content_type :json
    # Check params
    status 400
    return { :error => "Please indicate a subdomain" }.to_json unless params.has_key?("subdomain")
    return { :error => "Subdomain is invalid: #{params[:subdomain]}.#{DOMAIN}" }.to_json unless params[:subdomain].match /^[a-z0-9-]{3,16}$/
    return { :error => "Key is invalid: #{params[:public_key]}" }.to_json unless params[:public_key].match /^[a-z0-9]{22}==$/i

    # If already exists
    status 409
    if entry = Entry.first(:subdomain => params[:subdomain])
        return { :error => "Subdomain already taken: #{entry.subdomain}.#{DOMAIN}" }.to_json
    end
    if entry = Entry.first(:public_key => params[:public_key])
        return { :error => "Key already exists for domain #{entry.subdomain}.#{DOMAIN}" }.to_json
    end

    # Process
    entry = Entry.new(:public_key => params[:public_key], :subdomain => params[:subdomain], :current_ip => request.ip)
    entry.ips << Ip.create(:ip_addr => request.ip)
    if entry.save
        status 201
        return { :public_key => entry.public_key, :subdomain => entry.subdomain, :current_ip => entry.current_ip }.to_json
    else
        status 412
        return { :error => "A problem occured during DNS registration" }.to_json
    end
end

put '/:public_key' do
    content_type :json
    # Check params
    unless params[:public_key].match /^[a-z0-9]{22}==$/i
        status 400
        return { :error => "Key is invalid: #{params[:public_key]}" }.to_json
    end

    entry = Entry.first(:public_key => params[:public_key])
    unless request.ip == entry.current_ip
        entry.ips << Ip.create(:ip_addr => request.ip)
    end
    entry.current_ip = request.ip
    if entry.save
        status 201
        return { :public_key => entry.public_key, :subdomain => entry.subdomain, :current_ip => entry.current_ip }.to_json
    else
        status 412
        return { :error => "A problem occured during DNS update" }.to_json
    end
end

delete '/:public_key' do
    content_type :json
    # Check params
    unless params[:public_key].match /^[a-z0-9]{22}==$/i
        status 400
        return { :error => "Key is invalid: #{params[:public_key]}" }.to_json
    end

    if entry = Entry.first(:public_key => params[:public_key])
        return "OK" if entry.destroy
    end
end

get '/all' do
    unless request.ip == ALLOWED_IP
        status 403
        return "Access denied"
    end
    content_type :json
    Entry.all.to_json
end

get '/:public_key/ips' do
    unless request.ip == ALLOWED_IP
        status 403
        return "Access denied"
    end
    content_type :json
    unless params[:public_key].match /^[a-z0-9]{22}==$/i
        status 400
        return { :error => "Key is invalid: #{params[:public_key]}" }.to_json
    end
    ips = []
    Entry.first(:public_key => params[:public_key]).ips.all.each do |ip|
        ips.push(ip.ip_addr)
    end
    ips.to_json
end

get '/ban/:ip_to_ban' do
    unless request.ip == ALLOWED_IP
        status 403
        return "Access denied"
    end
    unless params[:ip_to_ban].match /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
        status 400
        return { :error => "IP is invalid: #{params[:ip_to_ban]}" }.to_json
    end

    Ipban.create(:ip_addr => params[:ip_to_ban])
    Ipban.all.to_json
end

get '/unban/:ip_to_ub' do
    unless request.ip == ALLOWED_IP
        status 403
        return "Access denied"
    end
    unless params[:ip_to_ub].match /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
        status 400
        return { :error => "IP is invalid: #{params[:ip_to_ub]}" }.to_json
    end

    Ipban.first(:ip_addr => params[:ip_to_ub]).destroy
    Ipban.all.to_json
end


DataMapper.auto_upgrade!
