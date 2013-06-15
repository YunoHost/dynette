#!/usr/bin/ruby

require 'rubygems'
require 'sinatra'
require 'data_mapper'
require 'json'

DataMapper.setup(:default, ENV['DATABASE_URL'] || "pgsql://root:yayaya@localhost/dynette")
DOMAIN = "yoyoyo.fr"
ALLOWED_IP = "82.242.206.127"

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

get '/' do
    `whoami`
end

post '/' do
    content_type :json
    # Check params
    status 400
    return { :error => "Please indicate a subdomain" }.to_json unless params.has_key?("subdomain")
    return { :error => "Please indicate a public key" }.to_json unless params.has_key?("public_key")
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

put '/' do
    content_type :json
    # Check params
    status 400
    return { :error => "Please indicate a public key" }.to_json unless params.has_key?("public_key")
    return { :error => "Key is invalid: #{params[:public_key]}" }.to_json unless params[:public_key].match /^[a-z0-9]{22}==$/i

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

get '/all' do
    unless request.ip == ALLOWED_IP
        status 403
        return "Access denied"
    end
    content_type :json
    Entry.all.to_json
end

get '/ips' do
    unless request.ip == ALLOWED_IP
        status 403
        return "Access denied"
    end
    content_type :json
    Entry.first(:public_key => params[:public_key]).ips.ip_addr.to_json
end


DataMapper.auto_upgrade!
