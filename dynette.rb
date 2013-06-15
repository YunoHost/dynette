#!/usr/bin/ruby

require 'rubygems'
require 'sinatra'
require 'data_mapper'
require 'json'

DataMapper.setup(:default, ENV['DATABASE_URL'] || "pgsql://root:yayaya@localhost/dynette")
DOMAIN = "yoyoyo.fr"

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
    unless params[:subdomain].match /^[a-z0-9-]{3,16}$/
        status 400
        return { :error => "Subdomain is invalid: #{params[:subdomain]}.#{DOMAIN}" }
    end
    unless params[:public_key].match /^[a-z0-9]{22}==$/i
        status 400
        return { :error => "Key is invalid: #{params[:public_key]}" }
    end
    unless params[:current_ip].match /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
        status 400
        return { :error => "Key is invalid: #{params[:current_ip]}" }
    end

    # If already exists
    if entry = Entry.first(:subdomain => params[:subdomain])
        status 409
        return { :error => "Subdomain already taken: #{entry.subdomain}.#{DOMAIN}" }
    end
    if entry = Entry.first(:public_key => params[:public_key])
        status 409
        return { :error => "Key already exists for domain #{entry.subdomain}.#{DOMAIN}" }
    end
    entry = Entry.new(:public_key => params[:public_key], :subdomain => params[:subdomain], :current_ip => request.ip)
    entry.ips << Ip.create(:ip_addr => request.ip)
    if entry.save
        status 201
        return { :public_key => params[:public_key], :subdomain => params[:subdomain], :current_ip => request.ip }.to_json
    else
        status 412
        return { :error => "A problem occured during DNS registration" }
    end
end

get '/all' do
    unless request.ip == "82.242.206.127"
        status 403
        return "Access denied"
    end
    content_type :json
    Entry.all.to_json
end

DataMapper.auto_upgrade!
