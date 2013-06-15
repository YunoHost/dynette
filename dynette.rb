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

#get '/' do
    #`whoami`
#end

post '/' do
    content_type :json
    # TODO: check params
    if entry = Entry.first(:public_key => params[:public_key])
        status 409
        return { :error => "Key already exists for domain #{entry.subdomain}.#{DOMAIN}" }
    end
    entry = Entry.new(:public_key => params[:public_key], :subdomain => params[:subdomain], :current_ip => request.ip)
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
