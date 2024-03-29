require 'dm-core'
require 'dm-timestamps'
require "dm-migrations"
require "data_mapper"
require "bcrypt"
require "securerandom"

DataMapper::setup(:default, "sqlite3://#{Dir.pwd}/report.db")

class User
  include DataMapper::Resource

  attr_accessor :password, :password_confirmation

  property :id,             Serial
  property :email,          String,     :required => true, :unique => true, :format => :email_address
  property :password_hash,  Text
  property :password_salt,  Text
  property :token,          String
  property :created_at,     DateTime
  property :admin,          Boolean,    :default => false

  validates_presence_of         :password
  validates_confirmation_of     :password
  validates_length_of           :password, :min => 6

  after :create do
    self.token = SecureRandom.hex
  end

  def generate_token
    self.update!(:token => SecureRandom.hex)
  end

  def admin?
    self.admin
  end

end


class Project

  include DataMapper::Resource

  property :id, Serial
  property :name, String

  has n, :records

end

class Record

  include DataMapper::Resource

  property :id, Serial
  property :type, Integer
  property :description, String
  property :time, Integer

  belongs_to :project, :required => false

end


#Create or upgrade all tables at once,like magic
DataMapper.auto_upgrade!
