require "sinatra"
require "sinatra/flash"

enable :sessions

require "./helpers"
require "./models"
require "./report"

run Sinatra::Application
