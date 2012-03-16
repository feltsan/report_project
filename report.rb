#require 'rubygems'
#require 'sinatra'
require 'date'
require 'haml'
#require "sinatra/flash"
#require "sinatra/base"

WORK_TYPES = {
        1 => "self-deployment",
        2 => "working",
        3 => "extra",
        4 => "team"

}

#set utf-8 for outgoing
before do
  headers "Content-Type"=>"text/html;charset=utf-8"
end

get "/" do
  erb :login
end

get '/rooms/:date' do |d|
  @date = Date.parse d
  haml :rooms
end


get '/list' do
  @title = "Reports list"
  @records = Record.all
  erb :list
end

get '/new' do
  @title = "Add report"
  @projects=Project.all

  erb :new
end

post '/create' do
  @record = Record.new(params[:record])
#  @record.content_type = params[:image][:type]
#  raise params.inspect
  @record.project_id = params[:project_id]
  @record.type = params[:type]
  if  params[:HH] != "" and params[:MM] != "" and params[:description] != "" and params[:HH].to_i < 23 and
          params[:MM].to_i < 60
    @record.time = params[:HH].to_i * 60 + params[:MM].to_i
    @record.description = params[:description]
    @record.save
    # path = File.join(Dir.pwd,"/public/records", @record.description)
    #  File.open(path , "wb") do |f|
    #   f.write(params[:image][:tempfile].read)
    #end
    # redirect("/show/#{@record.id}")
    #else
    redirect('/list')
#end
  else
    @error = "No correct time format or clear activity!!!"
    @title = "Add report"
    @projects=Project.all
    erb :new
  end

end

get '/delete/:id' do
  record = Record.get(params[:id])
  #path = File.join(Dir.pwd,"/public/ads",record.description)
  #File.delete(path)
  unless record.nil?
    record.destroy
  end
  redirect('/list')
end

get '/show/:id' do
  @record = Record.get(params[:id])
  if @record
    erb :show
  else
    redirect('/list')
  end
end


get "/signup" do
  erb :signup
end

post "/signup" do
  user = User.create(params[:user])
  user.password_salt = BCrypt::Engine.generate_salt
  user.password_hash = BCrypt::Engine.hash_secret(params[:user][:password], user.password_salt)
  if user.save
    flash[:info] = "Thank you for registering #{user.email}"
    session[:user] = user.token
    redirect "/"
  else
    session[:errors] = user.errors.full_messages
    redirect "/signup?" + hash_to_query_string(params[:user])
  end
end

get "/login" do
  if current_user
    redirect "/rooms/#{Date.today}"
  else
    erb :login
  end
end

post "/login" do
  if user = User.first(:email => params[:email])
    if user.password_hash == BCrypt::Engine.hash_secret(params[:password], user.password_salt)
      session[:user] = user.token
      response.set_cookie "user", {:value => user.token, :expires => (Time.now + 52*7*24*60*60)} if params[:remember_me]
      redirect "/rooms/#{Date.today}"
    else
      flash[:error] = "Email/Password combination does not match"
      redirect "/login?email=#{params[:email]}"
    end
  else
    flash[:error] = "That email address is not recognised"
    redirect "/login?email=#{params[:email]}"
  end
end

get "/logout" do
  current_user.generate_token
  response.delete_cookie "user"
  session[:user] = nil
  flash[:info] = "Successfully logged out"
  redirect "/"
end

get "/secret" do
  login_required
  "This is a secret secret"
end

get "/supersecret" do
  admin_required
  "Well done on being super special. You're a star!"
end

get "/personal/:id" do
  is_owner? params[:id]
  "<pre>id: #{current_user.id}\nemail: #{current_user.email}\nadmin? #{current_user.admin}</pre>"
end
