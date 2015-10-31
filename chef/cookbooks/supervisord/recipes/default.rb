#
# Cookbook Name:: supervisord
# Recipe:: default
#
# Copyright 2015, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#

file "/etc/supervisor/conf.d/perl.conf" do
  content <<END
[program:perl]
directory=/home/isucon/webapp/perl
command=/home/isucon/env.sh carton exec -- start_server --port 8080 -- plackup -s Gazelle -p 8080 --max-workers 10 --max-reqs-per-child=100000 --min-reqs-per-child=100000 app.psgi
user=isucon
stdout_logfile=/tmp/isucon.perl.log
stderr_logfile=/tmp/isucon.perl.log
autostart=true
END
  notifies :restart, "service[supervisor]"
end

file "/etc/supervisor/conf.d/ruby.conf" do
  content <<END
[program:ruby]
directory=/home/isucon/webapp/ruby
command=/home/isucon/env.sh bundle exec unicorn -c ./unicorn_config.rb
user=isucon
stdout_logfile=/tmp/isucon.ruby.log
stderr_logfile=/tmp/isucon.ruby.log
# turn this to false for other languages
autostart=false
END
  notifies :restart, "service[supervisor]"
end

service "supervisor" do
  action [:start, :enable]
end

