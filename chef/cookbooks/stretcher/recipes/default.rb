#
# Cookbook Name:: stretcher
# Recipe:: default
#
# Copyright 2015, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#


bash "install stretcher" do
  cwd "/tmp"
  code <<END
curl -sLO https://github.com/fujiwara/stretcher/releases/download/v0.2.0/stretcher-v0.2.0-linux-amd64.zip
unzip stretcher-v0.2.0-linux-amd64.zip
install stretcher-v0.2.0-linux-amd64 /usr/local/bin/stretcher
END
  not_if "/usr/local/bin/stretcher --version | fgrep 0.2.0"
end

file "/usr/local/bin/stretcher" do
  owner "root"
  group "root"
  mode "755"
end
