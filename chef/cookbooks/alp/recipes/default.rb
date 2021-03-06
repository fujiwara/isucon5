#
# Cookbook Name:: alp
# Recipe:: default
#
# Copyright 2015, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#


bash "install alp" do
  cwd "/tmp"
  code <<END
curl -sLO https://github.com/tkuchiki/alp/releases/download/v0.1.0/alp_linux_amd64.zip
unzip alp_linux_amd64.zip
install alp_linux_amd64 /usr/local/bin/alp
END
  not_if "/usr/local/bin/alp --version 2>&1 | fgrep 0.1.0"
end

file "/usr/local/bin/alp" do
  owner "root"
  group "root"
  mode "755"
end
