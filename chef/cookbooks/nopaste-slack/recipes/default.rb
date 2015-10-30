#
# Cookbook Name:: nopaste-slack
# Recipe:: default
#
# Copyright 2015, YOUR_COMPANY_NAME
#
# All rights reserved - Do Not Redistribute
#

bash "download nopaste-slack" do
  cwd "/tmp"
  code "curl -O /usr/local/bin/nopaste-slack https://storage.googleapis.com/isucon5-fujiwaragumi/nopaste-slack"
  not_if "test -e /usr/local/bin/nopaste-slack"
end

file "/usr/local/bin/nopaste-slack" do
  owner "root"
  group "root"
  mode  "755"
end
