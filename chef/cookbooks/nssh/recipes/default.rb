filename = "nssh-%s-linux-%s" % [ node[:nssh][:version], node[:nssh][:arch] ]
download_url = "https://github.com/fujiwara/nssh/releases/download/%s/%s.zip" % [ node[:nssh][:version], filename ]

bash "download nssh" do
  cwd "/tmp"
  user "root"
  code <<-EOF
    curl -L "#{download_url}" > #{filename}.zip
    unzip #{filename}.zip
    install #{filename} /usr/local/bin/nssh
  EOF
  not_if "/usr/local/bin/nssh -v | grep 'version: #{node[:nssh][:version]}'"
end

cookbook_file "/usr/local/bin/nssh-consul" do
  source "nssh-consul"
  owner "root"
  group "root"
  mode 0755
end
