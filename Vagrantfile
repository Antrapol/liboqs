
# Install in Mac M-class chip
# > brew install qemu
# > brew install --cask vagrant
# > vagrant plugin install vagrant-qemu

Vagrant.configure("2") do |config|
  config.vm.box = "cloud-image/ubuntu-24.04"
  config.vm.provider "qemu" do |qe|
    qe.ssh_port = "50022" # change ssh port as needed
  end

  config.vm.synced_folder ".", "/opt/liboqs"

  config.vm.provision "shell", inline: <<-SHELL, privileged: true
    apt-get update && apt-get install -y git curl build-essential software-properties-common astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind libgmp-dev
  SHELL
end

# > vagrant up --provider=qemu
# > vagrant ssh
