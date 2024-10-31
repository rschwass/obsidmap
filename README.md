# obsidmap

### Install

This tool requires Obsidian (duh!), the Dataview plugin, and the local rest API plugin (obsidian://show-plugin?id=obsidian-local-rest-api).

you must configure the following info from your local rest api settings in obsidian.
1. set the "obsidian_apikey" env variable in your ~/.bashrc file

```bash

export obsidian_apikey="abcdefghijklmnop...."


```

2. source ~/.bashrc

```bash

source ~/.bashrc

```

3. Make changes to your nmap command and comment out the one you dont need. 


```bash

#For windows nmap under wsl
command = %Q|cmd.exe /c nmap -sV -p- --open #{ARGV.join(' ')} -oX -|

#For Linux
command = %Q|nmap -sV -Pn -p- --open #{ARGV.join(' ')} -oX -|

```

Here is the dataview code
```
```dataview
table hostname, open_ports, ip from #asset 
```
```


Runs on ruby and you must install:

Nokogiri 

```
sudo gem isntall nokogiri
```

### Usage
```
ruby obsidimap.rb <host>
```