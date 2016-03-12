

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local httpspider=require "httpspider"
local string = require "string"

description=[[ Uses version infomation aquired during nmap scans to lookup metasploit modules and possible exploits for the software.]]
author="Tabish Imran"
license="Same as Nmap--See http://nmap.org/book/man-legal.html"
categories={"safe"}

---
-- @usage
-- nmap -sV --script metasploit_lookup.nse <host>
--
-- @output
-- PORT     STATE SERVICE         VERSION
-- 23/tcp   open  telnet          Linux telnetd
-- | metasploit-module-lookup: 
-- |   https://www.rapid7.com/db/modules/exploit/linux/telnet/telnet_encrypt_keyid
-- |_  |-->Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow |
-- 25/tcp   open  smtp            Sendmail 8.9.3/8.9.3
-- | metasploit-module-lookup:  
-- |   https://www.rapid7.com/db/modules/auxiliary/dos/smtp/sendmail_prescan
-- |   |-->Sendmail SMTP Address prescan Memory Corruption |
-- | 
-- |   https://www.rapid7.com/db/modules/post/linux/gather/enum_configs
-- |_  |-->Linux Gather Configurations |
-- 80/tcp   open  http            Apache httpd
-- | metasploit-module-lookup: 
-- |   https://www.rapid7.com/db/modules/exploit/windows/http/apache_chunked
-- |   |-->Apache Win32 Chunked Encoding |
-- | 
-- |   https://www.rapid7.com/db/modules/auxiliary/scanner/http/mod_negotiation_scanner
-- |   |-->Apache HTTPD mod_negotiation Scanner |
-- | 
-- |   https://www.rapid7.com/db/modules/auxiliary/scanner/http/mod_negotiation_brute
-- |_  |-->Apache HTTPD mod_negotiation Filename Bruter |
-- 



portrule = function(host,port)
  return port
end

get_results = function(host,port,explt_query)
  list={}
  count=1
  y=http.parse_url(explt_query)
  response=http.get(y.host,80,y.original)
  search=response.body
  for i in string.gmatch(search,"db/modules/[%s%w-_%/().]*%p%p%w%w[%s%w-_%/().]*")  do
    i=i.gsub(i,"\'>","\n  |-->")
    list[count]=rapid7..i.." |\n"
    count=count+1
  end
  return(list)
end




action = function(host,port)
  list={}
  if(port.version.product==nil) then
    port.version.product=""
  end
  if(port.version.version==nil) then
    port.version.version=""
  end
  if(string.len(port.version.product..port.version.version)<3) then
    return("No version data available ")
  else
    rapid7="https://www.rapid7.com/"
    explt_query="https://www.rapid7.com/db/search?utf8=%E2%9C%93&q="..port.version.product.." "..port.version.version.."&t=m" 
    explt_query=string.gsub(explt_query," ","+")
    list=get_results(host,port,explt_query)
    if(list[1]==nil) then
      explt_query="https://www.rapid7.com/db/search?utf8=%E2%9C%93&q="..port.version.product.."&t=m"  
      explt_query=string.gsub(explt_query," ","+")
      list=get_results(host,port,explt_query)
      if(list[1]==nil) then
        return("No results aquired ")
      end
    end
    return(list)
  end
end
