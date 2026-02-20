curl "http://94.237.122.188:51144/search.php?search=cairo" -H 'Authorization: Basic YWRtaW46YWRtaW4='


curl -X POST -d 'username=admin&password=admin' http://<SERVER_IP>:<PORT>/

curl -H 'Cookie: PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' http://<SERVER_IP>:<PORT>/

curl -X POST -d '{"search":"london"}' -b 'PHPSESSID=c1nsa6op7vtk7kdis7bcnbadf1' -H 'Content-Type: application/json' http://<SERVER_IP>:<PORT>/search.php


curl -X PUT http://<SERVER_IP>:<PORT>/api.php/city/london -d '{"city_name":"New_HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'

curl -X DELETE http://<SERVER_IP>:<PORT>/api.php/city/New_HTB_City


To use proxychains, we first have to edit /etc/proxychains.conf, comment out the final line and add the following line at the end of it:

#socks4         127.0.0.1 9050
http 127.0.0.1 8080

proxychains -q curl http://SERVER_IP:PORT

