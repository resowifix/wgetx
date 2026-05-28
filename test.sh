./wgetx http://perdu.com
wget http://perdu.com -O toto.html -o /dev/null
diff index.html toto.html

./wgetx http://perdu.com/
wget http://perdu.com/ -O toto.html -o /dev/null
diff index.html toto.html

./wgetx https://perdu.com
wget https://perdu.com -O toto.html -o /dev/null
diff index.html toto.html

./wgetx https://perdu.com/
wget https://perdu.com/ -O toto.html -o /dev/null
diff index.html toto.html
