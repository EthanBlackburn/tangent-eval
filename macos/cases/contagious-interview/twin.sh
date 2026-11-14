# The same kinds of acts, by the person, on their own work: they clone a real
# project they mean to contribute to, install its dependencies and run its
# tests, and look up their public address with the service the backdoor asks.
cd ~/code
git clone https://github.com/expressjs/cors.git
cd cors
npm install
npm test
curl -s http://ip-api.com/json | python3 -m json.tool
