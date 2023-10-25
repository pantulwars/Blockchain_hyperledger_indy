# Blockchain_hyperledger_indy
Note: for first time execute all the commands, then for next time only run commands marked with *

*1. docker ps 

*2. Easier way to start indy pool:

docker run -itd -p 9701-9708:9701-9708 mailtisen/indy_pool:latest 

3. Set up Indy:

sudo apt-get install ca-certificates -y 

sudo apt-get update 

4. alternative keyserver: hkp://keyserver.ubuntu.com:80

sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys CE7709D068DB5E88 

5. sudo add-apt-repository "deb https://repo.sovrin.org/sdk/deb bionic master" 

6. sudo apt-get update 

7. I had to run the following command, but you may or may not require it, so first run point 8, and if it gives an error, you can try this:

echo "deb http://security.ubuntu.com/ubuntu focal-security main" | sudo tee /etc/apt/sources.list.d/focal-security.list 

sudo apt-get update 

sudo apt-get install libssl1.1 

8. sudo apt-get install -y libindy 

9. sudo apt install python3-pip 

 pip3 install python3-indy  

*10. docker ps 

*11. docker exec -it 8b8863aaef4c bash 

Here, replace 8b8863aaef4c with the output from line 10's command 

12. tail -f /var/log/indy/sandbox/Node1.log 

13. ls /var/lib/indy/sandbox/ 

*14. cat /var/lib/indy/sandbox/pool_transactions_genesis 


On executing line 14, you will have to copy the output to genesis_txn.txn in the code folder and then execute main.py 
