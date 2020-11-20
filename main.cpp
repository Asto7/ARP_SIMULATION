#include <bits/stdc++.h> 
#include <thread> 
#include <unistd.h> 
#define buffer_size 2

using namespace std; 


class node;

int nodeId = 1, switchId = 1;


class ARP{
    public:
    string senderIp, senderMac,  destIP, destMac,  operationCode, hardwareType, protocolType, hardwareLength, protocolLength;
    ARP( string senderIp, string senderMac, string destIP, string destMac, string operationCode){
        this->senderIp = senderIp;
        this->senderMac = senderMac;
        this->destIP = destIP;
        this->destMac = destMac; 
        this->operationCode = operationCode;

        this->hardwareType = "1";
        this->protocolType = "0x0800";

        this->hardwareLength = "6";
        this->protocolLength = "4";
    }

    void printArp(){
        cout << "\t\t" << operationCode << " Packet:" << endl;
        cout << "\t\t-------------------------------------------------------------------------------------------------------------------------------------------------\n";
        cout << "\t\t|\tSource Ip address\t|\tSource Mac Address\t|\tDest IP Address\t|\tDest Mac Address\t|\tOperation Code\t|\n";
        cout << "\t\t-------------------------------------------------------------------------------------------------------------------------------------------------\n";
        cout << "\t\t|\t" << senderIp << "      \t|\t" << senderMac << "\t|\t" << destIP << "\t|\t" << destMac << "\t|\t" << operationCode << "\t|" << endl;
        cout << "\t\t-------------------------------------------------------------------------------------------------------------------------------------------------\n";

        cout << "\t\t-------------------------------------------------------------------------------------------------\n";
        cout << "\t\t|\tHardware Type\t|\tHardware Length\t|\tProtocol Type\t|\tProtocol Length\t|\n";
        cout << "\t\t-------------------------------------------------------------------------------------------------\n";
        cout << "\t\t|\t    " << hardwareType << "       \t|\t  " << hardwareLength << "        \t|\t   " << protocolType << "  \t|\t   " << protocolLength << "        \t|" << endl;
        cout << "\t\t-------------------------------------------------------------------------------------------------\n";
      }
};

class Switch{
    public:
    int id;
    string switch_name;
    vector<node*> neighbours;

    Switch(string name){
        this->id = switchId;
        switchId++;
        switch_name = name;
    }
    vector<ARP> redirect;
};

class node{
    public:
    int id;
    string mac, ip;

    int numberOfArpRequests;
    vector<string> requests;


    vector<ARP> responses;

    Switch *server;

    unordered_map<string, string> arp_cache;

    node(string mac, string ip, Switch *server){
        this->id = nodeId;
        nodeId++;
        this->mac = mac;
        this->ip = ip;
        this->numberOfArpRequests = 0;
        this->server = server;
        server->neighbours.push_back(this);
    }

    int storeRequest(string senderIpAddress){
        requests.push_back(senderIpAddress);
    }

    void printCache(){
        cout << "\t\tARP CACHE OF client" << id << ":" << endl;
        cout << "\t\t-------------------------------------------------\n";
        cout << "\t\t|\tIp address\t|\tMac Address\t|\n";
        cout << "\t\t-------------------------------------------------\n"; 
        for(auto i = arp_cache.begin(); i != arp_cache.end(); i++){
            cout << "\t\t|\t" << (*i).first << "\t|   " << (*i).second << "   |"  << endl;
        }
        cout << "\t\t-------------------------------------------------\n";
    }

};


void print_buffer_overflow(node *client){
    cout << "Client " << client->id <<": is dropping the packet due to BUFFER OVERFLOW\n";
}

unordered_map<int, node*> idToNode;
unordered_map<int, Switch*> idToSwitch;

void printClients(){
    cout << "\t\t" << "Total Clients" <<  endl;
    cout << "\t\t-------------------------------------------------------------------------\n";
    cout << "\t\t|\tClient Id\t|\tIp address\t|\tMac Address\t|\n";
    cout << "\t\t-------------------------------------------------------------------------\n";    
    for(auto i = idToNode.begin(); i != idToNode.end(); i++){
        cout << "\t\t|\t" << (*i).first << "         \t|\t" << (*i).second->ip << "\t|   " << (*i).second->mac << "   |" << endl;
    }
    cout << "\t\t-------------------------------------------------------------------------\n";    
}

void* switchFunc(void* arg){
    pthread_detach(pthread_self());
   
    int *id = (int *) arg;
    Switch *server = idToSwitch[*id];

    while(1){
        // sleep(2);
        if(server->redirect.size() > 0){
            ARP back = server->redirect.back();
            server->redirect.pop_back();
            
            cout << endl << endl <<  "*** ARP packet arrives at Network Switch ***" << endl;
            back.printArp();

            if(back.destMac == "ff:ff:ff:ff:ff:ff"){
                cout << endl << "Network Switch: As the destination mac address is ff:ff:ff:ff:ff:ff, so it is broadcast ARP_REQUEST\n";
                cout << endl << "Network Switch:  Broadcasting the ARP PAcket from Network switch\n\n";
                for(int i= 0;i < server->neighbours.size();i++){
                    if(server->neighbours[i]->ip != back.senderIp){
                        if(server->neighbours[i]->responses.size() < buffer_size)
                            server->neighbours[i]->responses.push_back(back);

                        else
                            print_buffer_overflow(server->neighbours[i]);    
                    }
                }
            }

            else{
                cout << endl << "Network Switch:  As the destination mac address is " << back.destMac << ", so it is Unicast ARP_REPLY\n";
                cout << endl << "Network Switch:  SENDING the ARP_REPLY to client with mac = " << back.destMac << endl << endl;
                for(int i= 0;i < server->neighbours.size();i++){
                    if(server->neighbours[i]->mac == back.destMac)
                    {
                        if(server->neighbours[i]->responses.size() < buffer_size)
                            server->neighbours[i]->responses.push_back(back);

                        else
                            print_buffer_overflow(server->neighbours[i]);    
                    }
                }
            }
                
        }
    }

    pthread_exit(NULL);
}

void* nodeFunc(void* arg){
    pthread_detach(pthread_self());
    int *id = (int *) arg;
    node *client = idToNode[*id];
    
    while(1){    
       
       
       
        if(client->requests.size() > 0){
            string senderIpAddress = client->requests.back();
            client->requests.pop_back();
            
            cout << endl << "***** Client " << client->id << " request mac Address for the given " + senderIpAddress + " Ip address ******\n\n";
            cout << "Present: \n";
            client->printCache();

            // sleep(1);

            if(client->arp_cache.find(senderIpAddress) != client->arp_cache.end()){
                cout << endl;
                cout << "MAC Address for the sender Ip Address ( " << senderIpAddress << " ) is availble in the cache of Client " << client->id <<". So no need to send Arp request\n"; 
            }   else{
                cout << endl;
                cout << "MAC Address for the sender Ip Address ( " << senderIpAddress << " ) is not availble in the cache of Client " << client->id <<". So there's need to send Arp request\n"; 
      
                //  senderIp, senderMac,  destIP, destMac,  operationCode
                ARP req(client->ip, client->mac, senderIpAddress, "ff:ff:ff:ff:ff:ff", "ARP_REQUEST");
                req.printArp();

                client->server->redirect.push_back(req);
            }
        }    


        if(client->responses.size() > 0){

            ARP back = client->responses.back();
            client->responses.pop_back();


            cout << endl << "***** Client " << client->id << " receives ARP packet from Network switch ******\n\n";      
            back.printArp();

            client->arp_cache[back.senderIp] = back.senderMac;

            cout << "Updated Arp cache of client " << client->id << endl;
            client->printCache();

            if(back.operationCode == "ARP_RESPONSE"){
                cout << "Client " << client->id << " get back the mac address ( " << back.senderMac << " ) for the IP address ( "<< back.senderIp << " ) "; 
                cout << endl <<endl; 
            } 
            
            else{
                cout << endl;  
                
                if(client->ip != back.destIP){
                    cout << "Client " << client->id << " DROPS THE PACKET AS THE destination IP address ( " << back.destIP << " ) doesn't match with the current client IP Address ( " << client->ip << " ) \n\n";
                }

                else{
                    cout << "Client " << client->id << " IP address ( " << client->ip << " ) matches with the ARP request destination IP Address ( " << back.destIP << " ) \n\n";
                    cout << "Client " << client->id << ": Sending back ARP response to the source IP address of the ARP Request  \n\n";
                    ARP res(client->ip, client->mac, back.senderIp, back.senderMac , "ARP_RESPONSE");
                    res.printArp();
                    client->server->redirect.push_back(res);
                }
            }
        }
        // sleep(2);
    }

    pthread_exit(NULL);
}

int main() 
{ 
  
    Switch *server = new Switch("Main Server");

    pthread_t ptid1;
    int id = server->id;
    pthread_create(&ptid1, NULL, switchFunc, &id);
    idToSwitch[id] = server;

    int type = 1;
    cout << "Press 1: For Inbuilt testCase" << endl;
    cout << "Press 2: For Custom testCase" << endl;    
    
    cin >> type;
    cout << type << endl;
    if(type == 1){

        cout << "In Custom Input There are 3 clients Connected to Network Switch\n" << endl;

        //sleep(1);

        node *client1 = new node("ef:ds:fd:ef:ds:fd", "23.23.23.01", server);
        node *client2 = new node("ed:ds:wd:re:dd:gd", "23.53.33.02", server);
        node *client3 = new node("ed:sd:w3:r0:2d:1d", "22.23.23.03", server);
    
        pthread_t  ptid2, ptid3, ptid4;
    
        int id1 = client1->id;
        pthread_create(&ptid2, NULL, nodeFunc, &id1);
        idToNode[id1] = client1;
        

        int id2 = client2->id;
        pthread_create(&ptid3, NULL, nodeFunc, &id2);
        idToNode[id2] = client2;
    
        int id3 = client3->id;
        pthread_create(&ptid4, NULL, nodeFunc, &id3);
        idToNode[id3] = client3;



        client1->storeRequest(client2->ip);
        client2->storeRequest(client3->ip);
        client3->storeRequest(client1->ip);
        client1->storeRequest(client2->ip);


        while(1){}

        pthread_join(ptid1, NULL); 
        pthread_join(ptid2, NULL); 
        pthread_join(ptid3, NULL); 
        pthread_join(ptid4, NULL);   
    }


    else{

        int numberOfClients = 2;

        cout << "Enter Number of clients\n";
        cin >> numberOfClients;
        cout << numberOfClients << endl;

        pthread_t ptid[numberOfClients];
        
        for(int i = 0; i < numberOfClients; i++){

            string mac = "ef:ds:fd:ef:ds:", ip = "23.23.23.";
            
            if(i >= 10){
                mac += to_string(i);
                ip += to_string(i);
            }

            else{
                mac += "0"+ to_string(i);
                ip += "0"+ to_string(i);
            }

            node *client1 = new node(mac, ip, server);
            int id1 = client1->id;
            pthread_create(&ptid[i], NULL, nodeFunc, &client1->id);
            idToNode[id1] = client1;
        }

        while(1){
            int a = 1;
            cout << "Enter 0 to exit\nEnter 1 to continue ";
            cin >> a;
            cout << a << endl;

            if(a == 0)
                break;

            else{
                printClients();
                cout << endl;
                int sourceId, destId;
                cout <<"\n\nEnter Source Client id ";
                cin >> sourceId;
                cout << sourceId << endl;

                cout <<"\nEnter Destination Client id ";
                cin >> destId;
                cout << destId << endl;

                node *tempClientSource = idToNode[sourceId], *tempDestSource = idToNode[destId];

                cout << " Now Source will find mac Address of the Destination whose Ip address is : ( " << tempDestSource->ip << " )" << endl;
                //sleep(1);
                cout << endl;
                tempClientSource->storeRequest(tempDestSource->ip);
                
            }
            sleep(2);
        }

        pthread_join(ptid1, NULL); 

        for(int i = 0; i < numberOfClients; i++)
            pthread_join(ptid[i], NULL); 

    }
    return 0; 
}
