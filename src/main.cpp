#include <fstream>
#include<iostream>
#include<string>
#include<vector>
#include<unordered_map>


enum class EventType{ AuthFailure, SudoSuccess, Other};


class LogEvent{
    public:
        LogEvent(const std::string& timestamp, const std::string&user, EventType type):
            timestamp_(timestamp), user_(user), type_(type){}

        const std::string& timestamp() const { return timestamp_;}
        const std::string& user() const{return user_;}
        EventType type() const{ return type_;}
    
    private:
        std::string timestamp_;
        std::string user_;
        EventType type_;


};

LogEvent parseLine(const std::string& line){
    std::string timestamp = line.substr(0, 15);
    std::string user;
    EventType type =EventType::Other;

    if (line.find("authentication failure") != std::string::npos){
        type= EventType::AuthFailure;
        size_t pos = line.rfind("user=");
        if (pos != std::string::npos){
            user = line.substr(pos + 5);
        }
    } else if (line.find("COMMAND=") != std::string::npos &&
               line.find("incorrect password attempts") == std::string::npos){
                type = EventType::SudoSuccess;
               }
               return LogEvent(timestamp, user, type);
}

int main(){
    std::ifstream file("data/sudo_events.txt");
    if(!file){
        std::cerr<<"could not opent data/sudo_events.txt\n";
        return 1;
    }    
   std::vector<LogEvent> events;
    std::string line;
    while (std::getline(file, line)){
        events.push_back(parseLine(line));
    }
    std::cout<<"Parsed" <<events.size() << "events\n";
    std::unordered_map<std::string, int> failureByUser;

    int failures = 0;
    int successes = 0;
    for (const LogEvent& ev : events){
        if(ev.type() == EventType::AuthFailure){
            ++failures;
            failureByUser[ev.user()]++;
            std::cout <<ev.timestamp()<< " FAIL user="<< ev.user()<< "\n";
        } else if (ev.type() == EventType::SudoSuccess){
            ++successes;
        }
    }
    for (const auto& pair : failureByUser){
        std::cout<< pair.first<<": "<<"faulures\n";
    }
    std::cout<<"failures: "<<failures <<"\n";
    std::cout<<"successes: "<<successes<<"\n";
    return 0;
}