#!/bin/bash

function __readini()
{   
    FILENAME="config.ini"
    SECTION=$1; KEY=$2
    RESULT=`awk '/\['$SECTION'\]/{a=1}a==1&&$1~/'$KEY'/{print $0}' $FILENAME | awk -F '=' '{print $2;exit}'`
    echo $RESULT
}

function __get_sts {
    kubectl get sts -n "$1" "$2" | awk -v s="$2" 'BEGIN{ok=1}{if($1==s){split($2,a,"/");if(a[1]==a[2]){ok=0;exit 0}}}END{exit ok}'
}

#等待sts running, 超时1分钟
function __wait_sts {
    timeout=true
    for i in {1..6}; do
        echo "check $1/$2 sleep 10s"
        sleep 10
        if __get_sts "$1" "$2"; then
            timeout=false
            break
        fi
    done
    if [[ "$timeout" == true ]]; then
        echo "check $1/$2 timeout"
        exit 1
    fi
    echo "$1/$2: ready"
}

function __generate_password {
     password=$(tr -dc '_A-Za-z0-9'  </dev/urandom  | head -c  24)
     echo $password
}