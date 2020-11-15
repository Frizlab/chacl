#!/bin/bash

cd "$(dirname "$0")"

chmod +a 'user:frizlab allow read' with_acls\ 
chmod +a 'group:staff deny read' with_acls\ 
chmod +a 'user:spotlight allow read' with_acls\ 
