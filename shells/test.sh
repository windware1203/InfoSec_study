date=$(date +"%Y_%m_%d")
fileName="./log/lynisLog_${date}.log"

read -p "enter your names:" name

echo ".........hi ${name}............"

sudo lynis audit system --logfile ${fileName} --auditor ${name}

sudo chmod +rwx ${fileName}
#sudo echo "Auther:${name} at${date}" >> ${fileName}
