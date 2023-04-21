date=$(date +"%Y/%m/%d")
read -p "enter your names:" name

echo ".........hi ${name}............"
sudo lynis audit system --logfile ./log/lynisLog_${date}.log --auditor ${name}

#sudo chmod +rx ./lynisLog_${date}.log
