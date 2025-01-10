SCRIPT_DIR=$(dirname "$(readlink -f "$0")")/..

# 6am every monday
(crontab -l; echo "\
0 6 * * 1 . $HOME/.bashrc; (bash $SCRIPT_DIR/run_gossip.sh) \
") | crontab

echo "Cron job added. Current crontab:"
crontab -l
