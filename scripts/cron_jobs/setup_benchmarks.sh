SCRIPT_DIR=$(dirname "$(readlink -f "$0")")/..

# 6am everyday
(crontab -l; echo "\
0 6 * * * . $HOME/.bashrc; (bash $SCRIPT_DIR/collect_benchmarks.sh) 2>&1 | logger -t sig_bench \
") | crontab

echo "Cron job added. Current crontab:"
crontab -l
