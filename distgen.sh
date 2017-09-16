#!/bin/bash
SRC_DIR=src
DIST_DIR=dist
sudo rm $DIST_DIR -rf
mkdir $DIST_DIR
cp $SRC_DIR/* $DIST_DIR
rm $DIST_DIR/*.o
rm $DIST_DIR/intangd
rm $DIST_DIR/distgen.sh
cp $SRC_DIR/tools/parse_log.py $DIST_DIR/
cp $SRC_DIR/tools/dump_stats_from_log.py $DIST_DIR/
cp $SRC_DIR/tools/dump_stats_from_log2.py $DIST_DIR/
cp $SRC_DIR/tools/dump_stats.py $DIST_DIR/
cp $SRC_DIR/tools/dump_stats2.py $DIST_DIR/
cp $SRC_DIR/tools/tools.py $DIST_DIR/
cp $SRC_DIR/tools/measure_ttl.py $DIST_DIR/
cp $SRC_DIR/tools/measure_all_ttl.py $DIST_DIR/
cp $SRC_DIR/tools/measure_all_ttl_dns.py $DIST_DIR/
cp $SRC_DIR/test/*.sh $DIST_DIR/
cp $SRC_DIR/test/*.py $DIST_DIR/
tar zcvf intang.tar.gz $DIST_DIR
#zip -qr intang.zip $DIST_DIR
sudo rm $DIST_DIR -rf
echo "Done."

