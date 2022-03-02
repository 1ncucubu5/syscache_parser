#!/usr/bin/python3
import csv
with open("out.csv", encoding='utf-8') as csv_file:
    file = csv.reader(csv_file, delimiter = ',')
    count = 0
    txt_file = open("syscaches.txt", 'w')
    for row in file:
        if count == 0:
            count += 1
        else:
            txt_file.write(row[1] + '\n')
            count += 1


