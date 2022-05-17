import json
import numpy as np
import matplotlib.pyplot as plt

def score_histogram(option, a, b):
    version='2.0'
    if(option):
        version='3.1'
    labels=[];
    values=[];
    for i in range(0, 100):
        labels.append(i/10);
        values.append(0);
    for rok in range(a,b):
        with open('json/nvdcve-1.1-'+str(rok)+'.json', 'r', encoding='utf-8') as myfile1:
            data = json.load(myfile1)
            for i in range(len(data["CVE_Items"])):
                try:
                    if version=='3.1' and list(data["CVE_Items"][i]["impact"].keys())[0] == "baseMetricV3":
                        tmp=data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"];
                        values[int(tmp*10)]+=1;
                    if version=='2.0'and list(data["CVE_Items"][i]["impact"].keys())[0] == "baseMetricV2":
                        tmp=data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["baseScore"];
                        values[int(tmp*10)]+=1;
                except IndexError:
                    pass

    #histogram
    plt.bar(labels, values, 0.1, align='center')
    #plt.gca().set_xticks(labels)
    plt.title("Histogram for "+str(a)+'-'+str(b)+', version '+version)
    plt.xlabel("Flags")
    plt.ylabel("Amount")
    plt.grid(axis='y', alpha=0.75)

    plt.tight_layout()
    plt.savefig('histograms/histogram_'+str(a)+'-'+str(b)+'_'+version+'.pdf')
    plt.show()

option=int(input("slect CVSS 2.0 [0] \nor CVSS 3.1 [1]: "))
a = int(input("select start dates (2002-2022): "))
b = int(input("select end dates (2002-2022): "))

score_histogram(option, a, b);
