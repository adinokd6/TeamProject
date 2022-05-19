import json
import numpy as np
import matplotlib.pyplot as plt


#option=1
#a=2002
#b=2005


def level_histogram(a,b,option):
    version='2.0'
    low, med, hig, cri=0, 0, 0 , 0
    lst=['LOW','MEDIUM', 'HIGH']
    if(option):
        lst.append('CRITICAL')
        version='3.1'

    for rok in range(a,b):
        with open('json/nvdcve-1.1-'+str(rok)+'.json', 'r', encoding='utf-8') as myfile1:
            data = json.load(myfile1)
            for i in range(len(data["CVE_Items"])):
                try:
                    if version=='3.1' and list(data["CVE_Items"][i]["impact"].keys())[0] == "baseMetricV3":
                        if data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"] == 'LOW':
                            low += 1
                            lst.append('LOW')
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"] == 'MEDIUM':
                            med+= 1
                            lst.append('MEDIUM')
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"] == 'HIGH':
                            hig += 1
                            lst.append('HIGH')
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"] == 'CRITICAL':
                            cri+= 1
                            lst.append('CRITICAL')
                    if version=='2.0' and list(data["CVE_Items"][i]["impact"].keys())[0] == "baseMetricV2":
                        if data["CVE_Items"][i]["impact"]["baseMetricV2"]["severity"] == 'LOW':
                            low += 1
                            lst.append('LOW')
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["severity"] == 'MEDIUM':
                            med+= 1
                            lst.append('MEDIUM')
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["severity"] == 'HIGH':
                            hig += 1
                            lst.append('HIGH')
                except IndexError:
                    pass

    print("Low=", low)
    print("Medium=", med)
    print("High=", hig)
    if option:
        print("Critical=", cri)

    #histogram

    plt.hist(lst)
    labels, counts = np.unique(lst, return_counts=True)
    plt.bar(labels, counts, align='center')
    plt.gca().set_xticks(labels)
    plt.title("Histogram for "+str(a)+'-'+str(b)+', version '+version)
    plt.xlabel("Flags")
    plt.ylabel("Amount")
    plt.grid(axis='y', alpha=0.75)

    plt.tight_layout()

    plt.savefig('histograms/histogram_level_'+str(a)+'-'+str(b)+'_'+version+'.pdf')

    plt.show()

def score_histogram(a, b,option):
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
    plt.savefig('histograms/histogram_score_'+str(a)+'-'+str(b)+'_'+version+'.pdf')
    plt.show()

def draw_histograms(a,b):
    level_histogram(a,b,0)
    level_histogram(a,b,1)
    score_histogram(a,b,0)
    score_histogram(a,b,1)


a = int(input("select start dates (2002-2022): "))
b = int(input("select end dates (2002-2022): "))

draw_histograms(a,b)
