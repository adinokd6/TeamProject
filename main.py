import json
import numpy as np
import matplotlib.pyplot as plt


#option=1
#a=2002
#b=2005
def flags_histogram(a, b, option):

    if option == 0:
        version = '2.0'
        labels = ['accessVector_local', 'accessVector_Adjacentnetwork', 'accessVector_network', 'accessComplexity_low', 'accessComplexity_medium', 'accessComplexity_high',
                  'authentication_multiple', 'authentication_single', 'authentication_none', 'confidentialityImpact_none', 'confidentialityImpact_partial', 'confidentialityImpact_complete',
                  'integrityImpact_none', 'integrityImpact_partial', 'integrityImpact_complete', 'availabilityImpact_none', 'availabilityImpact_partial', 'availabilityImpact_complete']

        accessVector_network_v2 = 0
        accessVector_local_v2 = 0
        accessVector_Adjacentnetwork_v2 = 0

        accessComplexity_low_v2 = 0
        accessComplexity_medium_v2 = 0
        accessComplexity_high_v2 = 0

        authentication_multiple_v2 = 0
        authentication_single_v2 = 0
        authentication_none_v2 = 0

        confidentialityImpact_none_v2 = 0
        confidentialityImpact_partial_v2 = 0
        confidentialityImpact_complete_v2 = 0

        integrityImpact_none_v2 = 0
        integrityImpact_partial_v2 = 0
        integrityImpact_complete_v2 = 0

        availabilityImpact_none_v2 = 0
        availabilityImpact_partial_v2 = 0
        availabilityImpact_complete_v2 = 0

    elif option == 1:
        version = '3.1'
        labels = ['attackVector_network', 'attackVector_adjacent', 'attackVector_local', 'attackVector_physical', 'attackComplexity_low', 'attackComplexity_high',
                  'privilegesRequired_none', 'privilegesRequired_low', 'privilegesRequired_high', 'userInteraction_none', 'userInteraction_required',
                  'scope_changed', 'scope_unchanged', 'confidentialityImpact_high', 'confidentialityImpact_low', 'confidentialityImpact_none', 'integrityImpact_high',
                  'integrityImpact_low', 'integrityImpact_none', 'availabilityImpact_high', 'availabilityImpact_low', 'availabilityImpact_none']

        attackVector_network_v3 = 0
        attackVector_adjacent_v3 = 0
        attackVector_local_v3 = 0
        attackVector_physical_v3 = 0

        attackComplexity_low_v3 = 0
        attackComplexity_high_v3 = 0

        privilegesRequired_none_v3 = 0
        privilegesRequired_low_v3 = 0
        privilegesRequired_high_v3 = 0

        userInteraction_none_v3 = 0
        userInteraction_required_v3 = 0

        scope_changed_v3 = 0
        scope_unchanged_v3 = 0

        confidentialityImpact_high_v3 = 0
        confidentialityImpact_low_v3 = 0
        confidentialityImpact_none_v3 = 0

        integrityImpact_high_v3 = 0
        integrityImpact_low_v3 = 0
        integrityImpact_none_v3 = 0

        availabilityImpact_high_v3 = 0
        availabilityImpact_low_v3 = 0
        availabilityImpact_none_v3 = 0

    else:
        print('Incorrect option...')
        return


    for rok in range(a, b):

        with open('json/nvdcve-1.1-' + str(rok) + '.json', 'r', encoding='utf-8') as myfile1:
            data = json.load(myfile1)
            for i in range(len(data["CVE_Items"])):
                try:
                    if version=='3.1' and list(data["CVE_Items"][i]["impact"].keys())[0] == "baseMetricV3":
                        if data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["attackVector"] == 'NETWORK':
                            attackVector_network_v3 += 1

                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["attackVector"] == 'ADJACENT':
                            attackVector_adjacent_v3 += 1

                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["attackVector"] == 'LOCAL':
                            attackVector_local_v3 += 1

                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["attackVector"] == 'PHYSICAL':
                            attackVector_physical_v3 += 1

                        if data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"] == 'LOW':
                            attackComplexity_low_v3 += 1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"] == 'HIGH':
                            attackComplexity_high_v3 += 1

                        if data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"] == 'NONE':
                            privilegesRequired_none_v3 += 1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"] == 'LOW':
                            privilegesRequired_low_v3 += 1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"] == 'HIGH':
                            privilegesRequired_high_v3 += 1

                        if data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"] == 'NONE':
                            userInteraction_none_v3 += 1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"] == 'REQUIRED':
                            userInteraction_required_v3 += 1

                        if data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["scope"] == 'CHANGED':
                            scope_changed_v3 += 1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["scope"] == 'UNCHANGED':
                            scope_unchanged_v3 += 1

                        if data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"] == 'NONE':
                            confidentialityImpact_none_v3 += 1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"] == 'LOW':
                            confidentialityImpact_low_v3 += 1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"] == 'HIGH':
                            confidentialityImpact_high_v3 += 1

                        if data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"] == 'NONE':
                            integrityImpact_none_v3 += 1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"] == 'LOW':
                            integrityImpact_low_v3 += 1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"] == 'HIGH':
                            integrityImpact_high_v3 += 1

                        if data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"] == 'NONE':
                            availabilityImpact_none_v3 += 1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"] == 'LOW':
                            availabilityImpact_low_v3 += 1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"] == 'HIGH':
                            availabilityImpact_high_v3 += 1

                    if version == '2.0' and list(data["CVE_Items"][i]["impact"].keys())[0] == "baseMetricV2":
                        if data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["accessVector"] == 'NETWORK':
                            accessVector_network_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["accessVector"] == 'LOCAL':
                            accessVector_local_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["accessVector"] == 'ADJACENTNETWORK':
                            accessVector_Adjacentnetwork_v2 +=1

                        if data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"] == 'LOW':
                            accessComplexity_low_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"] == 'MEDIUM':
                            accessComplexity_medium_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"] == 'HIGH':
                            accessComplexity_high_v2 +=1

                        if data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["authentication"] == 'MULTIPLE':
                            authentication_multiple_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["authentication"] == 'SINGLE':
                            authentication_single_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["authentication"] == 'NONE':
                            authentication_none_v2 +=1

                        if data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"] == 'NONE':
                            confidentialityImpact_none_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"] == 'PARTIAL':
                            confidentialityImpact_partial_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"] == 'COMPLETE':
                            confidentialityImpact_complete_v2 +=1

                        if data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"] == 'NONE':
                            integrityImpact_none_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"] == 'PARTIAL':
                            integrityImpact_partial_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"] == 'COMPLETE':
                            integrityImpact_complete_v2 +=1

                        if data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"] == 'NONE':
                            availabilityImpact_none_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"] == 'PARTIAL':
                            availabilityImpact_partial_v2 +=1
                        elif data["CVE_Items"][i]["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"] == 'COMPLETE':
                            availabilityImpact_complete_v2 +=1

                except IndexError:
                    pass
    if option == 1:
        values = [ attackVector_network_v3, attackVector_adjacent_v3, attackVector_local_v3, attackVector_physical_v3,
                   attackComplexity_low_v3, attackComplexity_high_v3, privilegesRequired_none_v3, privilegesRequired_low_v3,
                   privilegesRequired_high_v3, userInteraction_none_v3, userInteraction_required_v3, scope_changed_v3,
                   scope_unchanged_v3, confidentialityImpact_high_v3, confidentialityImpact_low_v3,
                   confidentialityImpact_none_v3, integrityImpact_high_v3, integrityImpact_low_v3, integrityImpact_none_v3,
                   availabilityImpact_high_v3, availabilityImpact_low_v3, availabilityImpact_none_v3 ]

    elif option == 0:
        values = [accessVector_local_v2, accessVector_Adjacentnetwork_v2, accessVector_network_v2,
                         accessComplexity_low_v2, accessComplexity_medium_v2, accessComplexity_high_v2,
                         authentication_multiple_v2, authentication_single_v2, authentication_none_v2,
                         confidentialityImpact_none_v2, confidentialityImpact_partial_v2, confidentialityImpact_complete_v2,
                         integrityImpact_none_v2, integrityImpact_partial_v2, integrityImpact_complete_v2,
                         availabilityImpact_none_v2, availabilityImpact_partial_v2, availabilityImpact_complete_v2]



    plt.bar(labels, values, 0.1, align='center')
    plt.xticks(rotation=90)
    plt.title("Flags histogram for "+str(a)+'-'+str(b)+', version '+version)
    plt.xlabel("Types of flags")
    plt.ylabel("Amount")
    plt.grid(axis='y', alpha=0.75)

    plt.tight_layout()
    plt.savefig('histograms/histogram_flags_'+str(a)+'-'+str(b)+'_'+version+'.pdf')
    plt.show()


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
    flags_histogram(a,b,0)
    flags_histogram(a,b,1)


a = int(input("select start dates (2002-2022): "))
b = int(input("select end dates (2002-2022): "))

draw_histograms(a,b)
