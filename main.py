import json

baseS = ['LOW','MEDIUM', 'HIGH', 'CRITICAL']
mid=0
high=0
vh=0
CVSS =["attackVector",
          "attackComplexity",
          "privilegesRequired",
          "userInteraction",
          "scope",
          "confidentialityImpact" ,
          "integrityImpact",
          "availabilityImpact" ,]
AV = ['PHYSICAL', 'LOCAL', 'ADJACENT', 'NETWORK']
AC = ['LOW', 'HIGH']
PR = ['NONE', 'LOW', 'HIGH']
UI = ['NONE', 'REQUIRED']
S = ['CHANGED', 'UNCHANGED']
C = ['NONE', 'LOW', 'HIGH']
I = ['NONE', 'LOW', 'HIGH']
A = ['NONE', 'LOW', 'HIGH']

listy = [AV, AC,PR,UI,S, C, I, A]

c = int(input("Choose what you want to search from the database "
              "\n 0 - the frequency of occurrence of a given classification category"
              "\n 1 - frequency of occurrence of the given value on a scale of 0 to 10 "
              "\n 2 - frequency of occurrence of a given flag "))
if c == 0:
    d = int(input("select a classification category: "
              "\n 0 - Low"
              "\n 1 -Medium"
              "\n 2 -High"
              "\n 3 -Critical"))
elif c == 1:
    e = int(input("Select start values on a scale of 0 to 10 "))
    f = int(input("Select end values on a scale of 0 to 10 "))

elif c == 2:
    g  = int(input("Select base score metric "
                   "\n 0 - attackVector"
                   "\n 1 - attackComplexity"
                    "\n2 -privilegesRequired"
                     "\n3 - userInteraction"
                     "\n4 - scope"
          "\n5 - confidentialityImpact" 
          "\n6 - integrityImpact"
          "\n7 - availabilityImpact"
                   ))
    print(listy[g])
    h = int(input("select a number starting with 0 to select the measure: "))

a = int(input("select start dates (2002-2022): "))
b = int(input("select end dates (2002-2022): "))+1

for rok in range(a,b):
    with open('json/nvdcve-1.1-'+str(rok)+'.json', 'r', encoding='utf-8') as myfile1:
        data = json.load(myfile1)

        for i in range(len(data["CVE_Items"])):
            try:

                if c == 0:
                    if list(data["CVE_Items"][i]["impact"].keys())[0] == "baseMetricV3":
                        if data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"] == baseS[d]:
                            mid += 1
                if c == 1:
                    if list(data["CVE_Items"][i]["impact"].keys())[0] == "baseMetricV3":
                        if e <= data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"]["baseScore"] <= f:
                            high += 1
                if c == 2:
                    if list(data["CVE_Items"][i]["impact"].keys())[0] == "baseMetricV3":
                        if data["CVE_Items"][i]["impact"]["baseMetricV3"]["cvssV3"][CVSS[g]] == listy[g][h]:
                            vh += 1





            except IndexError:
                pass
if c == 0:
    print("The number of times a given flag: ", mid)
elif c == 1:
    print('How many times a given value occurs on a scale of 0 to 10: ',high)
else:
    print('The number of occurrences of a given classification category: ', vh)


