import pandas as pd

# load the data into a dataframe
df = pd.read_csv('Output.csv')

# initialize variables
true_positive = 0
false_positive = 0
false_negative = 0
total_rows = 5196

# iterate over the rows in the dataframe
for index, row in df.iterrows():
    # compare the calculated value with the actual value
    if row['Output'] == row['Label']:
        true_positive += 1
    elif row['Output'] == 'DDOS' and row['Label'] == 'Normal':
        false_positive += 1
    elif row['Output'] == 'Normal' and row['Label'] == 'DDOS':
        false_negative += 1

# calculate accuracy and false positive rate
accuracy = true_positive *100/ total_rows
false_positive_rate = false_positive *100/ total_rows
false_negative_rate = false_negative*100 / total_rows

print(f'Accuracy: {accuracy}')
print(f'False positive rate: {false_positive_rate}')
print(f'False negative rate: {false_negative_rate}')