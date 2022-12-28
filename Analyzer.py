import pandas
from matplotlib import pyplot as plt
from sklearn.ensemble import IsolationForest
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from tkinter.filedialog import asksaveasfilename

win = Tk()
win.attributes("-topmost", True)
win.withdraw()
filename = askopenfilename(title = "Select file",filetypes = (("CSV Files","*.csv"),))

read = open(filename,'r')
df = pandas.read_csv(read)
read.close()
df['val'] = 1
df_op = df
df_op['Time Created'] = df_op['Time Created'].str.replace(r'[A-Z]', ' ', regex=True)
df_op['Time Created'] = pandas.to_datetime(df_op['Time Created'], infer_datetime_format=True)
df_op = df_op.resample('4H',on='Time Created').sum()
prop = ['Event ID', 'level', 'Process ID', 'Thread ID']
df_op = df_op.drop(prop , axis= 1)

# Model 1 for oversight help
#############################################################

# dft = df_op[['val']].to_numpy()
model = IsolationForest(contamination= .009)
model.fit(df_op[['val']].values)
df_op['anomaly']= model.predict(df_op[['val']].values)
ano = df_op.loc[df_op['anomaly'] == -1, ['val']]

#Plot
#############################################################
plt.rcParams["figure.figsize"] = (20,10)
plt.xticks(rotation=90, fontsize = 10)
plt.plot(df_op.index ,  df_op['val'], label = 'Number of events every 4 hours')
plt.scatter(x=ano.index,y=ano['val'], color = 'red',marker='s' , label= 'Anomalies')
plt.legend()
filesave = asksaveasfilename( defaultextension=".png")
plt.savefig(filesave)
read.close()
