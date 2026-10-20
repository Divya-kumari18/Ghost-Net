"""Consistent static-file features, training, and inference. No process fields are invented."""
from pathlib import Path
import hashlib
import json
import math
import numpy as np

FEATURES=['file_size','entropy','null_ratio','printable_ratio','mz_header']
MAX_BYTES=25_000_000

def features(path):
    path=Path(path)
    with path.open('rb') as stream:data=stream.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES:raise ValueError('File exceeds static-model size limit')
    counts=np.bincount(np.frombuffer(data,dtype=np.uint8),minlength=256)
    probabilities=counts[counts>0]/max(1,len(data))
    entropy=float(-(probabilities*np.log2(probabilities)).sum())
    values=[len(data),entropy,data.count(0)/max(1,len(data)),sum(32<=b<=126 for b in data)/max(1,len(data)),int(data.startswith(b'MZ'))]
    return dict(zip(FEATURES,values)),hashlib.sha256(data).hexdigest()

def predict(path,artifact):
    import joblib
    import pandas as pd
    import sklearn
    bundle=joblib.load(artifact)
    if bundle.get('features')!=FEATURES or bundle.get('sklearn_version')!=sklearn.__version__:
        raise ValueError('Static model schema/runtime mismatch; retrain with the installed runtime')
    values,_=features(path)
    probabilities=bundle['model'].predict_proba(pd.DataFrame([values],columns=FEATURES))[0]
    classes=bundle['model'].classes_
    index=int(np.argmax(probabilities));malicious=int(classes[index])==1
    return {'label':'malware' if malicious else 'benign','class_id':int(malicious),
            'confidence':round(float(probabilities[index])*100,2),'source':'static-random-forest','feature_count':len(FEATURES)}

def train(manifest,output):
    import joblib
    import pandas as pd
    import sklearn
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report,confusion_matrix
    manifest=Path(manifest).resolve()
    records=pd.read_csv(manifest)
    if not {'path','label'}<=set(records.columns):raise ValueError('CSV must contain path,label (0=benign,1=malicious)')
    rows=[];labels=[];seen=set()
    for row in records.itertuples():
        label=int(row.label)
        if label not in (0,1):raise ValueError('Labels must be 0 or 1')
        path=Path(row.path);path=path if path.is_absolute() else manifest.parent/path
        values,digest=features(path)
        if digest in seen:continue
        seen.add(digest);rows.append(values);labels.append(label)
    if min(labels.count(0),labels.count(1))<10:raise ValueError('At least 10 unique files per class required')
    X=pd.DataFrame(rows,columns=FEATURES)
    train_x,test_x,train_y,test_y=train_test_split(X,labels,test_size=.25,stratify=labels,random_state=42)
    model=RandomForestClassifier(n_estimators=300,class_weight='balanced',random_state=42,n_jobs=-1).fit(train_x,train_y)
    predicted=model.predict(test_x)
    metrics={'classification':classification_report(test_y,predicted,output_dict=True,zero_division=0),
             'confusion_matrix':confusion_matrix(test_y,predicted).tolist(),'training_files':len(train_x),'test_files':len(test_x)}
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    joblib.dump({'model':model,'features':FEATURES,'sklearn_version':sklearn.__version__,'metrics':metrics},output)
    output.with_suffix('.metrics.json').write_text(json.dumps(metrics,indent=2),encoding='utf-8')

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('manifest');parser.add_argument('--output',default='data/static-malware.joblib')
    args=parser.parse_args();train(args.manifest,args.output)
