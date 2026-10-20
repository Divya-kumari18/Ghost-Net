"""CNN-LSTM flow classifier. Train only on labeled, chronologically split real sequences."""
from pathlib import Path
import json
import numpy as np

FEATURES=['packet_size','source_port','destination_port','ttl','protocol_id']
STEPS=16

class SequenceModel:
    def __init__(self,directory):
        self.directory=Path(directory);self.model=None;self.error=None
        if not (self.directory/'model.keras').exists():self.error='No trained CNN-LSTM artifact';return
        try:
            import tensorflow as tf
            self.meta=json.loads((self.directory/'manifest.json').read_text())
            if self.meta['features']!=FEATURES or self.meta['steps']!=STEPS:raise ValueError('Sequence schema mismatch')
            self.model=tf.keras.models.load_model(self.directory/'model.keras')
            self.mean=np.array(self.meta['mean']);self.scale=np.array(self.meta['scale'])
        except Exception as ex:self.error=str(ex)
    def predict(self,sequences):
        if self.model is None:raise RuntimeError(self.error)
        values=np.asarray(sequences,dtype=np.float32)
        if values.ndim!=3 or values.shape[1:]!=(STEPS,len(FEATURES)) or not np.isfinite(values).all():
            raise ValueError(f'Expected finite [batch,{STEPS},{len(FEATURES)}] sequences')
        if len(values)>1000:raise ValueError('Maximum 1000 sequences per request')
        return self.model.predict((values-self.mean)/self.scale,verbose=0).reshape(-1).tolist()

def train(dataset,output,epochs=30):
    import tensorflow as tf
    from sklearn.metrics import classification_report,confusion_matrix
    # Explicit splits prevent random splitting overlapping packet windows across train/test.
    data=np.load(dataset,allow_pickle=False)
    arrays={key:data[key] for key in ['train_x','train_y','validation_x','validation_y','test_x','test_y']}
    for split in ['train','validation','test']:
        x=arrays[split+'_x'];y=arrays[split+'_y']
        if x.ndim!=3 or x.shape[1:]!=(STEPS,len(FEATURES)) or len(x)!=len(y) or not np.isfinite(x).all():raise ValueError('Invalid sequence dataset')
        if set(np.unique(y))!={0,1}:raise ValueError('Each split must contain both binary labels')
    mean=arrays['train_x'].mean(axis=(0,1));scale=arrays['train_x'].std(axis=(0,1));scale[scale==0]=1
    tf.keras.utils.set_random_seed(42)
    model=tf.keras.Sequential([tf.keras.layers.Input((STEPS,len(FEATURES))),tf.keras.layers.Conv1D(32,3,activation='relu'),
        tf.keras.layers.MaxPooling1D(2),tf.keras.layers.LSTM(32),tf.keras.layers.Dropout(.2),tf.keras.layers.Dense(1,activation='sigmoid')])
    model.compile(optimizer='adam',loss='binary_crossentropy',metrics=['accuracy',tf.keras.metrics.Precision(),tf.keras.metrics.Recall()])
    model.fit((arrays['train_x']-mean)/scale,arrays['train_y'],validation_data=((arrays['validation_x']-mean)/scale,arrays['validation_y']),
        epochs=epochs,batch_size=64,callbacks=[tf.keras.callbacks.EarlyStopping(patience=5,restore_best_weights=True)])
    predicted=(model.predict((arrays['test_x']-mean)/scale,verbose=0).reshape(-1)>=.5).astype(int)
    metrics={'classification':classification_report(arrays['test_y'],predicted,output_dict=True,zero_division=0),
        'confusion_matrix':confusion_matrix(arrays['test_y'],predicted).tolist()}
    output=Path(output);output.mkdir(parents=True,exist_ok=True);model.save(output/'model.keras')
    (output/'manifest.json').write_text(json.dumps({'features':FEATURES,'steps':STEPS,'mean':mean.tolist(),'scale':scale.tolist(),'metrics':metrics},indent=2))

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('dataset');parser.add_argument('--output',default='data/cnn-lstm');parser.add_argument('--epochs',type=int,default=30)
    args=parser.parse_args();train(args.dataset,args.output,args.epochs)
