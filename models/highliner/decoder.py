import tensorflow as tf
import numpy as np

#Decorator of the keras model to hide the input and output processing
class Decoder:
    def __init__(self, model_path, window_len):
        self.model = tf.keras.saving.load_model(model_path)
        self.window_len = window_len

    def _segment_input(self, seq):
        if (len(seq) % self.window_len > 0):
          num_windows = (len(seq)//self.window_len)+1
          ceiling = num_windows * self.window_len
          seq = np.pad(seq, ((0, ceiling-len(seq)), (0,0)))
        else:
          num_windows = len(seq)//self.window_len
        segments = np.split(seq, num_windows)
        return np.stack(segments)

    def _predict_segments(self, segmented_seq):
        segmented_preds = self.model.predict(segmented_seq)
        return segmented_preds

    def _join_back_segments(self, segmented_seq, seq_len):
        padded_pred = np.concatenate(segmented_seq)
        seq_pred = np.resize(padded_pred, seq_len)
        return seq_pred
        
    def decode(self, encoded_seq):
        seq_len = len(encoded_seq)
        segmented_seq = self._segment_input(encoded_seq)
        segmented_pred = self._predict_segments(segmented_seq)
        output_pred = self._join_back_segments(segmented_pred, seq_len)
        return output_pred
