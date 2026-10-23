"""Regression fixture for PY_UNSAFE_DESERIALIZATION variants (never executed)."""
import json
import _pickle as cPickle
import cloudpickle
import dill
import joblib
import numpy as np
import pandas as pd
import torch
from pickle import loads as pickle_loads
from pickle import Unpickler


def load_everything(path, blob, fh):
    a = pickle_loads(blob)
    b = cPickle.load(fh)
    c = dill.loads(blob)
    d = cloudpickle.load(fh)
    e = joblib.load(path)
    f = pd.read_pickle(path)
    g = Unpickler(fh).load()
    h = torch.load(path)
    i = torch.load(path, weights_only=False)
    j = torch.load(path, weights_only=True)
    k = np.load(path, allow_pickle=True)
    m = np.load(path)
    n = json.loads(blob)
    return a, b, c, d, e, f, g, h, i, j, k, m, n
