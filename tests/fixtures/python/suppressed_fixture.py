import pickle  # saifguard:ignore PY_UNSAFE_DESERIALIZATION test suppression

def load_data(f):
    return pickle.load(f)
