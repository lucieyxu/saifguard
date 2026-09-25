import pickle

def load_model_weights(file_path):
    with open(file_path, "rb") as f:
        # Insecure deserialization
        model = pickle.load(f)
    return model
