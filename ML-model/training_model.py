import random
import warnings
import sys
import numpy as np
import os
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
import joblib

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)


#backend model paths
MODEL_DIR = os.path.join(BASE_DIR, "backend", "app", "models")
WEIGHTS_DIR = os.path.join(MODEL_DIR, "weights")
ENCODERS_DIR = os.path.join(MODEL_DIR, "encoders")

from backend.app.models.model import Agent, FocalLoss
from backend.app.config import Config
from torch.utils.data import DataLoader, TensorDataset, WeightedRandomSampler
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, confusion_matrix

warnings.filterwarnings("ignore")

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
torch.cuda.manual_seed_all(SEED)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

selected_features = Config.FEATURES

BATCH_SIZE   = 512
LR           = 1e-3
WEIGHT_DECAY = 1e-4
MAX_EPOCHS   = 60
PATIENCE     = 10
THRESHOLD    = 0.75
CLIP_GRAD    = 5.0




def load_data(path):
    df = pd.read_csv(path, low_memory=False)
    df = df[selected_features + ['Label']].copy()
    df[selected_features] = df[selected_features].apply(pd.to_numeric, errors='coerce')
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    return df


def safe_transform(encoder, arr):
    known = set(encoder.classes_)
    return np.array([
        encoder.transform([v])[0] if v in known else 0
        for v in arr.astype(int)
    ])


@torch.no_grad()
def batched_predict(model, X_tensor, batch_size=2048):
    parts = []
    for i in range(0, len(X_tensor), batch_size):
        parts.append(model(X_tensor[i : i + batch_size].to(device)).cpu())
    return torch.cat(parts)


def calibrate_temperature(model, val_x, val_y):
    T = nn.Parameter(torch.ones(1, device=device) * 1.5)
    opt = optim.LBFGS([T], lr=0.01, max_iter=100)

    with torch.no_grad():
        logits = batched_predict(model, val_x).to(device)
    val_y_dev = val_y.to(device)

    def closure():
        opt.zero_grad()
        nn.CrossEntropyLoss()(logits / T.clamp(min=1e-6), val_y_dev).backward()
        return nn.CrossEntropyLoss()(logits / T.clamp(min=1e-6), val_y_dev)

    opt.step(closure)
    T_val = T.detach().abs()
    print(f"  Calibrated temperature: {T_val.item():.4f}")
    return T_val


def make_weighted_sampler(y):
    
    class_counts = np.bincount(y)
    weight_per_class = 1.0 / class_counts
    sample_weights = weight_per_class[y]
    return WeightedRandomSampler(
        weights=torch.tensor(sample_weights, dtype=torch.float32),
        num_samples=len(y),
        replacement=True,
    )

#different thresholds for different attack types
def tune_thresholds(probs_np, true_np, num_classes, target_precision=0.95):
    thresholds = np.full(num_classes, 0.75)   
    for cls in range(num_classes):
        cls_probs = probs_np[:, cls]
        for t in np.arange(0.75, 1.00, 0.01):
            predicted_as_cls = cls_probs >= t
            if predicted_as_cls.sum() == 0:
                thresholds[cls] = 0.99
                break
            prec = (true_np[predicted_as_cls] == cls).mean()
            if prec >= target_precision:
                thresholds[cls] = round(t, 2)
                break
        else:
            thresholds[cls] = 0.99
    return thresholds


def apply_per_class_threshold(probs_np, thresholds):
   
    pred_class = probs_np.argmax(axis=1)
    pred_conf  = probs_np[np.arange(len(probs_np)), pred_class]
    class_thresh = thresholds[pred_class]
    final = np.where(pred_conf >= class_thresh, pred_class, -1)
    return final


def main():
    print("Loading data...")
    df = load_data(r"G:\My Drive\live-data.csv")
    print(f"  Shape: {df.shape} | Labels: {df['Label'].value_counts().to_dict()}")

    label_enc = LabelEncoder()
    y_all = label_enc.fit_transform(df['Label'])
    X_all = df[selected_features].values

    # 70 / 10 / 20 split
    X_temp, X_test, y_temp, y_test = train_test_split(
        X_all, y_all, test_size=0.20, stratify=y_all, random_state=SEED
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=0.125, stratify=y_temp, random_state=SEED
    )

    # Protocol encoder — fit on train only (no leakage)
    proto_idx = selected_features.index('Protocol')
    le_proto  = LabelEncoder()
    X_train[:, proto_idx] = le_proto.fit_transform(X_train[:, proto_idx].astype(int))
    X_val[:, proto_idx]   = safe_transform(le_proto, X_val[:, proto_idx])
    X_test[:, proto_idx]  = safe_transform(le_proto, X_test[:, proto_idx])

    # Scaler — fit on train only
    scaler     = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_val_sc   = scaler.transform(X_val)
    X_test_sc  = scaler.transform(X_test)

    # Class weights for FocalLoss 
    class_weights = compute_class_weight(
        class_weight="balanced", classes=np.unique(y_train), y=y_train
    )
    cw_tensor = torch.tensor(class_weights, dtype=torch.float32).to(device)

    # WeightedRandomSampler balances batches without generating synthetic samples
    sampler = make_weighted_sampler(y_train)

    train_ds = TensorDataset(
        torch.tensor(X_train_sc, dtype=torch.float32),
        torch.tensor(y_train,    dtype=torch.long),
    )
    # shuffle=False because sampler handles ordering
    train_loader = DataLoader(
        train_ds, batch_size=BATCH_SIZE, sampler=sampler,
        pin_memory=(device.type == 'cuda'), num_workers=0,
    )

    val_x  = torch.tensor(X_val_sc,  dtype=torch.float32)
    val_y  = torch.tensor(y_val,     dtype=torch.long)
    test_x = torch.tensor(X_test_sc, dtype=torch.float32)
    test_y = torch.tensor(y_test,    dtype=torch.long)

    inp_size    = X_train_sc.shape[1]
    num_classes = len(np.unique(y_all))
    model       = Agent(inp_size, num_classes).to(device)

    criterion = FocalLoss(alpha=cw_tensor, gamma=2.0)
    optimizer = optim.AdamW(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)

    # pct_start=0.02: with ~3800 batches/epoch, 0.2 kept LR tiny for 12 full epochs.
    # 0.02 = warmup over ~1.2 epochs only — model reaches peak LR almost immediately.
    scheduler = optim.lr_scheduler.OneCycleLR(
        optimizer,
        max_lr=LR,
        steps_per_epoch=len(train_loader),
        epochs=MAX_EPOCHS,
        pct_start=0.02,
        anneal_strategy='cos',
    )

    print(f"\nTraining on {device} | {len(X_train_sc)} train | {len(X_val_sc)} val samples")
    best_val_loss    = float('inf')
    patience_counter = 0

    for epoch in range(1, MAX_EPOCHS + 1):
        model.train()
        total_loss = 0.0
        for xb, yb in train_loader:
            xb, yb = xb.to(device), yb.to(device)
            optimizer.zero_grad(set_to_none=True)
            loss = criterion(model(xb), yb)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), CLIP_GRAD)
            optimizer.step()
            scheduler.step()          
            total_loss += loss.item()

        model.eval()
        val_logits = batched_predict(model, val_x).to(device)   
        val_y_dev  = val_y.to(device)
        val_loss   = criterion(val_logits, val_y_dev).item()
        val_acc    = (val_logits.argmax(1) == val_y_dev).float().mean().item()

        if True: 
            print(
                f"  Epoch {epoch:3d}/{MAX_EPOCHS} | "
                f"Train Loss: {total_loss/len(train_loader):.4f} | "
                f"Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f}"
            )

        if val_loss < best_val_loss - 1e-5:
            best_val_loss    = val_loss
            patience_counter = 0
            torch.save(model.state_dict(), os.path.join(WEIGHTS_DIR,"best_model.pth"))
        else:
            patience_counter += 1
            if patience_counter >= PATIENCE:
                print(f"  Early stopping at epoch {epoch}.")
                break

    model.load_state_dict(torch.load(os.path.join(WEIGHTS_DIR,"best_model.pth"), map_location=device))
    model.eval()

    print("\nCalibrating temperature...")
    T = calibrate_temperature(model, val_x, val_y)

    print("\nTuning per-class thresholds on val set...")
    T_cpu = T.cpu()
    with torch.no_grad():
        val_probs = torch.softmax(batched_predict(model, val_x) / T_cpu, dim=1).numpy()

    # Find threshold per class that achieves >=95% precision on val set
    class_thresholds = tune_thresholds(val_probs, val_y.numpy(), num_classes, target_precision=0.95)
    for i, (cls_name, t) in enumerate(zip(label_enc.classes_, class_thresholds)):
        print(f"  {cls_name:<30} threshold: {t:.2f}")
    joblib.dump(class_thresholds, os.path.join(ENCODERS_DIR,"class_thresholds.pkl"))

    print("\nEvaluating on test set...")
    with torch.no_grad():
        test_probs = torch.softmax(batched_predict(model, test_x) / T_cpu, dim=1).numpy()

    true_np    = test_y.numpy()
    overall_np = test_probs.argmax(axis=1)
    overall_acc = (overall_np == true_np).mean()

    # Per-class threshold filtering
    final_pred = apply_per_class_threshold(test_probs, class_thresholds)
    confident  = final_pred != -1
    conf_acc   = (final_pred[confident] == true_np[confident]).mean() if confident.any() else 0.0
    coverage   = confident.mean()

    print("\n===== Test Results =====")
    print(f"Classes            : {label_enc.classes_}")
    print(f"Per-class thresholds: {class_thresholds}")
    print(f"Overall Accuracy   : {overall_acc:.4f}")
    print(f"Confident Accuracy : {conf_acc:.4f}")
    print(f"Coverage           : {coverage:.4f}")

    if confident.any():
        y_true_c = true_np[confident]
        y_pred_c = final_pred[confident]
        present  = np.unique(np.concatenate([y_true_c, y_pred_c]))
        print("\nConfusion Matrix (per-class threshold):")
        print(confusion_matrix(y_true_c, y_pred_c, labels=present))
        print("\nClassification Report (per-class threshold):")
        print(classification_report(
            y_true_c, y_pred_c,
            labels=present,
            target_names=label_enc.classes_[present],
            digits=4, zero_division=0,
        ))

    torch.save({
        "model_state_dict" : model.state_dict(),
        "temperature"      : T.cpu(),
        "inp_size"         : inp_size,
        "num_classes"      : num_classes,
    }, os.path.join(WEIGHTS_DIR,"ai_ids_micro.pth"))

    joblib.dump(scaler, os.path.join(ENCODERS_DIR,"scaler.pkl"))
    joblib.dump(label_enc, os.path.join(ENCODERS_DIR,"label_encoder.pkl"))
    joblib.dump(le_proto, os.path.join(ENCODERS_DIR,"protocol_encoder.pkl"))
    joblib.dump(label_enc.classes_ , os.path.join(ENCODERS_DIR,"classes.pkl"))
    print("\nArtifacts saved.")


if __name__ == '__main__':
    main()