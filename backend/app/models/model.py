import torch
import torch.nn as nn
import torch.nn.functional as F


class ResidualBlock(nn.Module):
    def __init__(self, in_dim: int, out_dim: int, dropout: float = 0.3):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(in_dim, out_dim),
            nn.BatchNorm1d(out_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(out_dim, out_dim),
            nn.BatchNorm1d(out_dim),
        )
        self.skip = nn.Linear(in_dim, out_dim, bias=False) if in_dim != out_dim else nn.Identity()
        self.act  = nn.GELU()

    def forward(self, x):
        return self.act(self.block(x) + self.skip(x))

#main model
class Agent(nn.Module):
    
    def __init__(self, inp: int, classes: int, dropout: float = 0.3):
        super().__init__()
        self.stem = nn.Sequential(
            nn.Linear(inp, 256),
            nn.BatchNorm1d(256),
            nn.GELU(),
            nn.Dropout(dropout),
        )
        self.res1 = ResidualBlock(256, 256, dropout)
        self.res2 = ResidualBlock(256, 128, dropout)
        self.head = nn.Sequential(
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.GELU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(64, classes),
        )
        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, nonlinearity="relu")
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(self, x):
        return self.head(self.res2(self.res1(self.stem(x))))

#loss fun 
class FocalLoss(nn.Module):
  
    def __init__(self, alpha=None, gamma: float = 2.0):
        super().__init__()
        self.register_buffer("alpha", alpha)
        self.gamma = gamma

    def forward(self, logits, targets):
        log_p   = F.log_softmax(logits, dim=1)
        log_pt  = log_p.gather(1, targets.unsqueeze(1)).squeeze(1)
        pt      = log_pt.exp()
        w       = (1.0 - pt).pow(self.gamma)
        if self.alpha is not None:
            w = self.alpha[targets] * w
        return (-w * log_pt).mean()