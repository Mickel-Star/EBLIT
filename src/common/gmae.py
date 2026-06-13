from __future__ import annotations

import os
from functools import partial
from itertools import chain
from types import SimpleNamespace
from typing import Any, Callable, Iterable

import dgl
import dgl.function as fn
import torch
import torch.nn as nn
import torch.nn.functional as F
from dgl.ops import edge_softmax
from dgl.utils import expand_as_pair


def create_activation(name: str | None) -> nn.Module | None:
    if not name:
        return None
    key = str(name).strip().lower()
    if key == "relu":
        return nn.ReLU()
    if key == "gelu":
        return nn.GELU()
    if key == "elu":
        return nn.ELU()
    if key == "prelu":
        return nn.PReLU()
    if key == "leakyrelu":
        return nn.LeakyReLU(0.2)
    raise ValueError(f"Unsupported activation: {name}")


def create_norm(name: str | None):
    if not name:
        return None
    key = str(name).strip().lower()
    if key == "batchnorm":
        return nn.BatchNorm1d
    if key == "layernorm":
        return nn.LayerNorm
    raise ValueError(f"Unsupported norm: {name}")


def sce_errors(x: torch.Tensor, y: torch.Tensor, alpha: float = 2.0) -> torch.Tensor:
    x = F.normalize(x, p=2, dim=-1)
    y = F.normalize(y, p=2, dim=-1)
    return torch.pow(1.0 - (x * y).sum(dim=-1), alpha)


def sce_loss(x: torch.Tensor, y: torch.Tensor, alpha: float = 2.0) -> torch.Tensor:
    return sce_errors(x, y, alpha=alpha).mean()


def _get_arg(args: Any, name: str, default: Any) -> Any:
    if isinstance(args, dict):
        return args.get(name, default)
    return getattr(args, name, default)


def build_model(args):
    args = args if isinstance(args, (dict, SimpleNamespace)) else SimpleNamespace(**vars(args))
    num_hidden = int(_get_arg(args, "num_hidden", 64))
    num_layers = int(_get_arg(args, "num_layers", 2))
    negative_slope = float(_get_arg(args, "negative_slope", 0.2))
    mask_rate = float(_get_arg(args, "mask_rate", 0.5))
    alpha_l = float(_get_arg(args, "alpha_l", 2.0))
    n_dim = int(_get_arg(args, "n_dim", 64))
    e_dim = int(_get_arg(args, "e_dim", 16))
    n_heads = int(_get_arg(args, "n_heads", 4))
    feat_drop = float(_get_arg(args, "feat_drop", 0.1))
    activation = str(_get_arg(args, "activation", "prelu"))
    residual = bool(_get_arg(args, "residual", True))
    norm = _get_arg(args, "norm", "BatchNorm")

    return GMAEModel(
        n_dim=n_dim,
        e_dim=e_dim,
        hidden_dim=num_hidden,
        n_layers=num_layers,
        n_heads=n_heads,
        activation=activation,
        feat_drop=feat_drop,
        negative_slope=negative_slope,
        residual=residual,
        mask_rate=mask_rate,
        norm=norm,
        loss_fn="sce",
        alpha_l=alpha_l,
    )


class GAT(nn.Module):
    def __init__(
        self,
        n_dim,
        e_dim,
        hidden_dim,
        out_dim,
        n_layers,
        n_heads,
        n_heads_out,
        activation,
        feat_drop,
        attn_drop,
        negative_slope,
        residual,
        norm,
        concat_out=False,
        encoding=False,
    ):
        super().__init__()
        self.out_dim = out_dim
        self.n_heads = n_heads
        self.n_layers = n_layers
        self.gats = nn.ModuleList()
        self.concat_out = concat_out

        last_activation = create_activation(activation) if encoding else None
        last_residual = bool(encoding and residual)
        last_norm = norm if encoding else None

        if self.n_layers == 1:
            self.gats.append(
                GATConv(
                    n_dim,
                    e_dim,
                    out_dim,
                    n_heads_out,
                    feat_drop,
                    attn_drop,
                    negative_slope,
                    last_residual,
                    norm=last_norm,
                    concat_out=self.concat_out,
                )
            )
        else:
            self.gats.append(
                GATConv(
                    n_dim,
                    e_dim,
                    hidden_dim,
                    n_heads,
                    feat_drop,
                    attn_drop,
                    negative_slope,
                    residual,
                    create_activation(activation),
                    norm=norm,
                    concat_out=self.concat_out,
                )
            )
            for _ in range(1, self.n_layers - 1):
                self.gats.append(
                    GATConv(
                        hidden_dim * self.n_heads,
                        e_dim,
                        hidden_dim,
                        n_heads,
                        feat_drop,
                        attn_drop,
                        negative_slope,
                        residual,
                        create_activation(activation),
                        norm=norm,
                        concat_out=self.concat_out,
                    )
                )
            self.gats.append(
                GATConv(
                    hidden_dim * self.n_heads,
                    e_dim,
                    out_dim,
                    n_heads_out,
                    feat_drop,
                    attn_drop,
                    negative_slope,
                    last_residual,
                    last_activation,
                    norm=last_norm,
                    concat_out=self.concat_out,
                )
            )
        self.head = nn.Identity()

    def forward(self, g, input_feature, return_hidden=False):
        h = input_feature
        hidden_list = []
        for layer in range(self.n_layers):
            h = self.gats[layer](g, h)
            hidden_list.append(h)
        if return_hidden:
            return self.head(h), hidden_list
        return self.head(h)

    def reset_classifier(self, num_classes):
        self.head = nn.Linear(self.n_heads * self.out_dim, num_classes)


class GATConv(nn.Module):
    def __init__(
        self,
        in_dim,
        e_dim,
        out_dim,
        n_heads,
        feat_drop=0.0,
        attn_drop=0.0,
        negative_slope=0.2,
        residual=False,
        activation=None,
        allow_zero_in_degree=False,
        bias=True,
        norm: Callable[[int], nn.Module] | None = None,
        concat_out=True,
    ):
        super().__init__()
        self.n_heads = n_heads
        self.src_feat, self.dst_feat = expand_as_pair(in_dim)
        self.edge_feat = e_dim
        self.out_feat = out_dim
        self.allow_zero_in_degree = allow_zero_in_degree
        self.concat_out = concat_out

        if isinstance(in_dim, tuple):
            self.fc_node_embedding = nn.Linear(self.src_feat, self.out_feat * self.n_heads, bias=False)
            self.fc_src = nn.Linear(self.src_feat, self.out_feat * self.n_heads, bias=False)
            self.fc_dst = nn.Linear(self.dst_feat, self.out_feat * self.n_heads, bias=False)
        else:
            self.fc_node_embedding = nn.Linear(self.src_feat, self.out_feat * self.n_heads, bias=False)
            self.fc = nn.Linear(self.src_feat, self.out_feat * self.n_heads, bias=False)
        self.edge_fc = nn.Linear(self.edge_feat, self.out_feat * self.n_heads, bias=False)
        self.attn_h = nn.Parameter(torch.empty(size=(1, self.n_heads, self.out_feat)))
        self.attn_e = nn.Parameter(torch.empty(size=(1, self.n_heads, self.out_feat)))
        self.attn_t = nn.Parameter(torch.empty(size=(1, self.n_heads, self.out_feat)))
        self.feat_drop = nn.Dropout(feat_drop)
        self.attn_drop = nn.Dropout(attn_drop)
        self.leaky_relu = nn.LeakyReLU(negative_slope)
        if bias:
            self.bias = nn.Parameter(torch.empty(size=(1, self.n_heads, self.out_feat)))
        else:
            self.register_buffer("bias", None)
        if residual:
            if self.dst_feat != self.n_heads * self.out_feat:
                self.res_fc = nn.Linear(self.dst_feat, self.n_heads * self.out_feat, bias=False)
            else:
                self.res_fc = nn.Identity()
        else:
            self.register_buffer("res_fc", None)
        self.reset_parameters()
        self.activation = activation
        self.norm = norm(self.n_heads * self.out_feat) if norm is not None else None

    def reset_parameters(self):
        gain = nn.init.calculate_gain("relu")
        nn.init.xavier_normal_(self.edge_fc.weight, gain=gain)
        if hasattr(self, "fc"):
            nn.init.xavier_normal_(self.fc.weight, gain=gain)
        else:
            nn.init.xavier_normal_(self.fc_src.weight, gain=gain)
            nn.init.xavier_normal_(self.fc_dst.weight, gain=gain)
        nn.init.xavier_normal_(self.attn_h, gain=gain)
        nn.init.xavier_normal_(self.attn_e, gain=gain)
        nn.init.xavier_normal_(self.attn_t, gain=gain)
        if self.bias is not None:
            nn.init.constant_(self.bias, 0)
        if isinstance(self.res_fc, nn.Linear):
            nn.init.xavier_normal_(self.res_fc.weight, gain=gain)

    def set_allow_zero_in_degree(self, set_value):
        self.allow_zero_in_degree = set_value

    def _finalize_output(self, rst, h_dst, dst_prefix_shape):
        if self.bias is not None:
            rst = rst + self.bias.view(*((1,) * len(dst_prefix_shape)), self.n_heads, self.out_feat)
        if self.res_fc is not None:
            resval = self.res_fc(h_dst).view(*dst_prefix_shape, -1, self.out_feat)
            rst = rst + resval
        if self.concat_out:
            rst = rst.flatten(1)
        else:
            rst = torch.mean(rst, dim=1)
        if self.norm is not None:
            rst = self.norm(rst)
        if self.activation:
            rst = self.activation(rst)
        return rst  # 残差、多头拼接、激活，输出最终特征

    def forward(self, graph, feat, get_attention=False):
        edge_feature = graph.edata["attr"]
        with graph.local_scope():
            if isinstance(feat, tuple):
                src_prefix_shape = feat[0].shape[:-1]
                dst_prefix_shape = feat[1].shape[:-1]
                h_src = self.feat_drop(feat[0])
                h_dst = self.feat_drop(feat[1])
                if not hasattr(self, "fc_src"):
                    feat_src = self.fc(h_src).view(*src_prefix_shape, self.n_heads, self.out_feat)
                    feat_dst = self.fc(h_dst).view(*dst_prefix_shape, self.n_heads, self.out_feat)
                else:
                    feat_src = self.fc_src(h_src).view(*src_prefix_shape, self.n_heads, self.out_feat)
                    feat_dst = self.fc_dst(h_dst).view(*dst_prefix_shape, self.n_heads, self.out_feat)
            else:
                src_prefix_shape = dst_prefix_shape = feat.shape[:-1]
                h_src = h_dst = self.feat_drop(feat)
                feat_src = feat_dst = self.fc(h_src).view(*src_prefix_shape, self.n_heads, self.out_feat)
                if graph.is_block:
                    feat_dst = feat_src[: graph.number_of_dst_nodes()]
                    h_dst = h_dst[: graph.number_of_dst_nodes()]
                    dst_prefix_shape = (graph.number_of_dst_nodes(),) + dst_prefix_shape[1:]

            if graph.num_edges() == 0:
                rst = feat_dst.new_zeros((feat_dst.shape[0], self.n_heads, self.out_feat))
                rst = self._finalize_output(rst, h_dst, dst_prefix_shape)
                if get_attention:
                    return rst, None
                return rst

            edge_prefix_shape = edge_feature.shape[:-1]
            eh = (feat_src * self.attn_h).sum(-1).unsqueeze(-1)  # 源节点注意力分数
            et = (feat_dst * self.attn_t).sum(-1).unsqueeze(-1)  # 目标节点注意力分数

            graph.srcdata.update({"hs": feat_src, "eh": eh})
            graph.dstdata.update({"et": et})

            feat_edge = self.edge_fc(edge_feature).view(*edge_prefix_shape, self.n_heads, self.out_feat)  # 边特征的线性变换
            ee = (feat_edge * self.attn_e).sum(-1).unsqueeze(-1)  # 边的注意力分数

            graph.edata.update({"ee": ee})
            graph.apply_edges(fn.u_add_e("eh", "ee", "ee"))  
            graph.apply_edges(fn.e_add_v("ee", "et", "e"))  # 三者聚合得到总注意力分数

            e = self.leaky_relu(graph.edata.pop("e"))  # 激活函数
            graph.edata["a"] = self.attn_drop(edge_softmax(graph, e))  # 对注意力进行归一化
            graph.update_all(fn.u_mul_e("hs", "a", "m"), fn.sum("m", "hs"))  # 聚合函数：对所有邻居消息求和 → 目标节点新特征

            rst = graph.dstdata["hs"].view(-1, self.n_heads, self.out_feat)  # 取出聚合后的特征
            rst = self._finalize_output(rst, h_dst, dst_prefix_shape)

            if get_attention:
                return rst, graph.edata["a"]
            return rst


class GMAEModel(nn.Module):
    def __init__(
        self,
        n_dim,
        e_dim,
        hidden_dim,
        n_layers,
        n_heads,
        activation,
        feat_drop,
        negative_slope,
        residual,
        norm,
        mask_rate=0.5,
        loss_fn="sce",
        alpha_l=2,
    ):
        super().__init__()
        self._mask_rate = float(mask_rate)
        self._output_hidden_size = hidden_dim
        self._loss_fn_name = str(loss_fn)
        self._alpha_l = float(alpha_l)
        self.recon_loss = nn.BCELoss(reduction="mean")

        def init_weights(m):
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)

        self.edge_recon_fc = nn.Sequential(
            nn.Linear(hidden_dim * n_layers * 2, hidden_dim),
            nn.LeakyReLU(negative_slope),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid(),
        )
        self.edge_recon_fc.apply(init_weights)

        assert hidden_dim % n_heads == 0
        enc_num_hidden = hidden_dim // n_heads
        enc_nhead = n_heads
        dec_in_dim = hidden_dim
        dec_num_hidden = hidden_dim

        self.encoder = GAT(
            n_dim=n_dim,
            e_dim=e_dim,
            hidden_dim=enc_num_hidden,
            out_dim=enc_num_hidden,
            n_layers=n_layers,
            n_heads=enc_nhead,
            n_heads_out=enc_nhead,
            concat_out=True,
            activation=activation,
            feat_drop=feat_drop,
            attn_drop=0.0,
            negative_slope=negative_slope,
            residual=residual,
            norm=create_norm(norm),
            encoding=True,
        )

        self.decoder = GAT(
            n_dim=dec_in_dim,
            e_dim=e_dim,
            hidden_dim=dec_num_hidden,
            out_dim=n_dim,
            n_layers=1,
            n_heads=n_heads,
            n_heads_out=1,
            concat_out=True,
            activation=activation,
            feat_drop=feat_drop,
            attn_drop=0.0,
            negative_slope=negative_slope,
            residual=residual,
            norm=create_norm(norm),
            encoding=False,
        )

        self.enc_mask_token = nn.Parameter(torch.zeros(1, n_dim))
        self.encoder_to_decoder = nn.Linear(dec_in_dim * n_layers, dec_in_dim, bias=False)
        self.criterion = self.setup_loss_fn(loss_fn, alpha_l)

    @property
    def output_hidden_dim(self):
        return self._output_hidden_size

    def setup_loss_fn(self, loss_fn, alpha_l):
        if loss_fn == "sce":
            return partial(sce_loss, alpha=alpha_l)
        raise NotImplementedError(f"Unsupported loss function: {loss_fn}")

    def _reconstruction_errors(self, x: torch.Tensor, y: torch.Tensor) -> torch.Tensor:
        if self._loss_fn_name == "sce":
            return sce_errors(x, y, alpha=self._alpha_l)
        raise NotImplementedError(f"Unsupported loss function: {self._loss_fn_name}")

    def encoding_mask_noise(self, g, mask_rate=0.3):
        new_g = g.clone()
        num_nodes = int(g.num_nodes())
        if num_nodes == 0:
            empty = torch.empty(0, dtype=torch.long, device=g.device)
            return new_g, (empty, empty)

        candidate_nodes = None
        if "is_process" in g.ndata:
            process_nodes = torch.nonzero(g.ndata["is_process"], as_tuple=False).flatten()
            if int(process_nodes.numel()) > 0:
                candidate_nodes = process_nodes
        if candidate_nodes is None:
            candidate_nodes = torch.arange(num_nodes, device=g.device, dtype=torch.long)

        perm = candidate_nodes[torch.randperm(int(candidate_nodes.numel()), device=g.device)]
        num_mask_nodes = max(1, int(mask_rate * int(candidate_nodes.numel())))
        num_mask_nodes = min(num_mask_nodes, int(candidate_nodes.numel()))
        mask_nodes = perm[:num_mask_nodes]
        keep_mask = torch.ones(num_nodes, dtype=torch.bool, device=g.device)
        keep_mask[mask_nodes] = False
        keep_nodes = torch.nonzero(keep_mask, as_tuple=False).flatten()
        new_g.ndata["attr"][mask_nodes] = self.enc_mask_token
        return new_g, (mask_nodes, keep_nodes)

    def _encode(self, g, x: torch.Tensor):
        _, all_hidden = self.encoder(g, x, return_hidden=True)
        enc_rep = torch.cat(all_hidden, dim=1)
        return enc_rep, self.encoder_to_decoder(enc_rep)

    def reconstruct(self, g):
        x = g.ndata["attr"].to(g.device)
        enc_rep, rep = self._encode(g, x)
        recon = self.decoder(g, rep)
        return recon, enc_rep

    def forward(self, g):
        return self.compute_loss(g)

    def _structure_loss(self, g, enc_rep: torch.Tensor) -> torch.Tensor:
        num_edges = int(g.number_of_edges())
        num_nodes = int(g.number_of_nodes())
        if num_edges <= 0 or num_nodes <= 1:
            return enc_rep.new_zeros(())

        edge_src, edge_dst = g.edges()
        existing_pairs = {
            (int(src), int(dst))
            for src, dst in zip(edge_src.detach().cpu().tolist(), edge_dst.detach().cpu().tolist())
        }
        negative_capacity = max(int(num_nodes * num_nodes) - len(existing_pairs), 0)
        if negative_capacity <= 0:
            return enc_rep.new_zeros(())

        sample_size = min(10000, num_edges, negative_capacity)
        pos_indices = torch.randperm(num_edges, device=g.device)[:sample_size]
        pos_src = edge_src[pos_indices]
        pos_dst = edge_dst[pos_indices]

        neg_src, neg_dst = self._sample_negative_edges(
            num_nodes=num_nodes,
            sample_size=sample_size,
            existing_pairs=existing_pairs,
            device=g.device,
        )
        paired = min(int(pos_src.shape[0]), int(neg_src.shape[0]))
        if paired <= 0:
            return enc_rep.new_zeros(())
        pos_src = pos_src[:paired]
        pos_dst = pos_dst[:paired]
        neg_src = neg_src[:paired]
        neg_dst = neg_dst[:paired]

        sample_src = enc_rep[torch.cat([pos_src, neg_src])].to(g.device)
        sample_dst = enc_rep[torch.cat([pos_dst, neg_dst])].to(g.device)
        y_pred = self.edge_recon_fc(torch.cat([sample_src, sample_dst], dim=-1)).squeeze(-1)
        y = torch.cat(
            [
                torch.ones(paired, device=g.device),
                torch.zeros(paired, device=g.device),
            ]
        )
        return self.recon_loss(y_pred, y)

    def _sample_negative_edges(
        self,
        *,
        num_nodes: int,
        sample_size: int,
        existing_pairs: set[tuple[int, int]],
        device,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        if sample_size <= 0:
            empty = torch.empty(0, dtype=torch.long, device=device)
            return empty, empty

        selected: list[tuple[int, int]] = []
        selected_set: set[tuple[int, int]] = set()
        max_attempts = max(int(sample_size) * 20, 100)
        attempts = 0
        while len(selected) < sample_size and attempts < max_attempts:
            attempts += 1
            src = int(torch.randint(int(num_nodes), (1,), device="cpu").item())
            dst = int(torch.randint(int(num_nodes), (1,), device="cpu").item())
            pair = (src, dst)
            if pair in existing_pairs or pair in selected_set:
                continue
            selected.append(pair)
            selected_set.add(pair)

        if len(selected) < sample_size and int(num_nodes) * int(num_nodes) <= 1_000_000:
            for src in range(int(num_nodes)):
                for dst in range(int(num_nodes)):
                    pair = (src, dst)
                    if pair in existing_pairs or pair in selected_set:
                        continue
                    selected.append(pair)
                    selected_set.add(pair)
                    if len(selected) >= sample_size:
                        break
                if len(selected) >= sample_size:
                    break

        if not selected:
            empty = torch.empty(0, dtype=torch.long, device=device)
            return empty, empty

        neg_src = torch.tensor([pair[0] for pair in selected], dtype=torch.long, device=device)
        neg_dst = torch.tensor([pair[1] for pair in selected], dtype=torch.long, device=device)
        return neg_src, neg_dst

    def compute_loss_components(self, g):
        if int(g.num_nodes()) == 0:
            zero = torch.zeros((), device=g.device, requires_grad=True)
            return {
                "total_loss": zero,
                "node_recon_loss": zero.detach(),
                "structure_loss": zero.detach(),
            }

        masked_g, (mask_nodes, _keep_nodes) = self.encoding_mask_noise(g, self._mask_rate)
        recon, enc_rep = self.reconstruct(masked_g)

        if int(mask_nodes.shape[0]) > 0:
            x_init = g.ndata["attr"][mask_nodes]
            x_rec = recon[mask_nodes]
            node_recon_loss = self.criterion(x_rec, x_init)
        else:
            node_recon_loss = recon.new_zeros(())

        structure_loss = self._structure_loss(g, enc_rep)
        total_loss = node_recon_loss + structure_loss
        return {
            "total_loss": total_loss,
            "node_recon_loss": node_recon_loss,
            "structure_loss": structure_loss,
        }

    def compute_loss(self, g):
        return self.compute_loss_components(g)["total_loss"]

    def compute_node_reconstruction_errors(
        self,
        g,
        node_indices: Iterable[int] | None = None,
        batch_size: int | None = None,
    ) -> torch.Tensor:
        num_nodes = int(g.num_nodes())
        errors = torch.zeros(num_nodes, device=g.device)
        if num_nodes == 0:
            return errors

        original = g.ndata["attr"]
        indices = [int(idx) for idx in (node_indices if node_indices is not None else range(num_nodes))]
        if not indices:
            return errors

        current_batch_size = self._resolve_infer_batch_size(g.device, batch_size)
        cursor = 0
        with torch.no_grad():
            while cursor < len(indices):
                chunk = indices[cursor : cursor + current_batch_size]
                try:
                    chunk_errors = self._compute_node_reconstruction_errors_chunk(g, original, chunk)
                except RuntimeError as exc:
                    if not self._should_retry_smaller_batch(g.device, current_batch_size, exc):
                        raise
                    current_batch_size = max(1, current_batch_size // 2)
                    torch.cuda.empty_cache()
                    continue

                chunk_idx = torch.tensor(chunk, dtype=torch.long, device=g.device)
                errors[chunk_idx] = chunk_errors
                cursor += len(chunk)
        return errors

    def _resolve_infer_batch_size(self, device, override: int | None) -> int:
        if override is not None:
            return max(1, int(override))
        env_value = os.environ.get("DRSEC_GMAE_INFER_BATCH_SIZE")
        if env_value:
            try:
                return max(1, int(env_value))
            except ValueError:
                pass
        device_str = str(device)
        return 32 if device_str.startswith("cuda") else 8

    def _compute_node_reconstruction_errors_chunk(
        self,
        g,
        original: torch.Tensor,
        chunk: list[int],
    ) -> torch.Tensor:
        masked_graphs = []
        for idx in chunk:
            masked_g = g.clone()
            masked_g.ndata["attr"][idx] = self.enc_mask_token
            masked_graphs.append(masked_g)

        batched_g = dgl.batch(masked_graphs)
        recon, _ = self.reconstruct(batched_g)

        num_nodes = int(g.num_nodes())
        chunk_idx = torch.tensor(chunk, dtype=torch.long, device=g.device)
        graph_offsets = torch.arange(len(chunk), device=g.device, dtype=torch.long) * num_nodes
        batch_idx = graph_offsets + chunk_idx
        x_rec = recon[batch_idx]
        x_init = original[chunk_idx]
        return self._reconstruction_errors(x_rec, x_init)

    def _should_retry_smaller_batch(self, device, batch_size: int, exc: RuntimeError) -> bool:
        if batch_size <= 1 or not str(device).startswith("cuda"):
            return False
        msg = str(exc).lower()
        return "out of memory" in msg

    def embed(self, g):
        x = g.ndata["attr"].to(g.device)
        rep = self.encoder(g, x)
        return rep

    @property
    def enc_params(self):
        return self.encoder.parameters()

    @property
    def dec_params(self):
        return chain(*[self.encoder_to_decoder.parameters(), self.decoder.parameters()])
