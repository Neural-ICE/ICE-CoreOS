# AI quickstart — run models on ICE-CoreOS

ICE-CoreOS is an **immutable, container-native** OS. AI runtimes (Ollama, vLLM,
the Hugging Face CLI, …) are **not baked into the base image** — they run as
**containers** that get the GPU through the NVIDIA **CDI** spec ICE-CoreOS
generates at boot (`nvidia-cdi-generate.service`). This keeps the base small,
secure, and OTA-light, while you run and update workloads independently.

`podman` and `nvidia-container-toolkit` (CDI) are already set up. Below, GPU
access is requested with `--device nvidia.com/gpu=all`.

## 1. Verify GPU access from a container

Blackwell (GB10) needs **CUDA ≥ 12.8**. The container's CUDA version must be
**≤ the driver's CUDA version** — run `nvidia-smi` and read the `CUDA Version`
field (it shows **13.2** with the bundled r595 driver). So pick a CUDA image at
or below that (e.g. `13.2.1-base-ubi9`; see
<https://hub.docker.com/r/nvidia/cuda/tags>):

```sh
podman run --rm --device nvidia.com/gpu=all \
  docker.io/nvidia/cuda:13.2.1-base-ubi9 nvidia-smi
```

You should see the GB10 GPU and `CUDA Version: 13.2` listed.

## 2. Ollama (one-liner)

```sh
podman run -d --name ollama --device nvidia.com/gpu=all \
  -p 11434:11434 -v ollama:/root/.ollama docker.io/ollama/ollama:latest
podman exec -it ollama ollama run llama3.2
```

## 3. vLLM (OpenAI-compatible server)

```sh
podman run -d --name vllm --device nvidia.com/gpu=all \
  -p 8000:8000 -v hf-cache:/root/.cache/huggingface \
  docker.io/vllm/vllm-openai:latest \
  --model meta-llama/Llama-3.2-3B-Instruct --host 0.0.0.0 --port 8000
curl http://localhost:8000/v1/models
```

## 4. Hugging Face CLI (no host install)

```sh
podman run --rm -it -v hf-cache:/root/.cache/huggingface \
  -e HF_TOKEN="$HF_TOKEN" docker.io/python:3.12-slim \
  bash -lc 'pip install -q huggingface_hub[cli] && hf download <repo-id>'
```

## 5. Run them as services (Quadlets)

For workloads that should start at boot and restart on failure, use the example
[Quadlets](../examples/quadlets/) (`ollama.container`, `vllm.container`):

```sh
sudo cp examples/quadlets/ollama.* /etc/containers/systemd/
sudo systemctl daemon-reload
sudo systemctl start ollama
```

## Notes

- **Store models on the encrypted data volume.** Point your volumes / `HF_HOME`
  at `/var/lib/neural-ice/data/...` so big model caches land on the encrypted,
  TPM-unlocked data partition (not the 300 GiB system volume).
- **Rootless vs rootful.** The examples are rootful for simplicity. Rootless
  Podman works too (run as `core`); ensure CDI is readable and use
  `podman --userns=keep-id` patterns as needed.
- **SELinux.** If the GPU device nodes are blocked, add
  `--security-opt=label=disable` (one-liner) or `SecurityLabelDisable=true`
  (Quadlet).
