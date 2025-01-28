### pre-requisite
- install rust and cargo. can be installed from [here](https://www.rust-lang.org/tools/install)
- verify the installation by running `cargo --version` and `rustc --version`
- install cross
```bash
cargo install cross --force
```
- have docker installed, because cross uses docker to build the binaries for different platforms
- adjust `changeme` [src/creds.rs](./src/creds.rs)

### windows arm64
```bash
cross build --release --target aarch64-pc-windows-msv
```

### windows x86_64
```bash
cross build --release --target x86_64-pc-windows-msvc
```


### linux arm64 debian
```bash
cross build --release --target aarch64-unknown-linux-gnu
```


### linux x86_64 debian
```bash
cross build --release --target x86_64-unknown-linux-gnu
```

### linux x86_64 musl / alpine
```bash
cross build --release --target x86_64-unknown-linux-musl
```

### linux arm64 musl / alpine
```bash
cross build --release --target aarch64-unknown-linux-musl
```


### build and push your docker image to docker hub or any other registry you want

feel free to adjust the `BINARY_FILE` and `IMAGE_NAME` in the following command
the `BINARY_FILE` is the path to the binary file that you want to build the docker image

normally you want to use `musl` target for alpine images for slim image. in this Dockerfile, we are using `x86_64-unknown-linux-musl` target.

please check your node architecture before building the image. you can check it by running `uname -m` in the existing pod exec terminal. build the image for the same architecture.

```bash
docker build --build-arg BINARY_FILE=./target/x86_64-unknown-linux-musl/release/regcred-ecr -t <your-docker-username>/<your-image-name>:<tag> .
```

### push the image to docker hub
```bash
docker push <your-docker-username>/<your-image-name>:<tag>
```


see examples cronjob yaml file in [Link to job.example.yaml](./examples/job.example.yaml) directory


