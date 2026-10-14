# Package an already tested static artifact; compile and qualify before building.
FROM scratch
COPY --chmod=0555 target/x86_64-unknown-linux-musl/release/pumgye /pumgye
USER 65532:65532
ENTRYPOINT ["/pumgye"]
