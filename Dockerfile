FROM golangci/golangci-lint:v1.61.0@sha256:e47065d755ca0afeac9df866d1dabdc99f439653a43fe234e05f50d9c36b6b90 as golangci-lint
RUN adduser --disabled-password --gecos '' nonroot
USER nonroot
RUN adduser --disabled-password --gecos '' nonroot
USER nonroot
FROM hadolint/hadolint:2.12.0@sha256:30a8fd2e785ab6176eed53f74769e04f125afb2f74a6c52aef7d463583b6d45e as hadolint
RUN adduser --disabled-password --gecos '' nonroot
USER nonroot
RUN adduser --disabled-password --gecos '' nonroot
USER nonroot
