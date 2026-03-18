.class final Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;
.super Lio/opentelemetry/exporter/internal/grpc/MarshalerServiceStub;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "TraceServiceFutureStub"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lio/opentelemetry/exporter/internal/grpc/MarshalerServiceStub<",
        "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
        "Lio/opentelemetry/exporter/otlp/trace/ExportTraceServiceResponse;",
        "Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;",
        ">;"
    }
.end annotation


# direct methods
.method private constructor <init>(Lio/grpc/Channel;Lio/grpc/CallOptions;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/internal/grpc/MarshalerServiceStub;-><init>(Lio/grpc/Channel;Lio/grpc/CallOptions;)V

    return-void
.end method

.method public synthetic constructor <init>(Lio/grpc/Channel;Lio/grpc/CallOptions;Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;-><init>(Lio/grpc/Channel;Lio/grpc/CallOptions;)V

    return-void
.end method


# virtual methods
.method public bridge synthetic build(Lio/grpc/Channel;Lio/grpc/CallOptions;)Lio/grpc/stub/AbstractStub;
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;->build(Lio/grpc/Channel;Lio/grpc/CallOptions;)Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;

    move-result-object p0

    return-object p0
.end method

.method public build(Lio/grpc/Channel;Lio/grpc/CallOptions;)Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;
    .locals 0

    .line 2
    new-instance p0, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;

    invoke-direct {p0, p1, p2}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;-><init>(Lio/grpc/Channel;Lio/grpc/CallOptions;)V

    return-object p0
.end method

.method public export(Lio/opentelemetry/exporter/internal/marshal/Marshaler;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ")",
            "Lcom/google/common/util/concurrent/ListenableFuture;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;->getChannel()Lio/grpc/Channel;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc;->access$000()Lio/grpc/MethodDescriptor;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {p0}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;->getCallOptions()Lio/grpc/CallOptions;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {v0, v1, p0}, Lio/grpc/Channel;->newCall(Lio/grpc/MethodDescriptor;Lio/grpc/CallOptions;)Lio/grpc/ClientCall;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-static {p0, p1}, Lio/grpc/stub/ClientCalls;->futureUnaryCall(Lio/grpc/ClientCall;Ljava/lang/Object;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
