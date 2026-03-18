.class Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/grpc/MethodDescriptor$Marshaller;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lio/grpc/MethodDescriptor$Marshaller<",
        "Lio/opentelemetry/exporter/otlp/trace/ExportTraceServiceResponse;",
        ">;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public parse(Ljava/io/InputStream;)Lio/opentelemetry/exporter/otlp/trace/ExportTraceServiceResponse;
    .locals 0

    .line 2
    sget-object p0, Lio/opentelemetry/exporter/otlp/trace/ExportTraceServiceResponse;->INSTANCE:Lio/opentelemetry/exporter/otlp/trace/ExportTraceServiceResponse;

    return-object p0
.end method

.method public bridge synthetic parse(Ljava/io/InputStream;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$2;->parse(Ljava/io/InputStream;)Lio/opentelemetry/exporter/otlp/trace/ExportTraceServiceResponse;

    move-result-object p0

    return-object p0
.end method

.method public stream(Lio/opentelemetry/exporter/otlp/trace/ExportTraceServiceResponse;)Ljava/io/InputStream;
    .locals 0

    .line 2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    const-string p1, "Only for parsing"

    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public bridge synthetic stream(Ljava/lang/Object;)Ljava/io/InputStream;
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/exporter/otlp/trace/ExportTraceServiceResponse;

    invoke-virtual {p0, p1}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$2;->stream(Lio/opentelemetry/exporter/otlp/trace/ExportTraceServiceResponse;)Ljava/io/InputStream;

    move-result-object p0

    return-object p0
.end method
