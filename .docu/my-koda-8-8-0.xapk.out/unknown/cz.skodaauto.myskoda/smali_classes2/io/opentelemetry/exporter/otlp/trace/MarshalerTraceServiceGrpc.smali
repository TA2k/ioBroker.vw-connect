.class final Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;
    }
.end annotation


# static fields
.field private static final REQUEST_MARSHALLER:Lio/grpc/MethodDescriptor$Marshaller;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/grpc/MethodDescriptor$Marshaller<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            ">;"
        }
    .end annotation
.end field

.field private static final RESPONSE_MARSHALER:Lio/grpc/MethodDescriptor$Marshaller;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/grpc/MethodDescriptor$Marshaller<",
            "Lio/opentelemetry/exporter/otlp/trace/ExportTraceServiceResponse;",
            ">;"
        }
    .end annotation
.end field

.field private static final SERVICE_NAME:Ljava/lang/String; = "opentelemetry.proto.collector.trace.v1.TraceService"

.field private static final getExportMethod:Lio/grpc/MethodDescriptor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/grpc/MethodDescriptor<",
            "Lio/opentelemetry/exporter/internal/marshal/Marshaler;",
            "Lio/opentelemetry/exporter/otlp/trace/ExportTraceServiceResponse;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$1;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc;->REQUEST_MARSHALLER:Lio/grpc/MethodDescriptor$Marshaller;

    .line 7
    .line 8
    new-instance v1, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$2;

    .line 9
    .line 10
    invoke-direct {v1}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$2;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc;->RESPONSE_MARSHALER:Lio/grpc/MethodDescriptor$Marshaller;

    .line 14
    .line 15
    invoke-static {}, Lio/grpc/MethodDescriptor;->newBuilder()Lio/grpc/MethodDescriptor$Builder;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    sget-object v3, Lio/grpc/MethodDescriptor$MethodType;->UNARY:Lio/grpc/MethodDescriptor$MethodType;

    .line 20
    .line 21
    invoke-virtual {v2, v3}, Lio/grpc/MethodDescriptor$Builder;->setType(Lio/grpc/MethodDescriptor$MethodType;)Lio/grpc/MethodDescriptor$Builder;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    const-string v3, "opentelemetry.proto.collector.trace.v1.TraceService"

    .line 26
    .line 27
    const-string v4, "Export"

    .line 28
    .line 29
    invoke-static {v3, v4}, Lio/grpc/MethodDescriptor;->generateFullMethodName(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    invoke-virtual {v2, v3}, Lio/grpc/MethodDescriptor$Builder;->setFullMethodName(Ljava/lang/String;)Lio/grpc/MethodDescriptor$Builder;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-virtual {v2, v0}, Lio/grpc/MethodDescriptor$Builder;->setRequestMarshaller(Lio/grpc/MethodDescriptor$Marshaller;)Lio/grpc/MethodDescriptor$Builder;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-virtual {v0, v1}, Lio/grpc/MethodDescriptor$Builder;->setResponseMarshaller(Lio/grpc/MethodDescriptor$Marshaller;)Lio/grpc/MethodDescriptor$Builder;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-virtual {v0}, Lio/grpc/MethodDescriptor$Builder;->build()Lio/grpc/MethodDescriptor;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    sput-object v0, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc;->getExportMethod:Lio/grpc/MethodDescriptor;

    .line 50
    .line 51
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic access$000()Lio/grpc/MethodDescriptor;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc;->getExportMethod:Lio/grpc/MethodDescriptor;

    .line 2
    .line 3
    return-object v0
.end method

.method private static synthetic lambda$newFutureStub$0(Ljava/lang/String;Lio/grpc/Channel;Lio/grpc/CallOptions;)Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;

    .line 2
    .line 3
    invoke-virtual {p2, p0}, Lio/grpc/CallOptions;->withAuthority(Ljava/lang/String;)Lio/grpc/CallOptions;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 p2, 0x0

    .line 8
    invoke-direct {v0, p1, p0, p2}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;-><init>(Lio/grpc/Channel;Lio/grpc/CallOptions;Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$1;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public static newFutureStub(Lio/grpc/Channel;Ljava/lang/String;)Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    new-instance p1, Lio/opentelemetry/exporter/otlp/logs/a;

    .line 2
    .line 3
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {p1, p0}, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;->newStub(Lio/grpc/stub/AbstractStub$StubFactory;Lio/grpc/Channel;)Lio/grpc/stub/AbstractStub;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    check-cast p0, Lio/opentelemetry/exporter/otlp/trace/MarshalerTraceServiceGrpc$TraceServiceFutureStub;

    .line 11
    .line 12
    return-object p0
.end method
