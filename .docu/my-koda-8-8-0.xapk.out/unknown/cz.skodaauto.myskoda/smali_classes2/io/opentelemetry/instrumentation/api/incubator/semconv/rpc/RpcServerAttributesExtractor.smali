.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcServerAttributesExtractor;
.super Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcCommonAttributesExtractor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcCommonAttributesExtractor<",
        "TREQUEST;TRESPONSE;>;",
        "Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;"
    }
.end annotation


# direct methods
.method private constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter<",
            "TREQUEST;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcCommonAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcServerAttributesExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcServerAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public internalGetSpanKey()Lio/opentelemetry/instrumentation/api/internal/SpanKey;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->RPC_SERVER:Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 2
    .line 3
    return-object p0
.end method
