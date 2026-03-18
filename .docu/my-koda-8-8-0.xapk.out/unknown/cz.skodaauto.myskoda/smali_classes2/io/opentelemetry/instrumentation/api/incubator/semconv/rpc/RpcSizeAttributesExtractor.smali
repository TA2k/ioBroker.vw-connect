.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
        "TREQUEST;TRESPONSE;>;"
    }
.end annotation


# static fields
.field static final RPC_REQUEST_SIZE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field static final RPC_RESPONSE_SIZE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter<",
            "TREQUEST;>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "rpc.request.size"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor;->RPC_REQUEST_SIZE:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    const-string v0, "rpc.response.size"

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor;->RPC_RESPONSE_SIZE:Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter<",
            "TREQUEST;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;

    .line 5
    .line 6
    return-void
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;)Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor;
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
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 0
    .param p4    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p5    # Ljava/lang/Throwable;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;TRESPONSE;",
            "Ljava/lang/Throwable;",
            ")V"
        }
    .end annotation

    .line 1
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor;->RPC_REQUEST_SIZE:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    iget-object p4, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;

    .line 4
    .line 5
    invoke-interface {p4, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;->getRequestSize(Ljava/lang/Object;)Ljava/lang/Long;

    .line 6
    .line 7
    .line 8
    move-result-object p4

    .line 9
    invoke-static {p1, p2, p4}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor;->RPC_RESPONSE_SIZE:Lio/opentelemetry/api/common/AttributeKey;

    .line 13
    .line 14
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcSizeAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;

    .line 15
    .line 16
    invoke-interface {p0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/rpc/RpcAttributesGetter;->getResponseSize(Ljava/lang/Object;)Ljava/lang/Long;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-static {p1, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    return-void
.end method
