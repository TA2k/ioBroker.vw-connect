.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;
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
.field private static final PEER_SERVICE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter<",
            "TREQUEST;>;"
        }
    .end annotation
.end field

.field private final peerServiceResolver:Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "peer.service"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;->PEER_SERVICE:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter<",
            "TREQUEST;>;",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;->attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;->peerServiceResolver:Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;

    .line 7
    .line 8
    return-void
.end method

.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;->lambda$mapToPeerService$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;)Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter<",
            "TREQUEST;>;",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;",
            ")",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private static synthetic lambda$mapToPeerService$0()Ljava/lang/String;
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    return-object v0
.end method

.method private mapToPeerService(Ljava/lang/String;Ljava/lang/Integer;)Ljava/lang/String;
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p2    # Ljava/lang/Integer;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;->peerServiceResolver:Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;

    .line 6
    .line 7
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/a;

    .line 8
    .line 9
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-interface {p0, p1, p2, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;->resolveService(Ljava/lang/String;Ljava/lang/Integer;Ljava/util/function/Supplier;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
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
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;->peerServiceResolver:Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;

    .line 2
    .line 3
    invoke-interface {p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    if-eqz p2, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;->attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;

    .line 11
    .line 12
    invoke-interface {p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;->getServerAddress(Ljava/lang/Object;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p2

    .line 16
    iget-object p4, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;->attributesGetter:Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;

    .line 17
    .line 18
    invoke-interface {p4, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;->getServerPort(Ljava/lang/Object;)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object p3

    .line 22
    invoke-direct {p0, p2, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;->mapToPeerService(Ljava/lang/String;Ljava/lang/Integer;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceAttributesExtractor;->PEER_SERVICE:Lio/opentelemetry/api/common/AttributeKey;

    .line 29
    .line 30
    invoke-interface {p1, p2, p0}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 31
    .line 32
    .line 33
    :cond_1
    :goto_0
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
