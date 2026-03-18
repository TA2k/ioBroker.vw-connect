.class public final Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesExtractor;
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


# instance fields
.field private final internalExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;

    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    invoke-direct {v0, p1, v1, v1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;ZZ)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesExtractor;->internalExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;

    .line 11
    .line 12
    return-void
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesExtractor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;)V

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
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesExtractor;->internalExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p3, p4}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
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
