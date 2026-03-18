.class public final Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesExtractor;
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
.field private final internalExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor<",
            "TREQUEST;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter<",
            "TREQUEST;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;

    .line 5
    .line 6
    new-instance v1, Lio/opentelemetry/instrumentation/api/semconv/network/internal/ServerAddressAndPortExtractor;

    .line 7
    .line 8
    invoke-static {}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;->noop()Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-direct {v1, p1, v2}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/ServerAddressAndPortExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;)V

    .line 13
    .line 14
    .line 15
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesExtractor;->internalExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;

    .line 19
    .line 20
    return-void
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesExtractor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter<",
            "TREQUEST;>;)",
            "Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesGetter;)V

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
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/ServerAttributesExtractor;->internalExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
