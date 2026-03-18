.class public final Lio/opentelemetry/instrumentation/api/semconv/network/internal/ClientAddressAndPortExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor<",
        "TREQUEST;>;"
    }
.end annotation


# instance fields
.field private final fallbackAddressAndPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor<",
            "TREQUEST;>;"
        }
    .end annotation
.end field

.field private final getter:Lio/opentelemetry/instrumentation/api/semconv/network/ClientAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/ClientAttributesGetter<",
            "TREQUEST;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/network/ClientAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/ClientAttributesGetter<",
            "TREQUEST;>;",
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor<",
            "TREQUEST;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/ClientAddressAndPortExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/ClientAttributesGetter;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/ClientAddressAndPortExtractor;->fallbackAddressAndPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public extract(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/Object;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/ClientAddressAndPortExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/ClientAttributesGetter;

    .line 2
    .line 3
    invoke-interface {v0, p2}, Lio/opentelemetry/instrumentation/api/semconv/network/ClientAttributesGetter;->getClientAddress(Ljava/lang/Object;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/ClientAddressAndPortExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/ClientAttributesGetter;

    .line 8
    .line 9
    invoke-interface {v1, p2}, Lio/opentelemetry/instrumentation/api/semconv/network/ClientAttributesGetter;->getClientPort(Ljava/lang/Object;)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/ClientAddressAndPortExtractor;->fallbackAddressAndPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;

    .line 18
    .line 19
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;->extract(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    invoke-interface {p1, v0}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;->setAddress(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-interface {p1, v1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;->setPort(Ljava/lang/Integer;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
