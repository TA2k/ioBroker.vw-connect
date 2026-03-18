.class public final Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field private final addressAndPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor<",
            "TREQUEST;>;"
        }
    .end annotation
.end field

.field private final capturePort:Z


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;Z)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor<",
            "TREQUEST;>;Z)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;->addressAndPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;

    .line 5
    .line 6
    iput-boolean p2, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;->capturePort:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public onStart(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;->addressAndPortExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;

    .line 2
    .line 3
    invoke-interface {v0, p2}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;->extract(Ljava/lang/Object;)Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    iget-object v0, p2, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;->address:Ljava/lang/String;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    sget-object v1, Lio/opentelemetry/semconv/ClientAttributes;->CLIENT_ADDRESS:Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    invoke-static {p1, v1, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalClientAttributesExtractor;->capturePort:Z

    .line 17
    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    iget-object p0, p2, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;->port:Ljava/lang/Integer;

    .line 21
    .line 22
    if-eqz p0, :cond_0

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-lez p0, :cond_0

    .line 29
    .line 30
    sget-object p0, Lio/opentelemetry/semconv/ClientAttributes;->CLIENT_PORT:Lio/opentelemetry/api/common/AttributeKey;

    .line 31
    .line 32
    iget-object p2, p2, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPort;->port:Ljava/lang/Integer;

    .line 33
    .line 34
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 35
    .line 36
    .line 37
    move-result p2

    .line 38
    int-to-long v0, p2

    .line 39
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    invoke-static {p1, p0, p2}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    return-void
.end method
