.class final Lio/opentelemetry/instrumentation/api/semconv/http/HostAddressAndPortExtractor;
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
.field private final getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter<",
            "TREQUEST;*>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter<",
            "TREQUEST;*>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HostAddressAndPortExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public extract(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/Object;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HostAddressAndPortExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 2
    .line 3
    const-string v0, "host"

    .line 4
    .line 5
    invoke-interface {p0, p2, v0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getHttpRequestHeader(Ljava/lang/Object;Ljava/lang/String;)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->firstHeaderValue(Ljava/util/List;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    const/16 p2, 0x3a

    .line 17
    .line 18
    invoke-virtual {p0, p2}, Ljava/lang/String;->indexOf(I)I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    const/4 v0, -0x1

    .line 23
    if-ne p2, v0, :cond_1

    .line 24
    .line 25
    invoke-interface {p1, p0}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;->setAddress(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_1
    const/4 v0, 0x0

    .line 30
    invoke-virtual {p0, v0, p2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-interface {p1, v0}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;->setAddress(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    add-int/lit8 p2, p2, 0x1

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    invoke-static {p1, p0, p2, v0}, Lio/opentelemetry/instrumentation/api/semconv/http/HeaderParsingHelper;->setPort(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/String;II)V

    .line 44
    .line 45
    .line 46
    return-void
.end method
