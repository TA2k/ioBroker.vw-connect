.class final Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;
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
.field private final getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;*>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter<",
            "TREQUEST;*>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 5
    .line 6
    return-void
.end method

.method private static extractClientInfo(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/String;II)Z
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    if-lt p2, p3, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    invoke-virtual {p1, p2}, Ljava/lang/String;->charAt(I)C

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/16 v2, 0x22

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    if-ne v1, v2, :cond_2

    .line 13
    .line 14
    add-int/2addr p2, v3

    .line 15
    invoke-virtual {p1, v2, p2}, Ljava/lang/String;->indexOf(II)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-static {v1, p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HeaderParsingHelper;->notFound(II)Z

    .line 20
    .line 21
    .line 22
    move-result p3

    .line 23
    if-eqz p3, :cond_1

    .line 24
    .line 25
    return v0

    .line 26
    :cond_1
    invoke-static {p0, p1, p2, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;->extractClientInfo(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/String;II)Z

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0

    .line 31
    :cond_2
    invoke-virtual {p1, p2}, Ljava/lang/String;->charAt(I)C

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    const/16 v4, 0x5b

    .line 36
    .line 37
    if-ne v1, v4, :cond_4

    .line 38
    .line 39
    add-int/2addr p2, v3

    .line 40
    const/16 v1, 0x5d

    .line 41
    .line 42
    invoke-virtual {p1, v1, p2}, Ljava/lang/String;->indexOf(II)I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    invoke-static {v1, p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HeaderParsingHelper;->notFound(II)Z

    .line 47
    .line 48
    .line 49
    move-result p3

    .line 50
    if-eqz p3, :cond_3

    .line 51
    .line 52
    return v0

    .line 53
    :cond_3
    invoke-virtual {p1, p2, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-interface {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;->setAddress(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    return v3

    .line 61
    :cond_4
    move v1, p2

    .line 62
    move v4, v0

    .line 63
    :goto_0
    if-ge v1, p3, :cond_a

    .line 64
    .line 65
    invoke-virtual {p1, v1}, Ljava/lang/String;->charAt(I)C

    .line 66
    .line 67
    .line 68
    move-result v5

    .line 69
    const/16 v6, 0x2e

    .line 70
    .line 71
    if-ne v5, v6, :cond_5

    .line 72
    .line 73
    move v4, v3

    .line 74
    :cond_5
    if-eqz v4, :cond_6

    .line 75
    .line 76
    const/16 v6, 0x3a

    .line 77
    .line 78
    if-ne v5, v6, :cond_6

    .line 79
    .line 80
    move v6, v3

    .line 81
    goto :goto_1

    .line 82
    :cond_6
    move v6, v0

    .line 83
    :goto_1
    const/16 v7, 0x2c

    .line 84
    .line 85
    if-eq v5, v7, :cond_8

    .line 86
    .line 87
    const/16 v7, 0x3b

    .line 88
    .line 89
    if-eq v5, v7, :cond_8

    .line 90
    .line 91
    if-eq v5, v2, :cond_8

    .line 92
    .line 93
    if-eqz v6, :cond_7

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_7
    add-int/lit8 v1, v1, 0x1

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_8
    :goto_2
    if-ne v1, p2, :cond_9

    .line 100
    .line 101
    return v0

    .line 102
    :cond_9
    invoke-virtual {p1, p2, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    invoke-interface {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;->setAddress(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    return v3

    .line 110
    :cond_a
    invoke-virtual {p1, p2, p3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    invoke-interface {p0, p1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;->setAddress(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    return v3
.end method

.method private static extractFromForwardedForHeader(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/String;)Z
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    invoke-static {p0, p1, v0, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;->extractClientInfo(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/String;II)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method private static extractFromForwardedHeader(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/String;)Z
    .locals 3

    .line 1
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "for="

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x0

    .line 14
    if-gez v0, :cond_0

    .line 15
    .line 16
    return v1

    .line 17
    :cond_0
    add-int/lit8 v0, v0, 0x4

    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    add-int/lit8 v2, v2, -0x1

    .line 24
    .line 25
    if-lt v0, v2, :cond_1

    .line 26
    .line 27
    return v1

    .line 28
    :cond_1
    const/16 v1, 0x3b

    .line 29
    .line 30
    invoke-virtual {p1, v1, v0}, Ljava/lang/String;->indexOf(II)I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-gez v1, :cond_2

    .line 35
    .line 36
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    :cond_2
    invoke-static {p0, p1, v0, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;->extractClientInfo(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/String;II)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    return p0
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
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 2
    .line 3
    const-string v1, "forwarded"

    .line 4
    .line 5
    invoke-interface {v0, p2, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getHttpRequestHeader(Ljava/lang/Object;Ljava/lang/String;)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-eqz v1, :cond_1

    .line 18
    .line 19
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    check-cast v1, Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {p1, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;->extractFromForwardedHeader(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/String;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 33
    .line 34
    const-string v1, "x-forwarded-for"

    .line 35
    .line 36
    invoke-interface {v0, p2, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getHttpRequestHeader(Ljava/lang/Object;Ljava/lang/String;)Ljava/util/List;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    :cond_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    if-eqz v1, :cond_3

    .line 49
    .line 50
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    check-cast v1, Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {p1, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;->extractFromForwardedForHeader(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/String;)Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-eqz v1, :cond_2

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_3
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    invoke-interface {v0, p2, v1}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkPeerAddress(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    invoke-interface {p1, v0}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;->setAddress(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAddressAndPortExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerAttributesGetter;

    .line 74
    .line 75
    invoke-interface {p0, p2, v1}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkPeerPort(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Integer;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-eqz p0, :cond_4

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 82
    .line 83
    .line 84
    move-result p2

    .line 85
    if-lez p2, :cond_4

    .line 86
    .line 87
    invoke-interface {p1, p0}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;->setPort(Ljava/lang/Integer;)V

    .line 88
    .line 89
    .line 90
    :cond_4
    :goto_0
    return-void
.end method
