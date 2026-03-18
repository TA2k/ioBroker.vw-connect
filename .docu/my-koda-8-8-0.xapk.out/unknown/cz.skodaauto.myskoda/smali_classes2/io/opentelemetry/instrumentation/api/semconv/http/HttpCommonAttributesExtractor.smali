.class abstract Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;
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
        "GETTER::",
        "Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter<",
        "TREQUEST;TRESPONSE;>;:",
        "Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter<",
        "TREQUEST;TRESPONSE;>;>",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
        "TREQUEST;TRESPONSE;>;"
    }
.end annotation


# instance fields
.field private final capturedRequestHeaders:[Ljava/lang/String;

.field private final capturedResponseHeaders:[Ljava/lang/String;

.field final getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "TGETTER;"
        }
    .end annotation
.end field

.field private final knownMethods:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final statusCodeConverter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;Ljava/util/List;Ljava/util/List;Ljava/util/Set;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TGETTER;",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->statusCodeConverter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;

    .line 7
    .line 8
    invoke-static {p3}, Lio/opentelemetry/instrumentation/api/semconv/http/CapturedHttpHeadersUtil;->lowercase(Ljava/util/List;)[Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->capturedRequestHeaders:[Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {p4}, Lio/opentelemetry/instrumentation/api/semconv/http/CapturedHttpHeadersUtil;->lowercase(Ljava/util/List;)[Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->capturedResponseHeaders:[Ljava/lang/String;

    .line 19
    .line 20
    new-instance p1, Ljava/util/HashSet;

    .line 21
    .line 22
    invoke-direct {p1, p5}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->knownMethods:Ljava/util/Set;

    .line 26
    .line 27
    return-void
.end method

.method public static firstHeaderValue(Ljava/util/List;)Ljava/lang/String;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    const/4 v0, 0x0

    .line 10
    invoke-interface {p0, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljava/lang/String;

    .line 15
    .line 16
    return-object p0
.end method

.method private static lowercaseStr(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .param p0    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 7
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
    const/4 p2, 0x0

    .line 2
    if-eqz p4, :cond_2

    .line 3
    .line 4
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 5
    .line 6
    invoke-interface {v0, p3, p4, p5}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getHttpResponseStatusCode(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)Ljava/lang/Integer;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-lez v1, :cond_0

    .line 17
    .line 18
    sget-object v1, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_RESPONSE_STATUS_CODE:Lio/opentelemetry/api/common/AttributeKey;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    int-to-long v2, v2

    .line 25
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-static {p1, v1, v2}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->capturedResponseHeaders:[Ljava/lang/String;

    .line 33
    .line 34
    array-length v2, v1

    .line 35
    const/4 v3, 0x0

    .line 36
    :goto_0
    if-ge v3, v2, :cond_3

    .line 37
    .line 38
    aget-object v4, v1, v3

    .line 39
    .line 40
    iget-object v5, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 41
    .line 42
    invoke-interface {v5, p3, p4, v4}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getHttpResponseHeader(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)Ljava/util/List;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    .line 47
    .line 48
    .line 49
    move-result v6

    .line 50
    if-nez v6, :cond_1

    .line 51
    .line 52
    invoke-static {v4}, Lio/opentelemetry/instrumentation/api/semconv/http/CapturedHttpHeadersUtil;->responseAttributeKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    invoke-static {p1, v4, v5}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :cond_1
    add-int/lit8 v3, v3, 0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    move-object v0, p2

    .line 63
    :cond_3
    if-eqz v0, :cond_4

    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-lez v1, :cond_4

    .line 70
    .line 71
    iget-object p5, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->statusCodeConverter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;

    .line 72
    .line 73
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 74
    .line 75
    .line 76
    move-result v1

    .line 77
    invoke-virtual {p5, v1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;->isError(I)Z

    .line 78
    .line 79
    .line 80
    move-result p5

    .line 81
    if-eqz p5, :cond_6

    .line 82
    .line 83
    invoke-virtual {v0}, Ljava/lang/Integer;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p2

    .line 87
    goto :goto_1

    .line 88
    :cond_4
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 89
    .line 90
    invoke-interface {p2, p3, p4, p5}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getErrorType(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p2

    .line 94
    if-nez p2, :cond_5

    .line 95
    .line 96
    if-eqz p5, :cond_5

    .line 97
    .line 98
    invoke-virtual {p5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    move-result-object p2

    .line 102
    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p2

    .line 106
    :cond_5
    if-nez p2, :cond_6

    .line 107
    .line 108
    const-string p2, "_OTHER"

    .line 109
    .line 110
    :cond_6
    :goto_1
    sget-object p5, Lio/opentelemetry/semconv/ErrorAttributes;->ERROR_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 111
    .line 112
    invoke-static {p1, p5, p2}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 116
    .line 117
    check-cast p2, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;

    .line 118
    .line 119
    invoke-interface {p2, p3, p4}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkProtocolName(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p2

    .line 123
    invoke-static {p2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->lowercaseStr(Ljava/lang/String;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p2

    .line 127
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 128
    .line 129
    check-cast p0, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;

    .line 130
    .line 131
    invoke-interface {p0, p3, p4}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkProtocolVersion(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->lowercaseStr(Ljava/lang/String;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    if-eqz p0, :cond_8

    .line 140
    .line 141
    const-string p3, "http"

    .line 142
    .line 143
    invoke-virtual {p3, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result p3

    .line 147
    if-nez p3, :cond_7

    .line 148
    .line 149
    sget-object p3, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_PROTOCOL_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 150
    .line 151
    invoke-static {p1, p3, p2}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    :cond_7
    sget-object p2, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_PROTOCOL_VERSION:Lio/opentelemetry/api/common/AttributeKey;

    .line 155
    .line 156
    invoke-static {p1, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    :cond_8
    return-void
.end method

.method public onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 2
    .line 3
    invoke-interface {p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getHttpRequestMethod(Ljava/lang/Object;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    if-eqz p2, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->knownMethods:Ljava/util/Set;

    .line 10
    .line 11
    invoke-interface {v0, p2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    sget-object v0, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_REQUEST_METHOD:Lio/opentelemetry/api/common/AttributeKey;

    .line 19
    .line 20
    const-string v1, "_OTHER"

    .line 21
    .line 22
    invoke-static {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    sget-object v0, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_REQUEST_METHOD_ORIGINAL:Lio/opentelemetry/api/common/AttributeKey;

    .line 26
    .line 27
    invoke-static {p1, v0, p2}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    :goto_0
    sget-object v0, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_REQUEST_METHOD:Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    invoke-static {p1, v0, p2}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    :goto_1
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->capturedRequestHeaders:[Ljava/lang/String;

    .line 37
    .line 38
    array-length v0, p2

    .line 39
    const/4 v1, 0x0

    .line 40
    :goto_2
    if-ge v1, v0, :cond_3

    .line 41
    .line 42
    aget-object v2, p2, v1

    .line 43
    .line 44
    iget-object v3, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 45
    .line 46
    invoke-interface {v3, p3, v2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;->getHttpRequestHeader(Ljava/lang/Object;Ljava/lang/String;)Ljava/util/List;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    if-nez v4, :cond_2

    .line 55
    .line 56
    invoke-static {v2}, Lio/opentelemetry/instrumentation/api/semconv/http/CapturedHttpHeadersUtil;->requestAttributeKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    invoke-static {p1, v2, v3}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_3
    return-void
.end method
