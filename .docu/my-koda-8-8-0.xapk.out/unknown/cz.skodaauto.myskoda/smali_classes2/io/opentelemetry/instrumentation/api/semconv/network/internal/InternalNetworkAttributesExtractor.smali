.class public final Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field private final captureLocalSocketAttributes:Z

.field private final captureProtocolAttributes:Z

.field private final getter:Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;ZZ)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter<",
            "TREQUEST;TRESPONSE;>;ZZ)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;

    .line 5
    .line 6
    iput-boolean p2, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->captureProtocolAttributes:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->captureLocalSocketAttributes:Z

    .line 9
    .line 10
    return-void
.end method

.method private static lowercase(Ljava/lang/String;)Ljava/lang/String;
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
.method public onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 4
    .param p3    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "TREQUEST;TRESPONSE;)V"
        }
    .end annotation

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->captureProtocolAttributes:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_TRANSPORT:Lio/opentelemetry/api/common/AttributeKey;

    .line 6
    .line 7
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;

    .line 8
    .line 9
    invoke-interface {v1, p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkTransport(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-static {v1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->lowercase(Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    sget-object v0, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 21
    .line 22
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;

    .line 23
    .line 24
    invoke-interface {v1, p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkType(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-static {v1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->lowercase(Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-static {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    sget-object v0, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_PROTOCOL_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 36
    .line 37
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;

    .line 38
    .line 39
    invoke-interface {v1, p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkProtocolName(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-static {v1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->lowercase(Ljava/lang/String;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-static {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    sget-object v0, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_PROTOCOL_VERSION:Lio/opentelemetry/api/common/AttributeKey;

    .line 51
    .line 52
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;

    .line 53
    .line 54
    invoke-interface {v1, p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkProtocolVersion(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-static {v1}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->lowercase(Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    invoke-static {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :cond_0
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->captureLocalSocketAttributes:Z

    .line 66
    .line 67
    if-eqz v0, :cond_1

    .line 68
    .line 69
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;

    .line 70
    .line 71
    invoke-interface {v0, p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkLocalAddress(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    if-eqz v0, :cond_1

    .line 76
    .line 77
    sget-object v1, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_LOCAL_ADDRESS:Lio/opentelemetry/api/common/AttributeKey;

    .line 78
    .line 79
    invoke-static {p1, v1, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;

    .line 83
    .line 84
    invoke-interface {v0, p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkLocalPort(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Integer;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    if-eqz v0, :cond_1

    .line 89
    .line 90
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-lez v1, :cond_1

    .line 95
    .line 96
    sget-object v1, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_LOCAL_PORT:Lio/opentelemetry/api/common/AttributeKey;

    .line 97
    .line 98
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    int-to-long v2, v0

    .line 103
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    invoke-static {p1, v1, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;

    .line 111
    .line 112
    invoke-interface {v0, p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkPeerAddress(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    if-eqz v0, :cond_2

    .line 117
    .line 118
    sget-object v1, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_PEER_ADDRESS:Lio/opentelemetry/api/common/AttributeKey;

    .line 119
    .line 120
    invoke-static {p1, v1, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;

    .line 124
    .line 125
    invoke-interface {p0, p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/NetworkAttributesGetter;->getNetworkPeerPort(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Integer;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    if-eqz p0, :cond_2

    .line 130
    .line 131
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 132
    .line 133
    .line 134
    move-result p2

    .line 135
    if-lez p2, :cond_2

    .line 136
    .line 137
    sget-object p2, Lio/opentelemetry/semconv/NetworkAttributes;->NETWORK_PEER_PORT:Lio/opentelemetry/api/common/AttributeKey;

    .line 138
    .line 139
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 140
    .line 141
    .line 142
    move-result p0

    .line 143
    int-to-long v0, p0

    .line 144
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    invoke-static {p1, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    :cond_2
    return-void
.end method
