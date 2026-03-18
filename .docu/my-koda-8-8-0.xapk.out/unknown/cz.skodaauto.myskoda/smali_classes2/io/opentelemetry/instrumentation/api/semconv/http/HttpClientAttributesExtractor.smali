.class public final Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;
.super Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor<",
        "TREQUEST;TRESPONSE;",
        "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
        "TREQUEST;TRESPONSE;>;>;",
        "Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;"
    }
.end annotation


# static fields
.field private static final PARAMS_TO_REDACT:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final internalNetworkExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field

.field private final internalServerExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor<",
            "TREQUEST;>;"
        }
    .end annotation
.end field

.field private final redactQueryParameters:Z

.field private final resendCountIncrementer:Ljava/util/function/ToIntFunction;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/ToIntFunction<",
            "Lio/opentelemetry/context/Context;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    const-string v1, "sig"

    .line 4
    .line 5
    const-string v2, "X-Goog-Signature"

    .line 6
    .line 7
    const-string v3, "AWSAccessKeyId"

    .line 8
    .line 9
    const-string v4, "Signature"

    .line 10
    .line 11
    filled-new-array {v3, v4, v1, v2}, [Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->PARAMS_TO_REDACT:Ljava/util/Set;

    .line 23
    .line 24
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;)V
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;)V"
        }
    .end annotation

    .line 1
    iget-object v1, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->httpAttributesGetter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

    .line 2
    .line 3
    sget-object v2, Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;->CLIENT:Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;

    .line 4
    .line 5
    iget-object v3, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->capturedRequestHeaders:Ljava/util/List;

    .line 6
    .line 7
    iget-object v4, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->capturedResponseHeaders:Ljava/util/List;

    .line 8
    .line 9
    iget-object v5, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->knownMethods:Ljava/util/Set;

    .line 10
    .line 11
    move-object v0, p0

    .line 12
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;Ljava/util/List;Ljava/util/List;Ljava/util/Set;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->buildNetworkExtractor()Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    iput-object p0, v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->internalNetworkExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;

    .line 20
    .line 21
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->buildServerExtractor()Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    iput-object p0, v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->internalServerExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;

    .line 26
    .line 27
    iget-object p0, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->resendCountIncrementer:Ljava/util/function/ToIntFunction;

    .line 28
    .line 29
    iput-object p0, v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->resendCountIncrementer:Ljava/util/function/ToIntFunction;

    .line 30
    .line 31
    iget-boolean p0, p1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->redactQueryParameters:Z

    .line 32
    .line 33
    iput-boolean p0, v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->redactQueryParameters:Z

    .line 34
    .line 35
    return-void
.end method

.method public static builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;-><init>(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private static containsParamToRedact(Ljava/lang/String;)Z
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->PARAMS_TO_REDACT:Ljava/util/Set;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {p0, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    return p0

    .line 27
    :cond_1
    const/4 p0, 0x0

    .line 28
    return p0
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->builder(Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractorBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static redactQueryParameters(Ljava/lang/String;)Ljava/lang/String;
    .locals 9

    .line 1
    const/16 v0, 0x3f

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->indexOf(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, -0x1

    .line 8
    if-eq v0, v1, :cond_7

    .line 9
    .line 10
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->containsParamToRedact(Ljava/lang/String;)Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    goto/16 :goto_4

    .line 17
    .line 18
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 21
    .line 22
    .line 23
    new-instance v2, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 26
    .line 27
    .line 28
    add-int/lit8 v3, v0, 0x1

    .line 29
    .line 30
    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    const/4 v5, 0x0

    .line 35
    if-ge v3, v4, :cond_6

    .line 36
    .line 37
    invoke-virtual {p0, v3}, Ljava/lang/String;->charAt(I)C

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    const/16 v6, 0x23

    .line 42
    .line 43
    const/16 v7, 0x26

    .line 44
    .line 45
    const/16 v8, 0x3d

    .line 46
    .line 47
    if-ne v4, v8, :cond_2

    .line 48
    .line 49
    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    sget-object v4, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->PARAMS_TO_REDACT:Ljava/util/Set;

    .line 53
    .line 54
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v5

    .line 58
    invoke-interface {v4, v5}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    if-eqz v4, :cond_5

    .line 63
    .line 64
    const-string v4, "REDACTED"

    .line 65
    .line 66
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    :goto_1
    add-int/lit8 v4, v3, 0x1

    .line 70
    .line 71
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 72
    .line 73
    .line 74
    move-result v5

    .line 75
    if-ge v4, v5, :cond_5

    .line 76
    .line 77
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 78
    .line 79
    .line 80
    move-result v5

    .line 81
    if-eq v5, v7, :cond_5

    .line 82
    .line 83
    if-ne v5, v6, :cond_1

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_1
    move v3, v4

    .line 87
    goto :goto_1

    .line 88
    :cond_2
    if-ne v4, v7, :cond_3

    .line 89
    .line 90
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 94
    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_3
    if-ne v4, v6, :cond_4

    .line 98
    .line 99
    invoke-virtual {p0, v3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_4
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    :cond_5
    :goto_2
    add-int/lit8 v3, v3, 0x1

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :cond_6
    :goto_3
    new-instance v2, Ljava/lang/StringBuilder;

    .line 117
    .line 118
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 119
    .line 120
    .line 121
    invoke-virtual {p0, v5, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string p0, "?"

    .line 129
    .line 130
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    :cond_7
    :goto_4
    return-object p0
.end method

.method private static redactUserInfo(Ljava/lang/String;)Ljava/lang/String;
    .locals 8

    .line 1
    const/16 v0, 0x3a

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->indexOf(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, -0x1

    .line 8
    if-ne v0, v1, :cond_0

    .line 9
    .line 10
    goto :goto_2

    .line 11
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    add-int/lit8 v3, v0, 0x2

    .line 16
    .line 17
    if-le v2, v3, :cond_6

    .line 18
    .line 19
    add-int/lit8 v4, v0, 0x1

    .line 20
    .line 21
    invoke-virtual {p0, v4}, Ljava/lang/String;->charAt(I)C

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    const/16 v5, 0x2f

    .line 26
    .line 27
    if-ne v4, v5, :cond_6

    .line 28
    .line 29
    invoke-virtual {p0, v3}, Ljava/lang/String;->charAt(I)C

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eq v3, v5, :cond_1

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_1
    add-int/lit8 v0, v0, 0x3

    .line 37
    .line 38
    move v3, v0

    .line 39
    move v4, v1

    .line 40
    :goto_0
    if-ge v3, v2, :cond_4

    .line 41
    .line 42
    invoke-virtual {p0, v3}, Ljava/lang/String;->charAt(I)C

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    const/16 v7, 0x40

    .line 47
    .line 48
    if-ne v6, v7, :cond_2

    .line 49
    .line 50
    move v4, v3

    .line 51
    :cond_2
    if-eq v6, v5, :cond_4

    .line 52
    .line 53
    const/16 v7, 0x3f

    .line 54
    .line 55
    if-eq v6, v7, :cond_4

    .line 56
    .line 57
    const/16 v7, 0x23

    .line 58
    .line 59
    if-ne v6, v7, :cond_3

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    add-int/lit8 v3, v3, 0x1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_4
    :goto_1
    if-eq v4, v1, :cond_6

    .line 66
    .line 67
    add-int/lit8 v2, v2, -0x1

    .line 68
    .line 69
    if-ne v4, v2, :cond_5

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 73
    .line 74
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 75
    .line 76
    .line 77
    const/4 v2, 0x0

    .line 78
    invoke-virtual {p0, v2, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v0, "REDACTED:REDACTED"

    .line 86
    .line 87
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0, v4}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    :cond_6
    :goto_2
    return-object p0
.end method

.method private stripSensitiveData(Ljava/lang/String;)Ljava/lang/String;
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->redactUserInfo(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->redactQueryParameters:Z

    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->redactQueryParameters(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_1
    :goto_0
    return-object p1
.end method


# virtual methods
.method public internalGetSpanKey()Lio/opentelemetry/instrumentation/api/internal/SpanKey;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->HTTP_CLIENT:Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 2
    .line 3
    return-object p0
.end method

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
    invoke-super/range {p0 .. p5}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->internalNetworkExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;

    .line 5
    .line 6
    invoke-virtual {p0, p1, p3, p4}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalNetworkAttributesExtractor;->onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    invoke-super {p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->internalServerExtractor:Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;

    .line 5
    .line 6
    invoke-virtual {v0, p1, p3}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/InternalServerAttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/semconv/http/HttpCommonAttributesGetter;

    .line 10
    .line 11
    check-cast v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;

    .line 12
    .line 13
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesGetter;->getUrlFull(Ljava/lang/Object;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p3

    .line 17
    invoke-direct {p0, p3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->stripSensitiveData(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p3

    .line 21
    sget-object v0, Lio/opentelemetry/semconv/UrlAttributes;->URL_FULL:Lio/opentelemetry/api/common/AttributeKey;

    .line 22
    .line 23
    invoke-static {p1, v0, p3}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpClientAttributesExtractor;->resendCountIncrementer:Ljava/util/function/ToIntFunction;

    .line 27
    .line 28
    invoke-interface {p0, p2}, Ljava/util/function/ToIntFunction;->applyAsInt(Ljava/lang/Object;)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-lez p0, :cond_0

    .line 33
    .line 34
    sget-object p2, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_REQUEST_RESEND_COUNT:Lio/opentelemetry/api/common/AttributeKey;

    .line 35
    .line 36
    invoke-interface {p1, p2, p0}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Lio/opentelemetry/api/common/AttributeKey;I)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 37
    .line 38
    .line 39
    :cond_0
    return-void
.end method
