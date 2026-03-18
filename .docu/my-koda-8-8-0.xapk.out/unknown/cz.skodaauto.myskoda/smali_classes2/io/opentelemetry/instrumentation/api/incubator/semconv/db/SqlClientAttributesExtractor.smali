.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;
.super Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor<",
        "TREQUEST;TRESPONSE;",
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter<",
        "TREQUEST;TRESPONSE;>;>;"
    }
.end annotation


# static fields
.field private static final DB_OPERATION:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final DB_QUERY_PARAMETER:Lio/opentelemetry/semconv/AttributeKeyTemplate;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/semconv/AttributeKeyTemplate<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final DB_STATEMENT:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final SQL_CALL:Ljava/lang/String; = "CALL"


# instance fields
.field private final captureQueryParameters:Z

.field private final oldSemconvTableAttribute:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final statementSanitizationEnabled:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "db.operation"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->DB_OPERATION:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    const-string v0, "db.statement"

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->DB_STATEMENT:Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    const-string v0, "db.query.parameter"

    .line 18
    .line 19
    invoke-static {v0}, Lio/opentelemetry/semconv/AttributeKeyTemplate;->stringKeyTemplate(Ljava/lang/String;)Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->DB_QUERY_PARAMETER:Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 24
    .line 25
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;Lio/opentelemetry/api/common/AttributeKey;ZZ)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;ZZ)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;)V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->oldSemconvTableAttribute:Lio/opentelemetry/api/common/AttributeKey;

    .line 5
    .line 6
    if-nez p4, :cond_0

    .line 7
    .line 8
    if-eqz p3, :cond_0

    .line 9
    .line 10
    const/4 p1, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p1, 0x0

    .line 13
    :goto_0
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->statementSanitizationEnabled:Z

    .line 14
    .line 15
    iput-boolean p4, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->captureQueryParameters:Z

    .line 16
    .line 17
    return-void
.end method

.method public static builder(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->builder(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->build()Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static join(Ljava/lang/String;Ljava/util/Collection;)Ljava/lang/String;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    :cond_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method private setQueryParameters(Lio/opentelemetry/api/common/AttributesBuilder;ZLjava/util/Map;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Z",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->captureQueryParameters:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    if-nez p2, :cond_0

    .line 6
    .line 7
    if-eqz p3, :cond_0

    .line 8
    .line 9
    invoke-interface {p3}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    if-eqz p2, :cond_0

    .line 22
    .line 23
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    check-cast p2, Ljava/util/Map$Entry;

    .line 28
    .line 29
    invoke-interface {p2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p3

    .line 33
    check-cast p3, Ljava/lang/String;

    .line 34
    .line 35
    invoke-interface {p2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    check-cast p2, Ljava/lang/String;

    .line 40
    .line 41
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->DB_QUERY_PARAMETER:Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 42
    .line 43
    invoke-virtual {v0, p3}, Lio/opentelemetry/semconv/AttributeKeyTemplate;->getAttributeKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 44
    .line 45
    .line 46
    move-result-object p3

    .line 47
    invoke-static {p1, p3, p2}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    return-void
.end method


# virtual methods
.method public bridge synthetic internalGetSpanKey()Lio/opentelemetry/instrumentation/api/internal/SpanKey;
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->internalGetSpanKey()Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributesBuilder;",
            "Lio/opentelemetry/context/Context;",
            "TREQUEST;)V"
        }
    .end annotation

    .line 1
    invoke-super {p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 5
    .line 6
    check-cast p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;

    .line 7
    .line 8
    invoke-interface {p2, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;->getRawQueryTexts(Ljava/lang/Object;)Ljava/util/Collection;

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 20
    .line 21
    check-cast v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;

    .line 22
    .line 23
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;->getBatchSize(Ljava/lang/Object;)Ljava/lang/Long;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    const/4 v1, 0x1

    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 31
    .line 32
    .line 33
    move-result-wide v2

    .line 34
    const-wide/16 v4, 0x1

    .line 35
    .line 36
    cmp-long v2, v2, v4

    .line 37
    .line 38
    if-lez v2, :cond_1

    .line 39
    .line 40
    move v2, v1

    .line 41
    goto :goto_0

    .line 42
    :cond_1
    const/4 v2, 0x0

    .line 43
    :goto_0
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitOldDatabaseSemconv()Z

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    const-string v4, "CALL"

    .line 48
    .line 49
    if-eqz v3, :cond_3

    .line 50
    .line 51
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    if-ne v3, v1, :cond_3

    .line 56
    .line 57
    invoke-interface {p2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    check-cast v3, Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {v3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizerUtil;->sanitize(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getOperation()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v6

    .line 75
    sget-object v7, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->DB_STATEMENT:Lio/opentelemetry/api/common/AttributeKey;

    .line 76
    .line 77
    iget-boolean v8, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->statementSanitizationEnabled:Z

    .line 78
    .line 79
    if-eqz v8, :cond_2

    .line 80
    .line 81
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getFullStatement()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v3

    .line 85
    :cond_2
    invoke-static {p1, v7, v3}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    sget-object v3, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->DB_OPERATION:Lio/opentelemetry/api/common/AttributeKey;

    .line 89
    .line 90
    invoke-static {p1, v3, v6}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v4, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v3

    .line 97
    if-nez v3, :cond_3

    .line 98
    .line 99
    iget-object v3, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->oldSemconvTableAttribute:Lio/opentelemetry/api/common/AttributeKey;

    .line 100
    .line 101
    invoke-virtual {v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getMainIdentifier()Ljava/lang/String;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    invoke-static {p1, v3, v5}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    :cond_3
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 109
    .line 110
    .line 111
    move-result v3

    .line 112
    if-eqz v3, :cond_a

    .line 113
    .line 114
    if-eqz v2, :cond_4

    .line 115
    .line 116
    sget-object v3, Lio/opentelemetry/semconv/DbAttributes;->DB_OPERATION_BATCH_SIZE:Lio/opentelemetry/api/common/AttributeKey;

    .line 117
    .line 118
    invoke-static {p1, v3, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :cond_4
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    const-string v3, "BATCH "

    .line 126
    .line 127
    if-ne v0, v1, :cond_7

    .line 128
    .line 129
    invoke-interface {p2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 130
    .line 131
    .line 132
    move-result-object p2

    .line 133
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p2

    .line 137
    check-cast p2, Ljava/lang/String;

    .line 138
    .line 139
    invoke-static {p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizerUtil;->sanitize(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    invoke-virtual {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getOperation()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    sget-object v5, Lio/opentelemetry/semconv/DbAttributes;->DB_QUERY_TEXT:Lio/opentelemetry/api/common/AttributeKey;

    .line 148
    .line 149
    iget-boolean v6, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->statementSanitizationEnabled:Z

    .line 150
    .line 151
    if-eqz v6, :cond_5

    .line 152
    .line 153
    invoke-virtual {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getFullStatement()Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object p2

    .line 157
    :cond_5
    invoke-static {p1, v5, p2}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    sget-object p2, Lio/opentelemetry/semconv/DbAttributes;->DB_OPERATION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 161
    .line 162
    if-eqz v2, :cond_6

    .line 163
    .line 164
    invoke-static {v3, v1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v3

    .line 168
    goto :goto_1

    .line 169
    :cond_6
    move-object v3, v1

    .line 170
    :goto_1
    invoke-static {p1, p2, v3}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v4, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    move-result p2

    .line 177
    if-nez p2, :cond_a

    .line 178
    .line 179
    sget-object p2, Lio/opentelemetry/semconv/DbAttributes;->DB_COLLECTION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 180
    .line 181
    invoke-virtual {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getMainIdentifier()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    goto :goto_3

    .line 189
    :cond_7
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 190
    .line 191
    check-cast p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;

    .line 192
    .line 193
    invoke-interface {p2, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;->getRawQueryTexts(Ljava/lang/Object;)Ljava/util/Collection;

    .line 194
    .line 195
    .line 196
    move-result-object p2

    .line 197
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->statementSanitizationEnabled:Z

    .line 198
    .line 199
    invoke-static {p2, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->analyze(Ljava/util/Collection;Z)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;

    .line 200
    .line 201
    .line 202
    move-result-object p2

    .line 203
    sget-object v0, Lio/opentelemetry/semconv/DbAttributes;->DB_QUERY_TEXT:Lio/opentelemetry/api/common/AttributeKey;

    .line 204
    .line 205
    const-string v1, "; "

    .line 206
    .line 207
    invoke-virtual {p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->getStatements()Ljava/util/Set;

    .line 208
    .line 209
    .line 210
    move-result-object v5

    .line 211
    invoke-static {v1, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->join(Ljava/lang/String;Ljava/util/Collection;)Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object v1

    .line 215
    invoke-static {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->getOperation()Ljava/lang/String;

    .line 219
    .line 220
    .line 221
    move-result-object v0

    .line 222
    if-eqz v0, :cond_8

    .line 223
    .line 224
    new-instance v0, Ljava/lang/StringBuilder;

    .line 225
    .line 226
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->getOperation()Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v1

    .line 233
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 234
    .line 235
    .line 236
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    goto :goto_2

    .line 241
    :cond_8
    const-string v0, "BATCH"

    .line 242
    .line 243
    :goto_2
    sget-object v1, Lio/opentelemetry/semconv/DbAttributes;->DB_OPERATION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 244
    .line 245
    invoke-static {p1, v1, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->getMainIdentifier()Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object v0

    .line 252
    if-eqz v0, :cond_a

    .line 253
    .line 254
    invoke-virtual {p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->getOperation()Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    if-eqz v0, :cond_9

    .line 259
    .line 260
    invoke-virtual {p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->getOperation()Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    invoke-virtual {v4, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    move-result v0

    .line 268
    if-nez v0, :cond_a

    .line 269
    .line 270
    :cond_9
    sget-object v0, Lio/opentelemetry/semconv/DbAttributes;->DB_COLLECTION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 271
    .line 272
    invoke-virtual {p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->getMainIdentifier()Ljava/lang/String;

    .line 273
    .line 274
    .line 275
    move-result-object p2

    .line 276
    invoke-static {p1, v0, p2}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 277
    .line 278
    .line 279
    :cond_a
    :goto_3
    iget-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 280
    .line 281
    check-cast p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;

    .line 282
    .line 283
    invoke-interface {p2, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;->getQueryParameters(Ljava/lang/Object;)Ljava/util/Map;

    .line 284
    .line 285
    .line 286
    move-result-object p2

    .line 287
    invoke-direct {p0, p1, v2, p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;->setQueryParameters(Lio/opentelemetry/api/common/AttributesBuilder;ZLjava/util/Map;)V

    .line 288
    .line 289
    .line 290
    return-void
.end method
