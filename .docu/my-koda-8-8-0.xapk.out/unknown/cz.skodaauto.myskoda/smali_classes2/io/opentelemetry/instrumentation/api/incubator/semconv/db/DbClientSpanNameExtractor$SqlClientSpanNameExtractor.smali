.class final Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$SqlClientSpanNameExtractor;
.super Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "SqlClientSpanNameExtractor"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor<",
        "TREQUEST;>;"
    }
.end annotation


# instance fields
.field private final getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter<",
            "TREQUEST;*>;"
        }
    .end annotation
.end field


# direct methods
.method private constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter<",
            "TREQUEST;*>;)V"
        }
    .end annotation

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$1;)V

    .line 3
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$SqlClientSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$SqlClientSpanNameExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;)V

    return-void
.end method

.method private isBatch(Ljava/lang/Object;)Z
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TREQUEST;)Z"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$SqlClientSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;->getBatchSize(Ljava/lang/Object;)Ljava/lang/Long;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 10
    .line 11
    .line 12
    move-result-wide p0

    .line 13
    const-wide/16 v0, 0x1

    .line 14
    .line 15
    cmp-long p0, p0, v0

    .line 16
    .line 17
    if-lez p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method


# virtual methods
.method public extract(Ljava/lang/Object;)Ljava/lang/String;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TREQUEST;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$SqlClientSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;->getDbNamespace(Ljava/lang/Object;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$SqlClientSpanNameExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;

    .line 8
    .line 9
    invoke-interface {v1, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;->getRawQueryTexts(Ljava/lang/Object;)Ljava/util/Collection;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/4 v3, 0x0

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    invoke-virtual {p0, v0, v3, v3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;->computeSpanName(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :cond_0
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    const/4 v4, 0x1

    .line 30
    if-nez v2, :cond_2

    .line 31
    .line 32
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    if-le p1, v4, :cond_1

    .line 37
    .line 38
    invoke-virtual {p0, v0, v3, v3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;->computeSpanName(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :cond_1
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    check-cast p1, Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizerUtil;->sanitize(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getOperation()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getMainIdentifier()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-virtual {p0, v0, v1, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;->computeSpanName(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0

    .line 70
    :cond_2
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 71
    .line 72
    .line 73
    move-result v2

    .line 74
    const-string v3, "BATCH "

    .line 75
    .line 76
    if-ne v2, v4, :cond_4

    .line 77
    .line 78
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    check-cast v1, Ljava/lang/String;

    .line 87
    .line 88
    invoke-static {v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizerUtil;->sanitize(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    invoke-virtual {v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getOperation()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$SqlClientSpanNameExtractor;->isBatch(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result p1

    .line 100
    if-eqz p1, :cond_3

    .line 101
    .line 102
    invoke-static {v3, v2}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    :cond_3
    invoke-virtual {v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getMainIdentifier()Ljava/lang/String;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    invoke-virtual {p0, v0, v2, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;->computeSpanName(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0

    .line 115
    :cond_4
    const/4 p1, 0x0

    .line 116
    invoke-static {v1, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->analyze(Ljava/util/Collection;Z)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->getOperation()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    if-eqz v1, :cond_5

    .line 125
    .line 126
    new-instance v1, Ljava/lang/StringBuilder;

    .line 127
    .line 128
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->getOperation()Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v2

    .line 135
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    goto :goto_0

    .line 143
    :cond_5
    const-string v1, "BATCH"

    .line 144
    .line 145
    :goto_0
    invoke-virtual {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->getMainIdentifier()Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    invoke-virtual {p0, v0, v1, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;->computeSpanName(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object p0

    .line 153
    return-object p0
.end method
