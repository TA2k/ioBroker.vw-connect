.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesExtractor;
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
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter<",
        "TREQUEST;TRESPONSE;>;>;"
    }
.end annotation


# static fields
.field static final DB_OPERATION:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
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


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "db.statement"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesExtractor;->DB_STATEMENT:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    const-string v0, "db.operation"

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesExtractor;->DB_OPERATION:Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            "RESPONSE:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesExtractor;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;)V

    .line 4
    .line 5
    .line 6
    return-object v0
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
    invoke-super {p0, p1, p2, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->onStart(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 5
    .line 6
    .line 7
    move-result p2

    .line 8
    if-eqz p2, :cond_0

    .line 9
    .line 10
    sget-object p2, Lio/opentelemetry/semconv/DbAttributes;->DB_QUERY_TEXT:Lio/opentelemetry/api/common/AttributeKey;

    .line 11
    .line 12
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 13
    .line 14
    check-cast v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;

    .line 15
    .line 16
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;->getDbQueryText(Ljava/lang/Object;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    sget-object p2, Lio/opentelemetry/semconv/DbAttributes;->DB_OPERATION_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 24
    .line 25
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 26
    .line 27
    check-cast v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;

    .line 28
    .line 29
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;->getDbOperationName(Ljava/lang/Object;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    sget-object p2, Lio/opentelemetry/semconv/DbAttributes;->DB_QUERY_SUMMARY:Lio/opentelemetry/api/common/AttributeKey;

    .line 37
    .line 38
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 39
    .line 40
    check-cast v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;

    .line 41
    .line 42
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;->getDbQuerySummary(Ljava/lang/Object;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    :cond_0
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitOldDatabaseSemconv()Z

    .line 50
    .line 51
    .line 52
    move-result p2

    .line 53
    if-eqz p2, :cond_1

    .line 54
    .line 55
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesExtractor;->DB_STATEMENT:Lio/opentelemetry/api/common/AttributeKey;

    .line 56
    .line 57
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 58
    .line 59
    check-cast v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;

    .line 60
    .line 61
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;->getDbQueryText(Ljava/lang/Object;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesExtractor;->DB_OPERATION:Lio/opentelemetry/api/common/AttributeKey;

    .line 69
    .line 70
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 71
    .line 72
    check-cast p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;

    .line 73
    .line 74
    invoke-interface {p0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;->getDbOperationName(Ljava/lang/Object;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-static {p1, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    :cond_1
    return-void
.end method
