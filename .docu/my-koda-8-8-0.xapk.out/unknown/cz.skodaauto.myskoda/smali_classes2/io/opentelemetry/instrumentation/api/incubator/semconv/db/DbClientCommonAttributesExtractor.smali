.class abstract Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
.implements Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        "RESPONSE:",
        "Ljava/lang/Object;",
        "GETTER::",
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter<",
        "TREQUEST;TRESPONSE;>;>",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
        "TREQUEST;TRESPONSE;>;",
        "Lio/opentelemetry/instrumentation/api/internal/SpanKeyProvider;"
    }
.end annotation


# static fields
.field private static final DB_CONNECTION_STRING:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final DB_NAME:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field static final DB_SYSTEM:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final DB_USER:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field final getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "TGETTER;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "db.name"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->DB_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    const-string v0, "db.system"

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->DB_SYSTEM:Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    const-string v0, "db.user"

    .line 18
    .line 19
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->DB_USER:Lio/opentelemetry/api/common/AttributeKey;

    .line 24
    .line 25
    const-string v0, "db.connection_string"

    .line 26
    .line 27
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->DB_CONNECTION_STRING:Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TGETTER;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public internalGetSpanKey()Lio/opentelemetry/instrumentation/api/internal/SpanKey;
    .locals 0

    .line 1
    sget-object p0, Lio/opentelemetry/instrumentation/api/internal/SpanKey;->DB_CLIENT:Lio/opentelemetry/instrumentation/api/internal/SpanKey;

    .line 2
    .line 3
    return-object p0
.end method

.method public final onEnd(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/context/Context;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Throwable;)V
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
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    if-eqz p2, :cond_2

    .line 6
    .line 7
    if-eqz p5, :cond_0

    .line 8
    .line 9
    sget-object p2, Lio/opentelemetry/semconv/ErrorAttributes;->ERROR_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 10
    .line 11
    invoke-virtual {p5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object p3

    .line 15
    invoke-virtual {p3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p3

    .line 19
    invoke-static {p1, p2, p3}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    if-nez p5, :cond_1

    .line 23
    .line 24
    if-eqz p4, :cond_2

    .line 25
    .line 26
    :cond_1
    sget-object p2, Lio/opentelemetry/semconv/DbAttributes;->DB_RESPONSE_STATUS_CODE:Lio/opentelemetry/api/common/AttributeKey;

    .line 27
    .line 28
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 29
    .line 30
    invoke-interface {p0, p4, p5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;->getResponseStatus(Ljava/lang/Object;Ljava/lang/Throwable;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-static {p1, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    :cond_2
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
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitStableDatabaseSemconv()Z

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    if-eqz p2, :cond_0

    .line 6
    .line 7
    sget-object p2, Lio/opentelemetry/semconv/DbAttributes;->DB_SYSTEM_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 10
    .line 11
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;->getDbSystem(Ljava/lang/Object;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->stableDbSystemName(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    sget-object p2, Lio/opentelemetry/semconv/DbAttributes;->DB_NAMESPACE:Lio/opentelemetry/api/common/AttributeKey;

    .line 23
    .line 24
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 25
    .line 26
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;->getDbNamespace(Ljava/lang/Object;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    :cond_0
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/SemconvStability;->emitOldDatabaseSemconv()Z

    .line 34
    .line 35
    .line 36
    move-result p2

    .line 37
    if-eqz p2, :cond_1

    .line 38
    .line 39
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->DB_SYSTEM:Lio/opentelemetry/api/common/AttributeKey;

    .line 40
    .line 41
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 42
    .line 43
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;->getDbSystem(Ljava/lang/Object;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->DB_USER:Lio/opentelemetry/api/common/AttributeKey;

    .line 51
    .line 52
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 53
    .line 54
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;->getUser(Ljava/lang/Object;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->DB_NAME:Lio/opentelemetry/api/common/AttributeKey;

    .line 62
    .line 63
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 64
    .line 65
    invoke-interface {v0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;->getDbNamespace(Ljava/lang/Object;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-static {p1, p2, v0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    sget-object p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->DB_CONNECTION_STRING:Lio/opentelemetry/api/common/AttributeKey;

    .line 73
    .line 74
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesExtractor;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;

    .line 75
    .line 76
    invoke-interface {p0, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientCommonAttributesGetter;->getConnectionString(Ljava/lang/Object;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-static {p1, p2, p0}, Lio/opentelemetry/instrumentation/api/internal/AttributesExtractorUtil;->internalSet(Lio/opentelemetry/api/common/AttributesBuilder;Lio/opentelemetry/api/common/AttributeKey;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    :cond_1
    return-void
.end method
