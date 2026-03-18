.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;
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


# static fields
.field private static final DB_SQL_TABLE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field captureQueryParameters:Z

.field final getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation
.end field

.field oldSemconvTableAttribute:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field statementSanitizationEnabled:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "db.sql.table"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->DB_SQL_TABLE:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter<",
            "TREQUEST;TRESPONSE;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->DB_SQL_TABLE:Lio/opentelemetry/api/common/AttributeKey;

    .line 5
    .line 6
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->oldSemconvTableAttribute:Lio/opentelemetry/api/common/AttributeKey;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->statementSanitizationEnabled:Z

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->captureQueryParameters:Z

    .line 13
    .line 14
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/instrumenter/AttributesExtractor<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->getter:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->oldSemconvTableAttribute:Lio/opentelemetry/api/common/AttributeKey;

    .line 6
    .line 7
    iget-boolean v3, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->statementSanitizationEnabled:Z

    .line 8
    .line 9
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->captureQueryParameters:Z

    .line 10
    .line 11
    invoke-direct {v0, v1, v2, v3, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;Lio/opentelemetry/api/common/AttributeKey;ZZ)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public setCaptureQueryParameters(Z)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z)",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->captureQueryParameters:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public setStatementSanitizationEnabled(Z)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(Z)",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .line 1
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->statementSanitizationEnabled:Z

    .line 2
    .line 3
    return-object p0
.end method

.method public setTableAttribute(Lio/opentelemetry/api/common/AttributeKey;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder<",
            "TREQUEST;TRESPONSE;>;"
        }
    .end annotation

    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    check-cast p1, Lio/opentelemetry/api/common/AttributeKey;

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesExtractorBuilder;->oldSemconvTableAttribute:Lio/opentelemetry/api/common/AttributeKey;

    .line 7
    .line 8
    return-object p0
.end method
