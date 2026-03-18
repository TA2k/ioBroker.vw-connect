.class public final synthetic Lio/opentelemetry/instrumentation/api/incubator/semconv/db/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Function;


# instance fields
.field public final synthetic a:Ljava/lang/String;

.field public final synthetic b:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/b;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/b;->b:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/b;->b:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 2
    .line 3
    check-cast p1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/b;->a:Ljava/lang/String;

    .line 6
    .line 7
    invoke-static {p0, v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer;->a(Ljava/lang/String;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizer$CacheKey;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
