.class Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Create;
.super Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "Create"
.end annotation


# instance fields
.field final synthetic this$0:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;


# direct methods
.method private constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)V
    .locals 1

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Create;->this$0:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Create;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)V

    return-void
.end method
