.class Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Update;
.super Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "Update"
.end annotation


# instance fields
.field final synthetic this$0:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;


# direct methods
.method private constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Update;->this$0:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Update;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)V

    return-void
.end method


# virtual methods
.method public handleIdentifier()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Update;->this$0:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->access$100(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->mainIdentifier:Ljava/lang/String;

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0
.end method
