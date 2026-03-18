.class Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Insert;
.super Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "Insert"
.end annotation


# instance fields
.field expectingTableName:Z

.field final synthetic this$0:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;


# direct methods
.method private constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Insert;->this$0:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    const/4 p1, 0x0

    .line 2
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Insert;->expectingTableName:Z

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V
    .locals 0

    .line 3
    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Insert;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)V

    return-void
.end method


# virtual methods
.method public handleIdentifier()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Insert;->expectingTableName:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Insert;->this$0:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;

    .line 8
    .line 9
    invoke-static {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;->access$100(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->mainIdentifier:Ljava/lang/String;

    .line 14
    .line 15
    const/4 p0, 0x1

    .line 16
    return p0
.end method

.method public handleInto()Z
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Insert;->expectingTableName:Z

    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    return p0
.end method
