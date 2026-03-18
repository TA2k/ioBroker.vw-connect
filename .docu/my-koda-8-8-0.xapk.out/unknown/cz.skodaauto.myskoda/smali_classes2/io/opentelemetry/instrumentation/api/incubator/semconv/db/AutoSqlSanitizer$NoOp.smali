.class Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$NoOp;
.super Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "NoOp"
.end annotation


# static fields
.field static final INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$NoOp;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$NoOp;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$NoOp;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public getResult(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    invoke-static {p1, p0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method
