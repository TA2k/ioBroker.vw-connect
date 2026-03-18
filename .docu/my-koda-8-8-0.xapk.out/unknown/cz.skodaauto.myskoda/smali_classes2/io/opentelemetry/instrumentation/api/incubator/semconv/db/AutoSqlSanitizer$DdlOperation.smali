.class abstract Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;
.super Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x401
    name = "DdlOperation"
.end annotation


# instance fields
.field private expectingOperationTarget:Z

.field private operationTarget:Ljava/lang/String;

.field final synthetic this$0:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;


# direct methods
.method private constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;->this$0:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V

    .line 2
    const-string p1, ""

    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;->operationTarget:Ljava/lang/String;

    const/4 p1, 0x1

    .line 3
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;->expectingOperationTarget:Z

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$1;)V
    .locals 0

    .line 4
    invoke-direct {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;)V

    return-void
.end method


# virtual methods
.method public expectingOperationTarget()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;->expectingOperationTarget:Z

    .line 2
    .line 3
    return p0
.end method

.method public getResult(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;
    .locals 3

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;->operationTarget:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    sget-object v2, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 25
    .line 26
    invoke-virtual {v1, v2}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, " "

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;->operationTarget:Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->mainIdentifier:Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {p1, v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :cond_0
    invoke-super {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$Operation;->getResult(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method

.method public handleIdentifier()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;->shouldHandleIdentifier()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;->this$0:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer;

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
    :cond_0
    const/4 p0, 0x1

    .line 16
    return p0
.end method

.method public handleOperationTarget(Ljava/lang/String;)Z
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;->operationTarget:Ljava/lang/String;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;->expectingOperationTarget:Z

    .line 5
    .line 6
    return p1
.end method

.method public shouldHandleIdentifier()Z
    .locals 1

    .line 1
    const-string v0, "TABLE"

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/AutoSqlSanitizer$DdlOperation;->operationTarget:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method
