.class Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;
    }
.end annotation


# instance fields
.field private final mainIdentifier:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final operation:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final statements:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method private constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->mainIdentifier:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->operation:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->statements:Ljava/util/Set;

    .line 9
    .line 10
    return-void
.end method

.method public static analyze(Ljava/util/Collection;Z)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;Z)",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$1;)V

    .line 5
    .line 6
    .line 7
    new-instance v2, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;

    .line 8
    .line 9
    invoke-direct {v2, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$1;)V

    .line 10
    .line 11
    .line 12
    new-instance v1, Ljava/util/LinkedHashSet;

    .line 13
    .line 14
    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    .line 15
    .line 16
    .line 17
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-eqz v3, :cond_1

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    check-cast v3, Ljava/lang/String;

    .line 32
    .line 33
    invoke-static {v3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementSanitizerUtil;->sanitize(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    invoke-virtual {v4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getMainIdentifier()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v5

    .line 41
    invoke-virtual {v0, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;->set(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getOperation()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v5

    .line 48
    invoke-virtual {v2, v5}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;->set(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    if-eqz p1, :cond_0

    .line 52
    .line 53
    invoke-virtual {v4}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlStatementInfo;->getFullStatement()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    :cond_0
    invoke-interface {v1, v3}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_1
    new-instance p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;

    .line 62
    .line 63
    invoke-virtual {v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;->getValue()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-virtual {v2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;->getValue()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    invoke-direct {p0, p1, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;)V

    .line 72
    .line 73
    .line 74
    return-object p0
.end method


# virtual methods
.method public getMainIdentifier()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->mainIdentifier:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getOperation()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->operation:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getStatements()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;->statements:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method
