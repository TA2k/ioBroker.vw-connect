.class public final enum Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

.field public static final enum COUCHBASE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

.field public static final enum DEFAULT:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;->DEFAULT:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;->COUCHBASE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 2
    .line 3
    const-string v1, "DEFAULT"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;->DEFAULT:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 10
    .line 11
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 12
    .line 13
    const-string v1, "COUCHBASE"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;->COUCHBASE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 20
    .line 21
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;->$values()[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;->$VALUES:[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 26
    .line 27
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;->$VALUES:[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlDialect;

    .line 8
    .line 9
    return-object v0
.end method
