.class public final enum Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

.field public static final enum CONTROLLER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

.field public static final enum NESTED_CONTROLLER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

.field public static final enum SERVER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

.field public static final enum SERVER_FILTER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;


# instance fields
.field final order:I

.field final useFirst:Z


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;
    .locals 4

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->SERVER_FILTER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->SERVER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 4
    .line 5
    sget-object v2, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->CONTROLLER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 6
    .line 7
    sget-object v3, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->NESTED_CONTROLLER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 2
    .line 3
    const-string v1, "SERVER_FILTER"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    invoke-direct {v0, v1, v2, v3, v2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;-><init>(Ljava/lang/String;IIZ)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->SERVER_FILTER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 11
    .line 12
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 13
    .line 14
    const-string v1, "SERVER"

    .line 15
    .line 16
    const/4 v4, 0x2

    .line 17
    invoke-direct {v0, v1, v3, v4}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;-><init>(Ljava/lang/String;II)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->SERVER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 21
    .line 22
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 23
    .line 24
    const-string v1, "CONTROLLER"

    .line 25
    .line 26
    const/4 v3, 0x3

    .line 27
    invoke-direct {v0, v1, v4, v3}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;-><init>(Ljava/lang/String;II)V

    .line 28
    .line 29
    .line 30
    sput-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->CONTROLLER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 31
    .line 32
    new-instance v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 33
    .line 34
    const-string v1, "NESTED_CONTROLLER"

    .line 35
    .line 36
    const/4 v4, 0x4

    .line 37
    invoke-direct {v0, v1, v3, v4, v2}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;-><init>(Ljava/lang/String;IIZ)V

    .line 38
    .line 39
    .line 40
    sput-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->NESTED_CONTROLLER:Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 41
    .line 42
    invoke-static {}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->$values()[Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    sput-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->$VALUES:[Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 47
    .line 48
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;II)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)V"
        }
    .end annotation

    const/4 v0, 0x1

    .line 1
    invoke-direct {p0, p1, p2, p3, v0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;-><init>(Ljava/lang/String;IIZ)V

    return-void
.end method

.method private constructor <init>(Ljava/lang/String;IIZ)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(IZ)V"
        }
    .end annotation

    .line 2
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 3
    iput p3, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->order:I

    .line 4
    iput-boolean p4, p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->useFirst:Z

    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->$VALUES:[Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/instrumentation/api/semconv/http/HttpServerRouteSource;

    .line 8
    .line 9
    return-object v0
.end method
