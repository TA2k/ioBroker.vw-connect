.class public final enum Lio/opentelemetry/sdk/internal/Signal;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/sdk/internal/Signal;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/sdk/internal/Signal;

.field public static final enum LOG:Lio/opentelemetry/sdk/internal/Signal;

.field public static final enum METRIC:Lio/opentelemetry/sdk/internal/Signal;

.field public static final enum PROFILE:Lio/opentelemetry/sdk/internal/Signal;

.field public static final enum SPAN:Lio/opentelemetry/sdk/internal/Signal;


# instance fields
.field private final exporterMetricNamespace:Ljava/lang/String;

.field private final metricUnit:Ljava/lang/String;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/sdk/internal/Signal;
    .locals 4

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/internal/Signal;->SPAN:Lio/opentelemetry/sdk/internal/Signal;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/sdk/internal/Signal;->METRIC:Lio/opentelemetry/sdk/internal/Signal;

    .line 4
    .line 5
    sget-object v2, Lio/opentelemetry/sdk/internal/Signal;->LOG:Lio/opentelemetry/sdk/internal/Signal;

    .line 6
    .line 7
    sget-object v3, Lio/opentelemetry/sdk/internal/Signal;->PROFILE:Lio/opentelemetry/sdk/internal/Signal;

    .line 8
    .line 9
    filled-new-array {v0, v1, v2, v3}, [Lio/opentelemetry/sdk/internal/Signal;

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
    new-instance v0, Lio/opentelemetry/sdk/internal/Signal;

    .line 2
    .line 3
    const-string v1, "otel.sdk.exporter.span"

    .line 4
    .line 5
    const-string v2, "span"

    .line 6
    .line 7
    const-string v3, "SPAN"

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct {v0, v3, v4, v1, v2}, Lio/opentelemetry/sdk/internal/Signal;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lio/opentelemetry/sdk/internal/Signal;->SPAN:Lio/opentelemetry/sdk/internal/Signal;

    .line 14
    .line 15
    new-instance v0, Lio/opentelemetry/sdk/internal/Signal;

    .line 16
    .line 17
    const-string v1, "otel.sdk.exporter.metric_data_point"

    .line 18
    .line 19
    const-string v2, "data_point"

    .line 20
    .line 21
    const-string v3, "METRIC"

    .line 22
    .line 23
    const/4 v4, 0x1

    .line 24
    invoke-direct {v0, v3, v4, v1, v2}, Lio/opentelemetry/sdk/internal/Signal;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lio/opentelemetry/sdk/internal/Signal;->METRIC:Lio/opentelemetry/sdk/internal/Signal;

    .line 28
    .line 29
    new-instance v0, Lio/opentelemetry/sdk/internal/Signal;

    .line 30
    .line 31
    const-string v1, "otel.sdk.exporter.log"

    .line 32
    .line 33
    const-string v2, "log_record"

    .line 34
    .line 35
    const-string v3, "LOG"

    .line 36
    .line 37
    const/4 v4, 0x2

    .line 38
    invoke-direct {v0, v3, v4, v1, v2}, Lio/opentelemetry/sdk/internal/Signal;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    sput-object v0, Lio/opentelemetry/sdk/internal/Signal;->LOG:Lio/opentelemetry/sdk/internal/Signal;

    .line 42
    .line 43
    new-instance v0, Lio/opentelemetry/sdk/internal/Signal;

    .line 44
    .line 45
    const/4 v1, 0x3

    .line 46
    const-string v2, "TBD"

    .line 47
    .line 48
    const-string v3, "PROFILE"

    .line 49
    .line 50
    invoke-direct {v0, v3, v1, v2, v2}, Lio/opentelemetry/sdk/internal/Signal;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Lio/opentelemetry/sdk/internal/Signal;->PROFILE:Lio/opentelemetry/sdk/internal/Signal;

    .line 54
    .line 55
    invoke-static {}, Lio/opentelemetry/sdk/internal/Signal;->$values()[Lio/opentelemetry/sdk/internal/Signal;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    sput-object v0, Lio/opentelemetry/sdk/internal/Signal;->$VALUES:[Lio/opentelemetry/sdk/internal/Signal;

    .line 60
    .line 61
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lio/opentelemetry/sdk/internal/Signal;->exporterMetricNamespace:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p4, p0, Lio/opentelemetry/sdk/internal/Signal;->metricUnit:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/sdk/internal/Signal;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/internal/Signal;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/internal/Signal;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/sdk/internal/Signal;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/internal/Signal;->$VALUES:[Lio/opentelemetry/sdk/internal/Signal;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/sdk/internal/Signal;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/sdk/internal/Signal;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public getExporterMetricNamespace()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/Signal;->exporterMetricNamespace:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMetricUnit()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/Signal;->metricUnit:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public logFriendlyName()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
