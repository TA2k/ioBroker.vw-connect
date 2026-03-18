.class abstract enum Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

.field public static final enum NONE:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

.field public static final enum SEMCONV:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

.field public static final enum SPAN_KIND:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->NONE:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->SPAN_KIND:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 4
    .line 5
    sget-object v2, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->SEMCONV:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 6
    .line 7
    filled-new-array {v0, v1, v2}, [Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy$1;

    .line 2
    .line 3
    const-string v1, "NONE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy$1;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->NONE:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 10
    .line 11
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy$2;

    .line 12
    .line 13
    const-string v1, "SPAN_KIND"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy$2;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->SPAN_KIND:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 20
    .line 21
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy$3;

    .line 22
    .line 23
    const-string v1, "SEMCONV"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy$3;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->SEMCONV:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 30
    .line 31
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->$values()[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->$VALUES:[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 36
    .line 37
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

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;ILio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy$1;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;-><init>(Ljava/lang/String;I)V

    return-void
.end method

.method public static fromConfig(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;
    .locals 1
    .param p0    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const-string p0, "semconv"

    .line 4
    .line 5
    :cond_0
    sget-object v0, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    const-string v0, "span-kind"

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_2

    .line 21
    .line 22
    const-string v0, "none"

    .line 23
    .line 24
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-nez p0, :cond_1

    .line 29
    .line 30
    sget-object p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->SEMCONV:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 31
    .line 32
    return-object p0

    .line 33
    :cond_1
    sget-object p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->NONE:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_2
    sget-object p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->SPAN_KIND:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 37
    .line 38
    return-object p0
.end method

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->$VALUES:[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressionStrategy;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public abstract create(Ljava/util/Set;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Lio/opentelemetry/instrumentation/api/internal/SpanKey;",
            ">;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;"
        }
    .end annotation
.end method
