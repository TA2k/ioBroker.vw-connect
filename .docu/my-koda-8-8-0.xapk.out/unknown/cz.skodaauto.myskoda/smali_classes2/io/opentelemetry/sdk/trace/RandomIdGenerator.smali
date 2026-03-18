.class final enum Lio/opentelemetry/sdk/trace/RandomIdGenerator;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/IdGenerator;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/sdk/trace/RandomIdGenerator;",
        ">;",
        "Lio/opentelemetry/sdk/trace/IdGenerator;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/sdk/trace/RandomIdGenerator;

.field public static final enum INSTANCE:Lio/opentelemetry/sdk/trace/RandomIdGenerator;

.field private static final INVALID_ID:J

.field private static final randomSupplier:Ljava/util/function/Supplier;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Supplier<",
            "Ljava/util/Random;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/sdk/trace/RandomIdGenerator;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/RandomIdGenerator;->INSTANCE:Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 2
    .line 3
    filled-new-array {v0}, [Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 2
    .line 3
    const-string v1, "INSTANCE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/sdk/trace/RandomIdGenerator;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/sdk/trace/RandomIdGenerator;->INSTANCE:Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/sdk/trace/RandomIdGenerator;->$values()[Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/sdk/trace/RandomIdGenerator;->$VALUES:[Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 16
    .line 17
    invoke-static {}, Lio/opentelemetry/sdk/internal/RandomSupplier;->platformDefault()Ljava/util/function/Supplier;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Lio/opentelemetry/sdk/trace/RandomIdGenerator;->randomSupplier:Ljava/util/function/Supplier;

    .line 22
    .line 23
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

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/sdk/trace/RandomIdGenerator;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/sdk/trace/RandomIdGenerator;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/trace/RandomIdGenerator;->$VALUES:[Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/sdk/trace/RandomIdGenerator;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/sdk/trace/RandomIdGenerator;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public generateSpanId()Ljava/lang/String;
    .locals 4

    .line 1
    sget-object p0, Lio/opentelemetry/sdk/trace/RandomIdGenerator;->randomSupplier:Ljava/util/function/Supplier;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/util/Random;

    .line 8
    .line 9
    :cond_0
    invoke-virtual {p0}, Ljava/util/Random;->nextLong()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    const-wide/16 v2, 0x0

    .line 14
    .line 15
    cmp-long v2, v0, v2

    .line 16
    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    invoke-static {v0, v1}, Lio/opentelemetry/api/trace/SpanId;->fromLong(J)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public generateTraceId()Ljava/lang/String;
    .locals 6

    .line 1
    sget-object p0, Lio/opentelemetry/sdk/trace/RandomIdGenerator;->randomSupplier:Ljava/util/function/Supplier;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/function/Supplier;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/util/Random;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/util/Random;->nextLong()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    :cond_0
    invoke-virtual {p0}, Ljava/util/Random;->nextLong()J

    .line 14
    .line 15
    .line 16
    move-result-wide v2

    .line 17
    const-wide/16 v4, 0x0

    .line 18
    .line 19
    cmp-long v4, v2, v4

    .line 20
    .line 21
    if-eqz v4, :cond_0

    .line 22
    .line 23
    invoke-static {v0, v1, v2, v3}, Lio/opentelemetry/api/trace/TraceId;->fromLongs(JJ)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "RandomIdGenerator{}"

    .line 2
    .line 3
    return-object p0
.end method
