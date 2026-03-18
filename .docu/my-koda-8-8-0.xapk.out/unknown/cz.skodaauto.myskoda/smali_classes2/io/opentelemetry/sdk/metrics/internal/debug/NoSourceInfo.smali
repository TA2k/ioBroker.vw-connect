.class final enum Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;",
        ">;",
        "Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

.field public static final enum INSTANCE:Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;->INSTANCE:Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

    .line 2
    .line 3
    filled-new-array {v0}, [Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

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
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

    .line 2
    .line 3
    const-string v1, "INSTANCE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;->INSTANCE:Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;->$values()[Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;->$VALUES:[Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

    .line 16
    .line 17
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

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;->$VALUES:[Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/sdk/metrics/internal/debug/NoSourceInfo;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public multiLineDebugString()Ljava/lang/String;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v0, "\tat unknown source\n\t\t"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/debug/DebugConfig;->getHowToEnableMessage()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public shortDebugString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "unknown source"

    .line 2
    .line 3
    return-object p0
.end method
