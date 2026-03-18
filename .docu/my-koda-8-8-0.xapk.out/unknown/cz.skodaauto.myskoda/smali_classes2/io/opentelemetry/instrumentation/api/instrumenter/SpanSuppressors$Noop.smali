.class final enum Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "Noop"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;",
        ">;",
        "Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressor;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;

.field public static final enum INSTANCE:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;->INSTANCE:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;

    .line 2
    .line 3
    filled-new-array {v0}, [Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;

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
    new-instance v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;

    .line 2
    .line 3
    const-string v1, "INSTANCE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;->INSTANCE:Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;->$values()[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;->$VALUES:[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;

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

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;->$VALUES:[Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/instrumentation/api/instrumenter/SpanSuppressors$Noop;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public shouldSuppress(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/SpanKind;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public storeInContext(Lio/opentelemetry/context/Context;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/Span;)Lio/opentelemetry/context/Context;
    .locals 0

    .line 1
    return-object p1
.end method
