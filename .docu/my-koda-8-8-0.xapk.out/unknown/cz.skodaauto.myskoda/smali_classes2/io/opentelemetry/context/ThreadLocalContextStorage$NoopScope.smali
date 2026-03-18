.class final enum Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/Scope;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/context/ThreadLocalContextStorage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "NoopScope"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;",
        ">;",
        "Lio/opentelemetry/context/Scope;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

.field public static final enum INSTANCE:Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;->INSTANCE:Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

    .line 2
    .line 3
    filled-new-array {v0}, [Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

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
    new-instance v0, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

    .line 2
    .line 3
    const-string v1, "INSTANCE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;->INSTANCE:Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;->$values()[Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;->$VALUES:[Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

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

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;->$VALUES:[Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public close()V
    .locals 0

    .line 1
    return-void
.end method
