.class final enum Lio/opentelemetry/context/ThreadLocalContextStorage;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/ContextStorage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;,
        Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/context/ThreadLocalContextStorage;",
        ">;",
        "Lio/opentelemetry/context/ContextStorage;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/context/ThreadLocalContextStorage;

.field public static final enum INSTANCE:Lio/opentelemetry/context/ThreadLocalContextStorage;

.field private static final THREAD_LOCAL_STORAGE:Ljava/lang/ThreadLocal;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ThreadLocal<",
            "Lio/opentelemetry/context/Context;",
            ">;"
        }
    .end annotation
.end field

.field private static final logger:Ljava/util/logging/Logger;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/context/ThreadLocalContextStorage;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage;->INSTANCE:Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 2
    .line 3
    filled-new-array {v0}, [Lio/opentelemetry/context/ThreadLocalContextStorage;

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
    new-instance v0, Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 2
    .line 3
    const-string v1, "INSTANCE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/context/ThreadLocalContextStorage;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage;->INSTANCE:Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/context/ThreadLocalContextStorage;->$values()[Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage;->$VALUES:[Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 16
    .line 17
    const-class v0, Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sput-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage;->logger:Ljava/util/logging/Logger;

    .line 28
    .line 29
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 30
    .line 31
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 32
    .line 33
    .line 34
    sput-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage;->THREAD_LOCAL_STORAGE:Ljava/lang/ThreadLocal;

    .line 35
    .line 36
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

.method public static synthetic access$100()Ljava/lang/ThreadLocal;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage;->THREAD_LOCAL_STORAGE:Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$200()Ljava/util/logging/Logger;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage;->logger:Ljava/util/logging/Logger;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/context/ThreadLocalContextStorage;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/context/ThreadLocalContextStorage;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/context/ThreadLocalContextStorage;->$VALUES:[Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/context/ThreadLocalContextStorage;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public attach(Lio/opentelemetry/context/Context;)Lio/opentelemetry/context/Scope;
    .locals 3

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    sget-object p0, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;->INSTANCE:Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/context/ThreadLocalContextStorage;->current()Lio/opentelemetry/context/Context;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-ne p1, v0, :cond_1

    .line 11
    .line 12
    sget-object p0, Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;->INSTANCE:Lio/opentelemetry/context/ThreadLocalContextStorage$NoopScope;

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_1
    sget-object v1, Lio/opentelemetry/context/ThreadLocalContextStorage;->THREAD_LOCAL_STORAGE:Ljava/lang/ThreadLocal;

    .line 16
    .line 17
    invoke-virtual {v1, p1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    new-instance v1, Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    invoke-direct {v1, p0, v0, p1, v2}, Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;-><init>(Lio/opentelemetry/context/ThreadLocalContextStorage;Lio/opentelemetry/context/Context;Lio/opentelemetry/context/Context;Lio/opentelemetry/context/ThreadLocalContextStorage$1;)V

    .line 24
    .line 25
    .line 26
    return-object v1
.end method

.method public current()Lio/opentelemetry/context/Context;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    sget-object p0, Lio/opentelemetry/context/ThreadLocalContextStorage;->THREAD_LOCAL_STORAGE:Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/context/Context;

    .line 8
    .line 9
    return-object p0
.end method
