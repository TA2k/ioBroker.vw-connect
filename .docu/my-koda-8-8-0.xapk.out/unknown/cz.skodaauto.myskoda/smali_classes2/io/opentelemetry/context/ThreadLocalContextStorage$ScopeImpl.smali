.class Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/Scope;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/context/ThreadLocalContextStorage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "ScopeImpl"
.end annotation


# instance fields
.field private final beforeAttach:Lio/opentelemetry/context/Context;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private closed:Z

.field final synthetic this$0:Lio/opentelemetry/context/ThreadLocalContextStorage;

.field private final toAttach:Lio/opentelemetry/context/Context;


# direct methods
.method private constructor <init>(Lio/opentelemetry/context/ThreadLocalContextStorage;Lio/opentelemetry/context/Context;Lio/opentelemetry/context/Context;)V
    .locals 0
    .param p1    # Lio/opentelemetry/context/ThreadLocalContextStorage;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 2
    iput-object p1, p0, Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;->this$0:Lio/opentelemetry/context/ThreadLocalContextStorage;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p2, p0, Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;->beforeAttach:Lio/opentelemetry/context/Context;

    .line 4
    iput-object p3, p0, Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;->toAttach:Lio/opentelemetry/context/Context;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/context/ThreadLocalContextStorage;Lio/opentelemetry/context/Context;Lio/opentelemetry/context/Context;Lio/opentelemetry/context/ThreadLocalContextStorage$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;-><init>(Lio/opentelemetry/context/ThreadLocalContextStorage;Lio/opentelemetry/context/Context;Lio/opentelemetry/context/Context;)V

    return-void
.end method


# virtual methods
.method public close()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;->closed:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;->this$0:Lio/opentelemetry/context/ThreadLocalContextStorage;

    .line 6
    .line 7
    invoke-virtual {v0}, Lio/opentelemetry/context/ThreadLocalContextStorage;->current()Lio/opentelemetry/context/Context;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v1, p0, Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;->toAttach:Lio/opentelemetry/context/Context;

    .line 12
    .line 13
    if-ne v0, v1, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    iput-boolean v0, p0, Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;->closed:Z

    .line 17
    .line 18
    invoke-static {}, Lio/opentelemetry/context/ThreadLocalContextStorage;->access$100()Ljava/lang/ThreadLocal;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iget-object p0, p0, Lio/opentelemetry/context/ThreadLocalContextStorage$ScopeImpl;->beforeAttach:Lio/opentelemetry/context/Context;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_0
    invoke-static {}, Lio/opentelemetry/context/ThreadLocalContextStorage;->access$200()Ljava/util/logging/Logger;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    sget-object v0, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 33
    .line 34
    const-string v1, " Trying to close scope which does not represent current context. Ignoring the call."

    .line 35
    .line 36
    invoke-virtual {p0, v0, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method
