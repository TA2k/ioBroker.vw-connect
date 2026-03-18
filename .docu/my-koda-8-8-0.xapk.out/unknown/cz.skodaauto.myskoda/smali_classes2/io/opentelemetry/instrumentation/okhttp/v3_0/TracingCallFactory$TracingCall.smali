.class Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/j;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "TracingCall"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall$TracingCallback;
    }
.end annotation


# instance fields
.field private final callingContext:Lio/opentelemetry/context/Context;

.field private final delegate:Ld01/j;


# direct methods
.method public constructor <init>(Ld01/j;Lio/opentelemetry/context/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->delegate:Ld01/j;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->callingContext:Lio/opentelemetry/context/Context;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public cancel()V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->delegate:Ld01/j;

    .line 2
    .line 3
    invoke-interface {p0}, Ld01/j;->cancel()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public clone()Ld01/j;
    .locals 4

    .line 2
    invoke-static {}, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->access$000()Ljava/lang/reflect/Method;

    move-result-object v0

    if-nez v0, :cond_0

    .line 3
    invoke-super {p0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ld01/j;

    return-object p0

    .line 4
    :cond_0
    :try_start_0
    new-instance v0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;

    invoke-static {}, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->access$000()Ljava/lang/reflect/Method;

    move-result-object v1

    iget-object v2, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->delegate:Ld01/j;

    const/4 v3, 0x0

    invoke-virtual {v1, v2, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ld01/j;

    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    move-result-object v2

    invoke-direct {v0, v1, v2}, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;-><init>(Ld01/j;Lio/opentelemetry/context/Context;)V
    :try_end_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    .line 5
    :catch_0
    invoke-super {p0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ld01/j;

    return-object p0
.end method

.method public bridge synthetic clone()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->clone()Ld01/j;

    move-result-object p0

    return-object p0
.end method

.method public enqueue(Ld01/k;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->delegate:Ld01/j;

    .line 2
    .line 3
    new-instance v1, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall$TracingCallback;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->callingContext:Lio/opentelemetry/context/Context;

    .line 6
    .line 7
    invoke-direct {v1, p1, p0}, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall$TracingCallback;-><init>(Ld01/k;Lio/opentelemetry/context/Context;)V

    .line 8
    .line 9
    .line 10
    invoke-interface {v0, v1}, Ld01/j;->enqueue(Ld01/k;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public execute()Ld01/t0;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->callingContext:Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    invoke-interface {v0}, Lio/opentelemetry/context/Context;->makeCurrent()Lio/opentelemetry/context/Scope;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->delegate:Ld01/j;

    .line 8
    .line 9
    invoke-interface {p0}, Ld01/j;->execute()Ld01/t0;

    .line 10
    .line 11
    .line 12
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-interface {v0}, Lio/opentelemetry/context/Scope;->close()V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-object p0

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    :try_start_1
    invoke-interface {v0}, Lio/opentelemetry/context/Scope;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :catchall_1
    move-exception v0

    .line 27
    invoke-virtual {p0, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    :cond_1
    :goto_0
    throw p0
.end method

.method public isCanceled()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->delegate:Ld01/j;

    .line 2
    .line 3
    invoke-interface {p0}, Ld01/j;->isCanceled()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public isExecuted()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->delegate:Ld01/j;

    .line 2
    .line 3
    invoke-interface {p0}, Ld01/j;->isExecuted()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public request()Ld01/k0;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->delegate:Ld01/j;

    .line 2
    .line 3
    invoke-interface {p0}, Ld01/j;->request()Ld01/k0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public abstract synthetic tag(Lhy0/d;)Ljava/lang/Object;
.end method

.method public abstract synthetic tag(Lhy0/d;Lay0/a;)Ljava/lang/Object;
.end method

.method public abstract synthetic tag(Ljava/lang/Class;)Ljava/lang/Object;
.end method

.method public abstract synthetic tag(Ljava/lang/Class;Lay0/a;)Ljava/lang/Object;
.end method

.method public timeout()Lu01/j0;
    .locals 2

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->access$100()Ljava/lang/reflect/Method;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    :try_start_0
    invoke-static {}, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory;->access$100()Ljava/lang/reflect/Method;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;->delegate:Ld01/j;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-virtual {v0, p0, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lu01/j0;
    :try_end_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    .line 21
    return-object p0

    .line 22
    :catch_0
    :goto_0
    sget-object p0, Lu01/j0;->d:Lu01/i0;

    .line 23
    .line 24
    return-object p0
.end method
