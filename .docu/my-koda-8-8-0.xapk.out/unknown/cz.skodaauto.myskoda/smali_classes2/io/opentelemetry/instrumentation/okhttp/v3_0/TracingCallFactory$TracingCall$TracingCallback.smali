.class Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall$TracingCallback;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/k;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "TracingCallback"
.end annotation


# instance fields
.field private final callingContext:Lio/opentelemetry/context/Context;

.field private final delegate:Ld01/k;


# direct methods
.method public constructor <init>(Ld01/k;Lio/opentelemetry/context/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall$TracingCallback;->delegate:Ld01/k;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall$TracingCallback;->callingContext:Lio/opentelemetry/context/Context;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public onFailure(Ld01/j;Ljava/io/IOException;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall$TracingCallback;->callingContext:Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    invoke-interface {v0}, Lio/opentelemetry/context/Context;->makeCurrent()Lio/opentelemetry/context/Scope;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall$TracingCallback;->delegate:Ld01/k;

    .line 8
    .line 9
    invoke-interface {p0, p1, p2}, Ld01/k;->onFailure(Ld01/j;Ljava/io/IOException;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-interface {v0}, Lio/opentelemetry/context/Scope;->close()V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    :try_start_1
    invoke-interface {v0}, Lio/opentelemetry/context/Scope;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catchall_1
    move-exception p1

    .line 26
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    :cond_1
    :goto_0
    throw p0
.end method

.method public onResponse(Ld01/j;Ld01/t0;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall$TracingCallback;->callingContext:Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    invoke-interface {v0}, Lio/opentelemetry/context/Context;->makeCurrent()Lio/opentelemetry/context/Scope;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/okhttp/v3_0/TracingCallFactory$TracingCall$TracingCallback;->delegate:Ld01/k;

    .line 8
    .line 9
    invoke-interface {p0, p1, p2}, Ld01/k;->onResponse(Ld01/j;Ld01/t0;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    invoke-interface {v0}, Lio/opentelemetry/context/Scope;->close()V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    :try_start_1
    invoke-interface {v0}, Lio/opentelemetry/context/Scope;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catchall_1
    move-exception p1

    .line 26
    invoke-virtual {p0, p1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    :cond_1
    :goto_0
    throw p0
.end method
