.class public final Ltechnology/cariad/cat/genx/GenXDispatcherImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/GenXDispatcher;
.implements Ljava/io/Closeable;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000:\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\t\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0000\u0018\u00002\u00020\u00012\u00020\u0002B\u0007\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J%\u0010\u000c\u001a\u00020\u00082\u0006\u0010\u0006\u001a\u00020\u00052\u000c\u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007H\u0002\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u001d\u0010\u000c\u001a\u00020\u00082\u000c\u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007H\u0016\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\'\u0010\u000c\u001a\u00020\u00082\u0006\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u0010\u001a\u00020\u000e2\u0006\u0010\u0011\u001a\u00020\u000eH\u0016\u00a2\u0006\u0004\u0008\u000c\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\u0008H\u0016\u00a2\u0006\u0004\u0008\u0013\u0010\u0004R\u0014\u0010\u0015\u001a\u00020\u00148\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0015\u0010\u0016R\u0014\u0010\u0018\u001a\u00020\u00178\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0018\u0010\u0019\u00a8\u0006\u001a"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/GenXDispatcherImpl;",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "Ljava/io/Closeable;",
        "<init>",
        "()V",
        "Lmy0/c;",
        "delay",
        "Lkotlin/Function0;",
        "Llx0/b0;",
        "function",
        "dispatch-VtjQ1oo",
        "(JLay0/a;)V",
        "dispatch",
        "(Lay0/a;)V",
        "",
        "nativeFunc",
        "delayMs",
        "context",
        "(JJJ)V",
        "close",
        "Landroid/os/HandlerThread;",
        "handlerThread",
        "Landroid/os/HandlerThread;",
        "Landroid/os/Handler;",
        "handler",
        "Landroid/os/Handler;",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final handler:Landroid/os/Handler;

.field private final handlerThread:Landroid/os/HandlerThread;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/os/HandlerThread;

    .line 5
    .line 6
    const-string v1, "GenX.Dispatcher"

    .line 7
    .line 8
    invoke-direct {v0, v1}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->handlerThread:Landroid/os/HandlerThread;

    .line 15
    .line 16
    new-instance v1, Landroid/os/Handler;

    .line 17
    .line 18
    invoke-virtual {v0}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-direct {v1, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 23
    .line 24
    .line 25
    iput-object v1, p0, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->handler:Landroid/os/Handler;

    .line 26
    .line 27
    return-void
.end method

.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->close$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic b(Lay0/a;)V
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->dispatch_VtjQ1oo$lambda$0(Lay0/a;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static final close$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "close()"

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic d()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->dispatch$lambda$2()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static final dispatch$lambda$0(Lay0/a;)V
    .locals 0

    .line 1
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static final dispatch$lambda$1(Ltechnology/cariad/cat/genx/GenXDispatcherImpl;JJ)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/GenXDispatcherKt;->nativeExecute(Ltechnology/cariad/cat/genx/GenXDispatcher;JJ)I

    .line 2
    .line 3
    .line 4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    return-object p0
.end method

.method private static final dispatch$lambda$2()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "dispatch(): Failed to execute a function, called by CoreGenX."

    .line 2
    .line 3
    return-object v0
.end method

.method private final dispatch-VtjQ1oo(JLay0/a;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->handler:Landroid/os/Handler;

    .line 2
    .line 3
    new-instance v0, Ltechnology/cariad/cat/genx/h;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-direct {v0, p3, v1}, Ltechnology/cariad/cat/genx/h;-><init>(Lay0/a;I)V

    .line 7
    .line 8
    .line 9
    invoke-static {p1, p2}, Lmy0/c;->e(J)J

    .line 10
    .line 11
    .line 12
    move-result-wide p1

    .line 13
    invoke-virtual {p0, v0, p1, p2}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method private static final dispatch_VtjQ1oo$lambda$0(Lay0/a;)V
    .locals 0

    .line 1
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic f(Ltechnology/cariad/cat/genx/GenXDispatcherImpl;JJ)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->dispatch$lambda$1(Ltechnology/cariad/cat/genx/GenXDispatcherImpl;JJ)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Lay0/a;)V
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->dispatch$lambda$0(Lay0/a;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public close()V
    .locals 7

    .line 1
    new-instance v3, Ltechnology/cariad/cat/genx/s0;

    .line 2
    .line 3
    const/16 v0, 0x9

    .line 4
    .line 5
    invoke-direct {v3, v0}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lt51/j;

    .line 9
    .line 10
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v5

    .line 14
    const-string v1, "getName(...)"

    .line 15
    .line 16
    invoke-static {v1}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    const-string v1, "GenX"

    .line 21
    .line 22
    sget-object v2, Lt51/g;->a:Lt51/g;

    .line 23
    .line 24
    const/4 v4, 0x0

    .line 25
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 29
    .line 30
    .line 31
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->handlerThread:Landroid/os/HandlerThread;

    .line 32
    .line 33
    invoke-virtual {p0}, Landroid/os/HandlerThread;->quitSafely()Z

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public dispatch(JJJ)V
    .locals 7

    .line 2
    :try_start_0
    sget v0, Lmy0/c;->g:I

    sget-object v0, Lmy0/e;->g:Lmy0/e;

    invoke-static {p3, p4, v0}, Lmy0/h;->t(JLmy0/e;)J

    move-result-wide p3

    new-instance v0, Ltechnology/cariad/cat/genx/i;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    move-object v1, p0

    move-wide v2, p1

    move-wide v4, p5

    :try_start_1
    invoke-direct/range {v0 .. v5}, Ltechnology/cariad/cat/genx/i;-><init>(Ltechnology/cariad/cat/genx/GenXDispatcherImpl;JJ)V

    invoke-direct {v1, p3, p4, v0}, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->dispatch-VtjQ1oo(JLay0/a;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    return-void

    :catch_0
    move-exception v0

    :goto_0
    move-object p0, v0

    move-object v4, p0

    goto :goto_1

    :catch_1
    move-exception v0

    move-object v1, p0

    goto :goto_0

    .line 3
    :goto_1
    new-instance v3, Ltechnology/cariad/cat/genx/s0;

    const/16 p0, 0xa

    invoke-direct {v3, p0}, Ltechnology/cariad/cat/genx/s0;-><init>(I)V

    .line 4
    new-instance v0, Lt51/j;

    .line 5
    invoke-static {v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v5

    .line 6
    const-string p0, "getName(...)"

    .line 7
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    .line 8
    const-string v1, "GenX"

    sget-object v2, Lt51/e;->a:Lt51/e;

    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    return-void
.end method

.method public dispatch(Lay0/a;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/a;",
            ")V"
        }
    .end annotation

    const-string v0, "function"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXDispatcherImpl;->handler:Landroid/os/Handler;

    new-instance v0, Ltechnology/cariad/cat/genx/h;

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Ltechnology/cariad/cat/genx/h;-><init>(Lay0/a;I)V

    invoke-virtual {p0, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    return-void
.end method
