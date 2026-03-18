.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ln71/a;
.implements Ljava/io/Closeable;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\u000b\n\u0002\u0008\u0006\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u0002B\u0007\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J%\u0010\u000b\u001a\u00020\n2\u0006\u0010\u0006\u001a\u00020\u00052\u000c\u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007H\u0016\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ%\u0010\r\u001a\u00020\n2\u0006\u0010\u0006\u001a\u00020\u00052\u000c\u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007H\u0016\u00a2\u0006\u0004\u0008\r\u0010\u000cJ%\u0010\u000e\u001a\u00020\n2\u0006\u0010\u0006\u001a\u00020\u00052\u000c\u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00080\u0007H\u0016\u00a2\u0006\u0004\u0008\u000e\u0010\u000cJ\u000f\u0010\u000f\u001a\u00020\u0008H\u0016\u00a2\u0006\u0004\u0008\u000f\u0010\u0004J\u000f\u0010\u0010\u001a\u00020\u0008H\u0016\u00a2\u0006\u0004\u0008\u0010\u0010\u0004R\u0016\u0010\u0012\u001a\u00020\u00118\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\u0012\u0010\u0013R\u0014\u0010\u0015\u001a\u00020\u00148\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0015\u0010\u0016R\u0016\u0010\u0017\u001a\u00020\u00118\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\u0017\u0010\u0013R\u0016\u0010\u0018\u001a\u00020\u00148\u0002@\u0002X\u0082\u000e\u00a2\u0006\u0006\n\u0004\u0008\u0018\u0010\u0016R\u0014\u0010\u0019\u001a\u00020\u00148\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0019\u0010\u0016R$\u0010\u001c\u001a\u00020\u001a2\u0006\u0010\u001b\u001a\u00020\u001a8\u0000@BX\u0080\u000e\u00a2\u0006\u000c\n\u0004\u0008\u001c\u0010\u001d\u001a\u0004\u0008\u001e\u0010\u001f\u00a8\u0006 "
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;",
        "Ln71/a;",
        "Ljava/io/Closeable;",
        "<init>",
        "()V",
        "",
        "delayInMilliseconds",
        "Lkotlin/Function0;",
        "Llx0/b0;",
        "function",
        "Ln71/b;",
        "dispatchToRPAThread",
        "(JLay0/a;)Ln71/b;",
        "dispatchToIOThread",
        "dispatchToMainThread",
        "cancelAllDispatchJobs",
        "close",
        "Landroid/os/HandlerThread;",
        "rpaHandlerThread",
        "Landroid/os/HandlerThread;",
        "Landroid/os/Handler;",
        "rpaHandler",
        "Landroid/os/Handler;",
        "ioHandlerThread",
        "ioHandler",
        "mainHandler",
        "",
        "value",
        "handlerThreadsAreTerminated",
        "Z",
        "getHandlerThreadsAreTerminated$remoteparkassistplugin_release",
        "()Z",
        "remoteparkassistplugin_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final $stable:I = 0x8


# instance fields
.field private handlerThreadsAreTerminated:Z

.field private ioHandler:Landroid/os/Handler;

.field private ioHandlerThread:Landroid/os/HandlerThread;

.field private final mainHandler:Landroid/os/Handler;

.field private final rpaHandler:Landroid/os/Handler;

.field private rpaHandlerThread:Landroid/os/HandlerThread;


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
    const-string v1, "RPA_HT"

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
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->rpaHandlerThread:Landroid/os/HandlerThread;

    .line 15
    .line 16
    new-instance v0, Landroid/os/Handler;

    .line 17
    .line 18
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->rpaHandlerThread:Landroid/os/HandlerThread;

    .line 19
    .line 20
    invoke-virtual {v1}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 25
    .line 26
    .line 27
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->rpaHandler:Landroid/os/Handler;

    .line 28
    .line 29
    new-instance v0, Landroid/os/HandlerThread;

    .line 30
    .line 31
    const-string v1, "RPA_IO_HT"

    .line 32
    .line 33
    invoke-direct {v0, v1}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->ioHandlerThread:Landroid/os/HandlerThread;

    .line 40
    .line 41
    new-instance v0, Landroid/os/Handler;

    .line 42
    .line 43
    iget-object v1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->ioHandlerThread:Landroid/os/HandlerThread;

    .line 44
    .line 45
    invoke-virtual {v1}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 50
    .line 51
    .line 52
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->ioHandler:Landroid/os/Handler;

    .line 53
    .line 54
    new-instance v0, Landroid/os/Handler;

    .line 55
    .line 56
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 61
    .line 62
    .line 63
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->mainHandler:Landroid/os/Handler;

    .line 64
    .line 65
    return-void
.end method

.method public static synthetic B(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Lh91/c;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->dispatchToMainThread$lambda$2(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Ljava/lang/Runnable;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic E()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->close$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic H(Lay0/a;)V
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->dispatchToRPAThread$lambda$0(Lay0/a;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic M(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Lh91/c;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->dispatchToIOThread$lambda$2(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Ljava/lang/Runnable;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final cancelAllDispatchJobs$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "cancelAllDispatchJobs()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final close$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "close()"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final dispatchToIOThread$lambda$0(Lay0/a;)V
    .locals 0

    .line 1
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static final dispatchToIOThread$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "dispatchToIOThread(): failed! HandlerThread already quit."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final dispatchToIOThread$lambda$2(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Ljava/lang/Runnable;)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->ioHandler:Landroid/os/Handler;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private static final dispatchToMainThread$lambda$0(Lay0/a;)V
    .locals 0

    .line 1
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static final dispatchToMainThread$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "dispatchToMainThread(): failed!"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final dispatchToMainThread$lambda$2(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Ljava/lang/Runnable;)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->mainHandler:Landroid/os/Handler;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method private static final dispatchToRPAThread$lambda$0(Lay0/a;)V
    .locals 0

    .line 1
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static final dispatchToRPAThread$lambda$1()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "dispatchToRPAThread(): failed! HandlerThread already quit."

    .line 2
    .line 3
    return-object v0
.end method

.method private static final dispatchToRPAThread$lambda$2(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Ljava/lang/Runnable;)Llx0/b0;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->rpaHandler:Landroid/os/Handler;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 7
    .line 8
    return-object p0
.end method

.method public static synthetic f()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->dispatchToRPAThread$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic g(Lay0/a;)V
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->dispatchToIOThread$lambda$0(Lay0/a;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic h()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->cancelAllDispatchJobs$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic j(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Lh91/c;)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->dispatchToRPAThread$lambda$2(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;Ljava/lang/Runnable;)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic k()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->dispatchToIOThread$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic l(Lay0/a;)V
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->dispatchToMainThread$lambda$0(Lay0/a;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic q()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->dispatchToMainThread$lambda$1()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method


# virtual methods
.method public cancelAllDispatchJobs()V
    .locals 2

    .line 1
    new-instance v0, Lt61/d;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {v0, v1}, Lt61/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->rpaHandlerThread:Landroid/os/HandlerThread;

    .line 11
    .line 12
    invoke-virtual {v0}, Landroid/os/HandlerThread;->quit()Z

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->ioHandlerThread:Landroid/os/HandlerThread;

    .line 16
    .line 17
    invoke-virtual {v0}, Landroid/os/HandlerThread;->quit()Z

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    iput-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->handlerThreadsAreTerminated:Z

    .line 22
    .line 23
    return-void
.end method

.method public close()V
    .locals 2

    .line 1
    new-instance v0, Lt61/d;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lt61/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0, v0}, Llp/i1;->b(Ljava/lang/Object;Lay0/a;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->cancelAllDispatchJobs()V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public dispatchToIOThread(JLay0/a;)Ln71/b;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Lay0/a;",
            ")",
            "Ln71/b;"
        }
    .end annotation

    .line 1
    const-string v0, "function"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh91/c;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    invoke-direct {v0, p3, v1}, Lh91/c;-><init>(Lay0/a;I)V

    .line 10
    .line 11
    .line 12
    iget-object p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->ioHandler:Landroid/os/Handler;

    .line 13
    .line 14
    invoke-virtual {p3, v0, p1, p2}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    if-nez p1, :cond_0

    .line 19
    .line 20
    new-instance p1, Lt61/d;

    .line 21
    .line 22
    const/4 p2, 0x2

    .line 23
    invoke-direct {p1, p2}, Lt61/d;-><init>(I)V

    .line 24
    .line 25
    .line 26
    const/4 p2, 0x0

    .line 27
    invoke-static {p0, p2, p1}, Llp/i1;->c(Ljava/lang/Object;Ljava/io/IOException;Lay0/a;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    new-instance p1, Ln71/b;

    .line 31
    .line 32
    new-instance p2, Lt61/g;

    .line 33
    .line 34
    const/16 p3, 0x9

    .line 35
    .line 36
    invoke-direct {p2, p3, p0, v0}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-direct {p1, p2}, Ln71/b;-><init>(Lay0/a;)V

    .line 40
    .line 41
    .line 42
    return-object p1
.end method

.method public dispatchToMainThread(JLay0/a;)Ln71/b;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Lay0/a;",
            ")",
            "Ln71/b;"
        }
    .end annotation

    .line 1
    const-string v0, "function"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh91/c;

    .line 7
    .line 8
    const/4 v1, 0x2

    .line 9
    invoke-direct {v0, p3, v1}, Lh91/c;-><init>(Lay0/a;I)V

    .line 10
    .line 11
    .line 12
    iget-object p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->mainHandler:Landroid/os/Handler;

    .line 13
    .line 14
    invoke-virtual {p3, v0, p1, p2}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    if-nez p1, :cond_0

    .line 19
    .line 20
    new-instance p1, Lt61/d;

    .line 21
    .line 22
    const/4 p2, 0x4

    .line 23
    invoke-direct {p1, p2}, Lt61/d;-><init>(I)V

    .line 24
    .line 25
    .line 26
    const/4 p2, 0x0

    .line 27
    invoke-static {p0, p2, p1}, Llp/i1;->c(Ljava/lang/Object;Ljava/io/IOException;Lay0/a;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    new-instance p1, Ln71/b;

    .line 31
    .line 32
    new-instance p2, Lt61/g;

    .line 33
    .line 34
    const/16 p3, 0xa

    .line 35
    .line 36
    invoke-direct {p2, p3, p0, v0}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-direct {p1, p2}, Ln71/b;-><init>(Lay0/a;)V

    .line 40
    .line 41
    .line 42
    return-object p1
.end method

.method public dispatchToRPAThread(JLay0/a;)Ln71/b;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(J",
            "Lay0/a;",
            ")",
            "Ln71/b;"
        }
    .end annotation

    .line 1
    const-string v0, "function"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lh91/c;

    .line 7
    .line 8
    const/4 v1, 0x3

    .line 9
    invoke-direct {v0, p3, v1}, Lh91/c;-><init>(Lay0/a;I)V

    .line 10
    .line 11
    .line 12
    iget-object p3, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->rpaHandler:Landroid/os/Handler;

    .line 13
    .line 14
    invoke-virtual {p3, v0, p1, p2}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    if-nez p1, :cond_0

    .line 19
    .line 20
    new-instance p1, Lt61/d;

    .line 21
    .line 22
    const/4 p2, 0x6

    .line 23
    invoke-direct {p1, p2}, Lt61/d;-><init>(I)V

    .line 24
    .line 25
    .line 26
    const/4 p2, 0x0

    .line 27
    invoke-static {p0, p2, p1}, Llp/i1;->c(Ljava/lang/Object;Ljava/io/IOException;Lay0/a;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    new-instance p1, Ln71/b;

    .line 31
    .line 32
    new-instance p2, Lt61/g;

    .line 33
    .line 34
    const/16 p3, 0x8

    .line 35
    .line 36
    invoke-direct {p2, p3, p0, v0}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-direct {p1, p2}, Ln71/b;-><init>(Lay0/a;)V

    .line 40
    .line 41
    .line 42
    return-object p1
.end method

.method public final getHandlerThreadsAreTerminated$remoteparkassistplugin_release()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPADispatcher;->handlerThreadsAreTerminated:Z

    .line 2
    .line 3
    return p0
.end method
