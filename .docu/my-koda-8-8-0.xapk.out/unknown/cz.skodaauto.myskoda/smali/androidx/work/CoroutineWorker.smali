.class public abstract Landroidx/work/CoroutineWorker;
.super Leb/v;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008&\u0018\u00002\u00020\u0001:\u0001\u0008B\u0017\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\t"
    }
    d2 = {
        "Landroidx/work/CoroutineWorker;",
        "Leb/v;",
        "Landroid/content/Context;",
        "appContext",
        "Landroidx/work/WorkerParameters;",
        "params",
        "<init>",
        "(Landroid/content/Context;Landroidx/work/WorkerParameters;)V",
        "eb/f",
        "work-runtime_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final h:Landroidx/work/WorkerParameters;

.field public final i:Leb/f;


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroidx/work/WorkerParameters;)V
    .locals 1

    .line 1
    const-string v0, "appContext"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "params"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, p1, p2}, Leb/v;-><init>(Landroid/content/Context;Landroidx/work/WorkerParameters;)V

    .line 12
    .line 13
    .line 14
    iput-object p2, p0, Landroidx/work/CoroutineWorker;->h:Landroidx/work/WorkerParameters;

    .line 15
    .line 16
    sget-object p1, Leb/f;->e:Leb/f;

    .line 17
    .line 18
    iput-object p1, p0, Landroidx/work/CoroutineWorker;->i:Leb/f;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a()Ly4/k;
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroidx/work/CoroutineWorker;->e()Lvy0/x;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {}, Lvy0/e0;->d()Lvy0/k1;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v0, v1}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v1, Leb/g;

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    const/4 v3, 0x0

    .line 17
    invoke-direct {v1, p0, v3, v2}, Leb/g;-><init>(Landroidx/work/CoroutineWorker;Lkotlin/coroutines/Continuation;I)V

    .line 18
    .line 19
    .line 20
    invoke-static {v0, v1}, Lkp/c6;->b(Lpx0/g;Lay0/n;)Ly4/k;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public final c()Ly4/k;
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroidx/work/CoroutineWorker;->e()Lvy0/x;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Leb/f;->e:Leb/f;

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Landroidx/work/CoroutineWorker;->e()Lvy0/x;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    iget-object v0, p0, Landroidx/work/CoroutineWorker;->h:Landroidx/work/WorkerParameters;

    .line 19
    .line 20
    iget-object v0, v0, Landroidx/work/WorkerParameters;->e:Lpx0/g;

    .line 21
    .line 22
    :goto_0
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    invoke-static {}, Lvy0/e0;->d()Lvy0/k1;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-interface {v0, v1}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    new-instance v1, Leb/g;

    .line 34
    .line 35
    const/4 v2, 0x1

    .line 36
    const/4 v3, 0x0

    .line 37
    invoke-direct {v1, p0, v3, v2}, Leb/g;-><init>(Landroidx/work/CoroutineWorker;Lkotlin/coroutines/Continuation;I)V

    .line 38
    .line 39
    .line 40
    invoke-static {v0, v1}, Lkp/c6;->b(Lpx0/g;Lay0/n;)Ly4/k;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method

.method public abstract d(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
.end method

.method public e()Lvy0/x;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/work/CoroutineWorker;->i:Leb/f;

    .line 2
    .line 3
    return-object p0
.end method
