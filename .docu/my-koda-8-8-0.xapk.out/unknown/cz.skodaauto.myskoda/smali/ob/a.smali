.class public final Lob/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lla/a0;

.field public final b:Lvy0/x;

.field public final c:Landroid/os/Handler;

.field public final d:Lj0/e;


# direct methods
.method public constructor <init>(Ljava/util/concurrent/ExecutorService;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/os/Handler;

    .line 5
    .line 6
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lob/a;->c:Landroid/os/Handler;

    .line 14
    .line 15
    new-instance v0, Lj0/e;

    .line 16
    .line 17
    invoke-direct {v0, p0}, Lj0/e;-><init>(Lob/a;)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lob/a;->d:Lj0/e;

    .line 21
    .line 22
    new-instance v0, Lla/a0;

    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    invoke-direct {v0, p1, v1}, Lla/a0;-><init>(Ljava/util/concurrent/Executor;I)V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lob/a;->a:Lla/a0;

    .line 29
    .line 30
    invoke-static {v0}, Lvy0/e0;->t(Ljava/util/concurrent/Executor;)Lvy0/x;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iput-object p1, p0, Lob/a;->b:Lvy0/x;

    .line 35
    .line 36
    return-void
.end method
