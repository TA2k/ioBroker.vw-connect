.class public final Lvy0/g;
.super Lvy0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:Ljava/lang/Thread;

.field public final h:Lvy0/z0;


# direct methods
.method public constructor <init>(Lpx0/g;Ljava/lang/Thread;Lvy0/z0;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, p1, v0, v0}, Lvy0/a;-><init>(Lpx0/g;ZZ)V

    .line 3
    .line 4
    .line 5
    iput-object p2, p0, Lvy0/g;->g:Ljava/lang/Thread;

    .line 6
    .line 7
    iput-object p3, p0, Lvy0/g;->h:Lvy0/z0;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final v(Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object p0, p0, Lvy0/g;->g:Ljava/lang/Thread;

    .line 6
    .line 7
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    invoke-static {p0}, Ljava/util/concurrent/locks/LockSupport;->unpark(Ljava/lang/Thread;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    return-void
.end method
