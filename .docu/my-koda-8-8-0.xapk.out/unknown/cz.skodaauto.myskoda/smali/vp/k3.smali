.class public final Lvp/k3;
.super Lvp/b0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public g:Lbp/c;

.field public h:Z

.field public final i:Lt1/j0;

.field public final j:Lc1/i2;

.field public final k:Lb81/d;


# direct methods
.method public constructor <init>(Lvp/g1;)V
    .locals 3

    .line 1
    invoke-direct {p0, p1}, Lvp/b0;-><init>(Lvp/g1;)V

    .line 2
    .line 3
    .line 4
    const/4 p1, 0x1

    .line 5
    iput-boolean p1, p0, Lvp/k3;->h:Z

    .line 6
    .line 7
    new-instance p1, Lt1/j0;

    .line 8
    .line 9
    const/16 v0, 0xd

    .line 10
    .line 11
    invoke-direct {p1, p0, v0}, Lt1/j0;-><init>(Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lvp/k3;->i:Lt1/j0;

    .line 15
    .line 16
    new-instance p1, Lc1/i2;

    .line 17
    .line 18
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object p0, p1, Lc1/i2;->g:Ljava/lang/Object;

    .line 22
    .line 23
    new-instance v0, Lvp/j3;

    .line 24
    .line 25
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v1, Lvp/g1;

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    invoke-direct {v0, p1, v1, v2}, Lvp/j3;-><init>(Ljava/lang/Object;Lvp/o1;I)V

    .line 31
    .line 32
    .line 33
    iput-object v0, p1, Lc1/i2;->f:Ljava/lang/Object;

    .line 34
    .line 35
    iget-object v0, v1, Lvp/g1;->n:Lto/a;

    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 41
    .line 42
    .line 43
    move-result-wide v0

    .line 44
    iput-wide v0, p1, Lc1/i2;->d:J

    .line 45
    .line 46
    iput-wide v0, p1, Lc1/i2;->e:J

    .line 47
    .line 48
    iput-object p1, p0, Lvp/k3;->j:Lc1/i2;

    .line 49
    .line 50
    new-instance p1, Lb81/d;

    .line 51
    .line 52
    invoke-direct {p1, p0}, Lb81/d;-><init>(Lvp/k3;)V

    .line 53
    .line 54
    .line 55
    iput-object p1, p0, Lvp/k3;->k:Lb81/d;

    .line 56
    .line 57
    return-void
.end method


# virtual methods
.method public final d0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final e0()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lvp/k3;->g:Lbp/c;

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    new-instance v0, Lbp/c;

    .line 9
    .line 10
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    const/4 v2, 0x1

    .line 15
    invoke-direct {v0, v1, v2}, Lbp/c;-><init>(Landroid/os/Looper;I)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lvp/k3;->g:Lbp/c;

    .line 19
    .line 20
    :cond_0
    return-void
.end method
