.class public final Lvy0/t1;
.super Lpx0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/i1;


# static fields
.field public static final d:Lvy0/t1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lvy0/t1;

    .line 2
    .line 3
    sget-object v1, Lvy0/h1;->d:Lvy0/h1;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lpx0/a;-><init>(Lpx0/f;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lvy0/t1;->d:Lvy0/t1;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final E(Lay0/k;)Lvy0/r0;
    .locals 0

    .line 1
    sget-object p0, Lvy0/u1;->d:Lvy0/u1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final H(Lvy0/p1;)Lvy0/o;
    .locals 0

    .line 1
    sget-object p0, Lvy0/u1;->d:Lvy0/u1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final a()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final b()Lky0/j;
    .locals 0

    .line 1
    sget-object p0, Lky0/e;->a:Lky0/e;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d(Ljava/util/concurrent/CancellationException;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final f(ZZLay0/k;)Lvy0/r0;
    .locals 0

    .line 1
    sget-object p0, Lvy0/u1;->d:Lvy0/u1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final isCancelled()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final j()Ljava/util/concurrent/CancellationException;
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 2
    .line 3
    const-string v0, "This job is always active"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public final l(Lrx0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string p1, "This job is always active"

    .line 4
    .line 5
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public final start()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "NonCancellable"

    .line 2
    .line 3
    return-object p0
.end method
