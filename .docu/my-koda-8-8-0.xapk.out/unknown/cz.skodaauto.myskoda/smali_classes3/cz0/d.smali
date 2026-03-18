.class public final Lcz0/d;
.super Lvy0/a1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Executor;


# static fields
.field public static final e:Lcz0/d;

.field public static final f:Lvy0/x;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcz0/d;

    .line 2
    .line 3
    invoke-direct {v0}, Lvy0/x;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcz0/d;->e:Lcz0/d;

    .line 7
    .line 8
    sget-object v0, Lcz0/l;->e:Lcz0/l;

    .line 9
    .line 10
    sget v1, Laz0/s;->a:I

    .line 11
    .line 12
    const/16 v2, 0x40

    .line 13
    .line 14
    if-ge v2, v1, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v1, v2

    .line 18
    :goto_0
    const/16 v2, 0xc

    .line 19
    .line 20
    const-string v3, "kotlinx.coroutines.io.parallelism"

    .line 21
    .line 22
    invoke-static {v1, v2, v3}, Laz0/b;->l(IILjava/lang/String;)I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    invoke-virtual {v0, v1}, Lcz0/l;->W(I)Lvy0/x;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sput-object v0, Lcz0/d;->f:Lvy0/x;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final T(Lpx0/g;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    sget-object p0, Lcz0/d;->f:Lvy0/x;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lvy0/x;->T(Lpx0/g;Ljava/lang/Runnable;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final U(Lpx0/g;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    sget-object p0, Lcz0/d;->f:Lvy0/x;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lvy0/x;->U(Lpx0/g;Ljava/lang/Runnable;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final W(I)Lvy0/x;
    .locals 0

    .line 1
    sget-object p0, Lcz0/l;->e:Lcz0/l;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lcz0/l;->W(I)Lvy0/x;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final close()V
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 2
    .line 3
    const-string v0, "Cannot be invoked on Dispatchers.IO"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method

.method public final e0()Ljava/util/concurrent/Executor;
    .locals 0

    .line 1
    return-object p0
.end method

.method public final execute(Ljava/lang/Runnable;)V
    .locals 1

    .line 1
    sget-object v0, Lpx0/h;->d:Lpx0/h;

    .line 2
    .line 3
    invoke-virtual {p0, v0, p1}, Lcz0/d;->T(Lpx0/g;Ljava/lang/Runnable;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "Dispatchers.IO"

    .line 2
    .line 3
    return-object p0
.end method
