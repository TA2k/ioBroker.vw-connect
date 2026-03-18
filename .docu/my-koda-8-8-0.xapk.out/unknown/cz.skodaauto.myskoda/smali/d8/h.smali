.class public final Ld8/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld8/j;


# virtual methods
.method public final c(Lt7/o;)I
    .locals 0

    .line 1
    iget-object p0, p1, Lt7/o;->r:Lt7/k;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final d(Landroid/os/Looper;Lb8/k;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final f(Ld8/f;Lt7/o;)Laq/a;
    .locals 1

    .line 1
    iget-object p0, p2, Lt7/o;->r:Lt7/k;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    new-instance p0, Laq/a;

    .line 8
    .line 9
    new-instance p1, Ld8/d;

    .line 10
    .line 11
    new-instance p2, Ld8/l;

    .line 12
    .line 13
    invoke-direct {p2}, Ljava/lang/Exception;-><init>()V

    .line 14
    .line 15
    .line 16
    const/16 v0, 0x1771

    .line 17
    .line 18
    invoke-direct {p1, p2, v0}, Ld8/d;-><init>(Ljava/lang/Throwable;I)V

    .line 19
    .line 20
    .line 21
    const/16 p2, 0x10

    .line 22
    .line 23
    invoke-direct {p0, p1, p2}, Laq/a;-><init>(Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    return-object p0
.end method
