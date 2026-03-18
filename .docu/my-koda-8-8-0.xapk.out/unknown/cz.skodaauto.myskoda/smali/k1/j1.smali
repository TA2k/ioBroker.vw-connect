.class public final Lk1/j1;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/r1;


# instance fields
.field public r:Lt3/a;


# virtual methods
.method public final l(Lt4/c;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    instance-of p1, p2, Lk1/d1;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    check-cast p2, Lk1/d1;

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 p2, 0x0

    .line 9
    :goto_0
    if-nez p2, :cond_1

    .line 10
    .line 11
    new-instance p2, Lk1/d1;

    .line 12
    .line 13
    invoke-direct {p2}, Lk1/d1;-><init>()V

    .line 14
    .line 15
    .line 16
    :cond_1
    new-instance p1, Lk1/a;

    .line 17
    .line 18
    iget-object p0, p0, Lk1/j1;->r:Lt3/a;

    .line 19
    .line 20
    invoke-direct {p1, p0}, Lk1/a;-><init>(Lt3/a;)V

    .line 21
    .line 22
    .line 23
    new-instance p0, Lk1/v;

    .line 24
    .line 25
    invoke-direct {p0, p1}, Lk1/v;-><init>(Lk1/a;)V

    .line 26
    .line 27
    .line 28
    iput-object p0, p2, Lk1/d1;->c:Lk1/d;

    .line 29
    .line 30
    return-object p2
.end method
