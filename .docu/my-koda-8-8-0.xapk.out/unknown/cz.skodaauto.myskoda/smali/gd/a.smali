.class public final Lgd/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh2/e8;


# virtual methods
.method public final a(I)Z
    .locals 0

    .line 1
    invoke-static {}, Ljava/time/LocalDate;->now()Ljava/time/LocalDate;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/time/LocalDate;->getYear()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-lt p0, p1, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final b(J)Z
    .locals 2

    .line 1
    sget-object p0, Lmy0/g;->a:Lmy0/b;

    .line 2
    .line 3
    invoke-interface {p0}, Lmy0/b;->now()Lmy0/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-static {p0}, Lkp/t9;->d(Lmy0/f;)Lgz0/p;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p0}, Lgz0/p;->a()J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    cmp-long p0, p1, v0

    .line 16
    .line 17
    if-gtz p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method
