.class public abstract Lkp/g6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final b(DLqr0/s;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "unitsType"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1, p2}, Lkp/g6;->e(DLqr0/s;)Llx0/l;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    iget-object p1, p0, Llx0/l;->d:Ljava/lang/Object;

    .line 11
    .line 12
    iget-object p0, p0, Llx0/l;->e:Ljava/lang/Object;

    .line 13
    .line 14
    new-instance p2, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string p1, " "

    .line 23
    .line 24
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public static final c(Lqr0/s;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_2

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p0, v0, :cond_1

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    if-ne p0, v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, La8/r0;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0

    .line 20
    :cond_1
    :goto_0
    sget-object p0, Lqr0/f;->k:Lqr0/f;

    .line 21
    .line 22
    invoke-static {p0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_2
    sget-object p0, Lqr0/o;->g:Lqr0/o;

    .line 28
    .line 29
    invoke-static {p0}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method

.method public static final d(DLqr0/s;)D
    .locals 2

    .line 1
    const-string v0, "unitsType"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p2

    .line 10
    if-eqz p2, :cond_3

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p2, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-ne p2, v0, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, La8/r0;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    :goto_0
    const-wide/16 v0, 0x0

    .line 26
    .line 27
    cmpg-double p2, p0, v0

    .line 28
    .line 29
    if-gtz p2, :cond_2

    .line 30
    .line 31
    return-wide v0

    .line 32
    :cond_2
    const-wide v0, 0x404f1165e7254814L    # 62.13592233009709

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    div-double/2addr v0, p0

    .line 38
    return-wide v0

    .line 39
    :cond_3
    return-wide p0
.end method

.method public static final e(DLqr0/s;)Llx0/l;
    .locals 1

    .line 1
    const-string v0, "unitsType"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0, p1, p2}, Lkp/g6;->d(DLqr0/s;)D

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-static {v0, p0, p1}, Lkp/k6;->a(ID)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-eqz p1, :cond_2

    .line 20
    .line 21
    if-eq p1, v0, :cond_1

    .line 22
    .line 23
    const/4 p2, 0x2

    .line 24
    if-ne p1, p2, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance p0, La8/r0;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    :goto_0
    sget-object p1, Lqr0/f;->k:Lqr0/f;

    .line 34
    .line 35
    invoke-static {p1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    goto :goto_1

    .line 40
    :cond_2
    sget-object p1, Lqr0/o;->g:Lqr0/o;

    .line 41
    .line 42
    invoke-static {p1}, Lkp/m6;->a(Lqr0/m;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    :goto_1
    new-instance p2, Llx0/l;

    .line 47
    .line 48
    invoke-direct {p2, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    return-object p2
.end method


# virtual methods
.method public a(Ljava/lang/String;Leb/m;Leb/z;)Leb/c0;
    .locals 7

    .line 1
    const-string v0, "uniqueWorkName"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "request"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p3}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object v5

    .line 15
    move-object v2, p0

    .line 16
    check-cast v2, Lfb/u;

    .line 17
    .line 18
    new-instance v1, Lfb/o;

    .line 19
    .line 20
    const/4 v6, 0x0

    .line 21
    move-object v3, p1

    .line 22
    move-object v4, p2

    .line 23
    invoke-direct/range {v1 .. v6}, Lfb/o;-><init>(Lfb/u;Ljava/lang/String;Leb/m;Ljava/util/List;I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1}, Lfb/o;->d()Leb/c0;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method
