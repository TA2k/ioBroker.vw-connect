.class public abstract Lkp/e9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(JJ)Lt4/k;
    .locals 7

    .line 1
    new-instance v0, Lt4/k;

    .line 2
    .line 3
    const/16 v1, 0x20

    .line 4
    .line 5
    shr-long v2, p0, v1

    .line 6
    .line 7
    long-to-int v2, v2

    .line 8
    const-wide v3, 0xffffffffL

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    and-long/2addr p0, v3

    .line 14
    long-to-int p0, p0

    .line 15
    shr-long v5, p2, v1

    .line 16
    .line 17
    long-to-int p1, v5

    .line 18
    add-int/2addr p1, v2

    .line 19
    and-long/2addr p2, v3

    .line 20
    long-to-int p2, p2

    .line 21
    add-int/2addr p2, p0

    .line 22
    invoke-direct {v0, v2, p0, p1, p2}, Lt4/k;-><init>(IIII)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method

.method public static final b(Ld3/c;)Lt4/k;
    .locals 4

    .line 1
    new-instance v0, Lt4/k;

    .line 2
    .line 3
    iget v1, p0, Ld3/c;->a:F

    .line 4
    .line 5
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    iget v2, p0, Ld3/c;->b:F

    .line 10
    .line 11
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    iget v3, p0, Ld3/c;->c:F

    .line 16
    .line 17
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    iget p0, p0, Ld3/c;->d:F

    .line 22
    .line 23
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    invoke-direct {v0, v1, v2, v3, p0}, Lt4/k;-><init>(IIII)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public static final c(Lhp0/e;Ljava/lang/String;Lhp0/f;)Lgp0/b;
    .locals 14

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "vehicleId"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lgp0/b;

    .line 12
    .line 13
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v5

    .line 17
    iget-object v0, p0, Lhp0/e;->c:Lhp0/d;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v6

    .line 23
    iget-object p0, p0, Lhp0/e;->b:Lhp0/c;

    .line 24
    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    new-instance v7, Lgp0/e;

    .line 28
    .line 29
    iget-object v8, p0, Lhp0/c;->a:Ljava/lang/Integer;

    .line 30
    .line 31
    iget-object v9, p0, Lhp0/c;->b:Ljava/lang/Integer;

    .line 32
    .line 33
    iget-object v10, p0, Lhp0/c;->c:Ljava/lang/Integer;

    .line 34
    .line 35
    iget-object v11, p0, Lhp0/c;->d:Ljava/lang/Integer;

    .line 36
    .line 37
    iget-boolean v12, p0, Lhp0/c;->f:Z

    .line 38
    .line 39
    iget-object p0, p0, Lhp0/c;->e:Lhp0/b;

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v13

    .line 45
    invoke-direct/range {v7 .. v13}, Lgp0/e;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;ZLjava/lang/String;)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    const/4 v7, 0x0

    .line 50
    :goto_0
    const-wide/16 v2, 0x0

    .line 51
    .line 52
    move-object v4, p1

    .line 53
    invoke-direct/range {v1 .. v7}, Lgp0/b;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lgp0/e;)V

    .line 54
    .line 55
    .line 56
    return-object v1
.end method
