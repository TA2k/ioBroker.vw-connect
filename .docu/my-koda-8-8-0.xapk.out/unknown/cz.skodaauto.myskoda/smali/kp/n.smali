.class public abstract Lkp/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ljava/lang/Class;)Landroidx/lifecycle/b1;
    .locals 4

    .line 1
    const-string v0, "Cannot create an instance of "

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    :try_start_0
    invoke-virtual {p0, v1}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 5
    .line 6
    .line 7
    move-result-object v2
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_2

    .line 8
    invoke-virtual {v2}, Ljava/lang/reflect/Constructor;->getModifiers()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    invoke-static {v3}, Ljava/lang/reflect/Modifier;->isPublic(I)Z

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    if-eqz v3, :cond_0

    .line 17
    .line 18
    :try_start_1
    invoke-virtual {v2, v1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    check-cast v1, Landroidx/lifecycle/b1;
    :try_end_1
    .catch Ljava/lang/InstantiationException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/IllegalAccessException; {:try_start_1 .. :try_end_1} :catch_0

    .line 26
    .line 27
    return-object v1

    .line 28
    :catch_0
    move-exception v1

    .line 29
    goto :goto_0

    .line 30
    :catch_1
    move-exception v1

    .line 31
    goto :goto_1

    .line 32
    :goto_0
    new-instance v2, Ljava/lang/RuntimeException;

    .line 33
    .line 34
    new-instance v3, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    invoke-direct {v2, p0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 47
    .line 48
    .line 49
    throw v2

    .line 50
    :goto_1
    new-instance v2, Ljava/lang/RuntimeException;

    .line 51
    .line 52
    new-instance v3, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-direct {v2, p0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 65
    .line 66
    .line 67
    throw v2

    .line 68
    :cond_0
    new-instance v1, Ljava/lang/RuntimeException;

    .line 69
    .line 70
    new-instance v2, Ljava/lang/StringBuilder;

    .line 71
    .line 72
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-direct {v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    throw v1

    .line 86
    :catch_2
    move-exception v1

    .line 87
    new-instance v2, Ljava/lang/RuntimeException;

    .line 88
    .line 89
    new-instance v3, Ljava/lang/StringBuilder;

    .line 90
    .line 91
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-direct {v2, p0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 102
    .line 103
    .line 104
    throw v2
.end method

.method public static final b(IILl2/o;)Le1/n1;
    .locals 3

    .line 1
    const/4 p1, 0x0

    .line 2
    new-array v0, p1, [Ljava/lang/Object;

    .line 3
    .line 4
    and-int/lit8 v1, p0, 0xe

    .line 5
    .line 6
    xor-int/lit8 v1, v1, 0x6

    .line 7
    .line 8
    const/4 v2, 0x4

    .line 9
    if-le v1, v2, :cond_0

    .line 10
    .line 11
    move-object v1, p2

    .line 12
    check-cast v1, Ll2/t;

    .line 13
    .line 14
    invoke-virtual {v1, p1}, Ll2/t;->e(I)Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-nez v1, :cond_1

    .line 19
    .line 20
    :cond_0
    and-int/lit8 p0, p0, 0x6

    .line 21
    .line 22
    if-ne p0, v2, :cond_2

    .line 23
    .line 24
    :cond_1
    const/4 p0, 0x1

    .line 25
    goto :goto_0

    .line 26
    :cond_2
    move p0, p1

    .line 27
    :goto_0
    check-cast p2, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    if-nez p0, :cond_3

    .line 34
    .line 35
    sget-object p0, Ll2/n;->a:Ll2/x0;

    .line 36
    .line 37
    if-ne v1, p0, :cond_4

    .line 38
    .line 39
    :cond_3
    new-instance v1, Le1/h1;

    .line 40
    .line 41
    const/4 p0, 0x0

    .line 42
    invoke-direct {v1, p1, p0}, Le1/h1;-><init>(II)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    :cond_4
    check-cast v1, Lay0/a;

    .line 49
    .line 50
    sget-object p0, Le1/n1;->i:Lu2/l;

    .line 51
    .line 52
    invoke-static {v0, p0, v1, p2, p1}, Lu2/m;->d([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    check-cast p0, Le1/n1;

    .line 57
    .line 58
    return-object p0
.end method

.method public static c(Lx2/s;Le1/n1;ZZZ)Lx2/s;
    .locals 11

    .line 1
    if-eqz p4, :cond_0

    .line 2
    .line 3
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 4
    .line 5
    :goto_0
    move-object v3, v0

    .line 6
    goto :goto_1

    .line 7
    :cond_0
    sget-object v0, Lg1/w1;->e:Lg1/w1;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :goto_1
    iget-object v7, p1, Le1/n1;->c:Li1/l;

    .line 11
    .line 12
    const/4 v10, 0x0

    .line 13
    const/4 v6, 0x0

    .line 14
    const/4 v8, 0x1

    .line 15
    const/4 v9, 0x0

    .line 16
    move-object v1, p0

    .line 17
    move-object v2, p1

    .line 18
    move v5, p2

    .line 19
    move v4, p3

    .line 20
    invoke-static/range {v1 .. v10}, Landroidx/compose/foundation/a;->l(Lx2/s;Lg1/q2;Lg1/w1;ZZLg1/j1;Li1/l;ZLe1/j;Lp1/h;)Lx2/s;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    new-instance p1, Landroidx/compose/foundation/ScrollingLayoutElement;

    .line 25
    .line 26
    invoke-direct {p1, v2, v5, p4}, Landroidx/compose/foundation/ScrollingLayoutElement;-><init>(Le1/n1;ZZ)V

    .line 27
    .line 28
    .line 29
    invoke-interface {p0, p1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method

.method public static d(Lx2/s;Le1/n1;I)Lx2/s;
    .locals 3

    .line 1
    and-int/lit8 v0, p2, 0x2

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move v0, v2

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v0, v1

    .line 10
    :goto_0
    and-int/lit8 p2, p2, 0x8

    .line 11
    .line 12
    if-eqz p2, :cond_1

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_1
    move v1, v2

    .line 16
    :goto_1
    invoke-static {p0, p1, v1, v0, v2}, Lkp/n;->c(Lx2/s;Le1/n1;ZZZ)Lx2/s;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
