.class public abstract Llp/ma;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(ZLl2/o;I)V
    .locals 4

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x3fa9771d

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    or-int/lit8 v0, p2, 0x6

    .line 10
    .line 11
    and-int/lit8 v0, v0, 0x5b

    .line 12
    .line 13
    const/16 v1, 0x12

    .line 14
    .line 15
    if-ne v0, v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {p1}, Ll2/t;->A()Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 25
    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_1
    :goto_0
    sget-object p0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 29
    .line 30
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    check-cast v0, Landroid/content/Context;

    .line 35
    .line 36
    invoke-static {v0}, Luw/c;->b(Landroid/content/Context;)Landroid/content/Context;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    sget-object v1, Luw/e;->a:Ll2/u2;

    .line 41
    .line 42
    invoke-virtual {v1, v0}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    filled-new-array {v1}, [Ll2/t1;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    const/4 v2, 0x1

    .line 51
    new-array v3, v2, [Ll2/t1;

    .line 52
    .line 53
    invoke-virtual {p0, v0}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    const/4 v0, 0x0

    .line 58
    aput-object p0, v3, v0

    .line 59
    .line 60
    invoke-static {v1, v3}, Lmx0/n;->O([Ljava/lang/Object;[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, [Ll2/t1;

    .line 65
    .line 66
    array-length v0, p0

    .line 67
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    check-cast p0, [Ll2/t1;

    .line 72
    .line 73
    const/16 v0, 0x38

    .line 74
    .line 75
    sget-object v1, Lny/j;->a:Lt2/b;

    .line 76
    .line 77
    invoke-static {p0, v1, p1, v0}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 78
    .line 79
    .line 80
    move p0, v2

    .line 81
    :goto_1
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    if-nez p1, :cond_2

    .line 86
    .line 87
    return-void

    .line 88
    :cond_2
    new-instance v0, Luw/a;

    .line 89
    .line 90
    invoke-direct {v0, p2, p0}, Luw/a;-><init>(IZ)V

    .line 91
    .line 92
    .line 93
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 94
    .line 95
    return-void
.end method

.method public static final b(Landroid/content/Context;)Lil/j;
    .locals 13

    .line 1
    new-instance v0, Lil/g;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lil/g;-><init>(Landroid/content/Context;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lil/j;

    .line 7
    .line 8
    iget-object p0, v0, Lil/g;->e:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, p0

    .line 11
    check-cast v2, Landroid/content/Context;

    .line 12
    .line 13
    iget-object p0, v0, Lil/g;->f:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, p0

    .line 16
    check-cast v3, Ltl/b;

    .line 17
    .line 18
    new-instance p0, Lil/e;

    .line 19
    .line 20
    const/4 v4, 0x0

    .line 21
    invoke-direct {p0, v0, v4}, Lil/e;-><init>(Lil/g;I)V

    .line 22
    .line 23
    .line 24
    invoke-static {p0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    new-instance p0, Lil/e;

    .line 29
    .line 30
    const/4 v5, 0x1

    .line 31
    invoke-direct {p0, v0, v5}, Lil/e;-><init>(Lil/g;I)V

    .line 32
    .line 33
    .line 34
    invoke-static {p0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    sget-object p0, Lil/f;->f:Lil/f;

    .line 39
    .line 40
    invoke-static {p0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 41
    .line 42
    .line 43
    move-result-object v6

    .line 44
    new-instance v7, Lil/c;

    .line 45
    .line 46
    sget-object v8, Lmx0/s;->d:Lmx0/s;

    .line 47
    .line 48
    move-object v9, v8

    .line 49
    move-object v10, v8

    .line 50
    move-object v11, v8

    .line 51
    move-object v12, v8

    .line 52
    invoke-direct/range {v7 .. v12}, Lil/c;-><init>(Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;Ljava/util/List;)V

    .line 53
    .line 54
    .line 55
    iget-object p0, v0, Lil/g;->g:Ljava/lang/Object;

    .line 56
    .line 57
    move-object v8, p0

    .line 58
    check-cast v8, Lxl/d;

    .line 59
    .line 60
    invoke-direct/range {v1 .. v8}, Lil/j;-><init>(Landroid/content/Context;Ltl/b;Llx0/q;Llx0/q;Llx0/q;Lil/c;Lxl/d;)V

    .line 61
    .line 62
    .line 63
    return-object v1
.end method
