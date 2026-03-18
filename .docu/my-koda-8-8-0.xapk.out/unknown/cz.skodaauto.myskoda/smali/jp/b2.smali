.class public abstract Ljp/b2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lx2/s;F)Lx2/s;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    int-to-float v1, v0

    .line 3
    invoke-static {p1, v1}, Ljava/lang/Float;->compare(FF)I

    .line 4
    .line 5
    .line 6
    move-result v2

    .line 7
    if-lez v2, :cond_0

    .line 8
    .line 9
    invoke-static {p1, v1}, Ljava/lang/Float;->compare(FF)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    :cond_0
    new-instance v1, Lb3/a;

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v1, p1, p1, v0, v2}, Lb3/a;-><init>(FFIZ)V

    .line 17
    .line 18
    .line 19
    invoke-static {p0, v1}, Landroidx/compose/ui/graphics/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static final b(Lyy0/i;Ljava/lang/Object;Landroidx/lifecycle/r;Landroidx/lifecycle/q;Lpx0/g;Ll2/o;I)Ll2/b1;
    .locals 10

    .line 1
    move/from16 v0, p6

    .line 2
    .line 3
    filled-new-array {p0, p2, p3, p4}, [Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v7

    .line 7
    move-object v8, p5

    .line 8
    check-cast v8, Ll2/t;

    .line 9
    .line 10
    invoke-virtual {v8, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v5

    .line 14
    and-int/lit16 v6, v0, 0x1c00

    .line 15
    .line 16
    xor-int/lit16 v6, v6, 0xc00

    .line 17
    .line 18
    const/16 v9, 0x800

    .line 19
    .line 20
    if-le v6, v9, :cond_0

    .line 21
    .line 22
    invoke-virtual {p3}, Ljava/lang/Enum;->ordinal()I

    .line 23
    .line 24
    .line 25
    move-result v6

    .line 26
    invoke-virtual {v8, v6}, Ll2/t;->e(I)Z

    .line 27
    .line 28
    .line 29
    move-result v6

    .line 30
    if-nez v6, :cond_1

    .line 31
    .line 32
    :cond_0
    and-int/lit16 v0, v0, 0xc00

    .line 33
    .line 34
    if-ne v0, v9, :cond_2

    .line 35
    .line 36
    :cond_1
    const/4 v0, 0x1

    .line 37
    goto :goto_0

    .line 38
    :cond_2
    const/4 v0, 0x0

    .line 39
    :goto_0
    or-int/2addr v0, v5

    .line 40
    invoke-virtual {v8, p4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    or-int/2addr v0, v5

    .line 45
    invoke-virtual {v8, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    or-int/2addr v0, v5

    .line 50
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 55
    .line 56
    if-nez v0, :cond_3

    .line 57
    .line 58
    if-ne v5, v9, :cond_4

    .line 59
    .line 60
    :cond_3
    new-instance v0, Laa/i0;

    .line 61
    .line 62
    const/4 v5, 0x0

    .line 63
    const/16 v6, 0x11

    .line 64
    .line 65
    move-object v4, p0

    .line 66
    move-object v1, p2

    .line 67
    move-object v2, p3

    .line 68
    move-object v3, p4

    .line 69
    invoke-direct/range {v0 .. v6}, Laa/i0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    move-object v5, v0

    .line 76
    :cond_4
    check-cast v5, Lay0/n;

    .line 77
    .line 78
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    if-ne v0, v9, :cond_5

    .line 83
    .line 84
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    :cond_5
    check-cast v0, Ll2/b1;

    .line 92
    .line 93
    const/4 v1, 0x4

    .line 94
    invoke-static {v7, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    invoke-virtual {v8, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v3

    .line 106
    if-nez v2, :cond_6

    .line 107
    .line 108
    if-ne v3, v9, :cond_7

    .line 109
    .line 110
    :cond_6
    new-instance v3, Ll2/p2;

    .line 111
    .line 112
    const/4 v2, 0x2

    .line 113
    const/4 v4, 0x0

    .line 114
    invoke-direct {v3, v5, v0, v4, v2}, Ll2/p2;-><init>(Lay0/n;Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v8, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    :cond_7
    check-cast v3, Lay0/n;

    .line 121
    .line 122
    invoke-static {v1, v3, v8}, Ll2/l0;->f([Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 123
    .line 124
    .line 125
    return-object v0
.end method

.method public static final c(Lyy0/a2;Ll2/o;)Ll2/b1;
    .locals 8

    .line 1
    sget-object v0, Ln7/c;->a:Ll2/s1;

    .line 2
    .line 3
    move-object v1, p1

    .line 4
    check-cast v1, Ll2/t;

    .line 5
    .line 6
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Landroidx/lifecycle/x;

    .line 11
    .line 12
    sget-object v4, Landroidx/lifecycle/q;->g:Landroidx/lifecycle/q;

    .line 13
    .line 14
    invoke-interface {p0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-interface {v0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    const/4 v7, 0x0

    .line 23
    sget-object v5, Lpx0/h;->d:Lpx0/h;

    .line 24
    .line 25
    move-object v1, p0

    .line 26
    move-object v6, p1

    .line 27
    invoke-static/range {v1 .. v7}, Ljp/b2;->b(Lyy0/i;Ljava/lang/Object;Landroidx/lifecycle/r;Landroidx/lifecycle/q;Lpx0/g;Ll2/o;I)Ll2/b1;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0
.end method
