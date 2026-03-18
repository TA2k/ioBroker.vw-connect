.class public abstract Llp/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lvv/m0;Luv/q;Ll2/o;I)V
    .locals 7

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v5, p2

    .line 7
    check-cast v5, Ll2/t;

    .line 8
    .line 9
    const p2, 0x4a4fbf5a    # 3403734.5f

    .line 10
    .line 11
    .line 12
    invoke-virtual {v5, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 p2, p3, 0xe

    .line 16
    .line 17
    if-nez p2, :cond_1

    .line 18
    .line 19
    invoke-virtual {v5, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p2

    .line 23
    if-eqz p2, :cond_0

    .line 24
    .line 25
    const/4 p2, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p2, 0x2

    .line 28
    :goto_0
    or-int/2addr p2, p3

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    move p2, p3

    .line 31
    :goto_1
    and-int/lit8 v0, p3, 0x70

    .line 32
    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    invoke-virtual {v5, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    const/16 v0, 0x20

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_2
    const/16 v0, 0x10

    .line 45
    .line 46
    :goto_2
    or-int/2addr p2, v0

    .line 47
    :cond_3
    and-int/lit8 v0, p2, 0x5b

    .line 48
    .line 49
    const/16 v1, 0x12

    .line 50
    .line 51
    if-ne v0, v1, :cond_5

    .line 52
    .line 53
    invoke-virtual {v5}, Ll2/t;->A()Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-nez v0, :cond_4

    .line 58
    .line 59
    goto :goto_3

    .line 60
    :cond_4
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 61
    .line 62
    .line 63
    move-object v1, p0

    .line 64
    goto :goto_4

    .line 65
    :cond_5
    :goto_3
    const v0, 0x5a2658f7

    .line 66
    .line 67
    .line 68
    invoke-virtual {v5, v0}, Ll2/t;->Z(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v5, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 80
    .line 81
    if-nez v0, :cond_6

    .line 82
    .line 83
    if-ne v1, v2, :cond_7

    .line 84
    .line 85
    :cond_6
    new-instance v1, Ltv/m;

    .line 86
    .line 87
    const/4 v0, 0x0

    .line 88
    invoke-direct {v1, p1, v0}, Ltv/m;-><init>(Luv/q;I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v5, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    :cond_7
    move-object v3, v1

    .line 95
    check-cast v3, Lay0/k;

    .line 96
    .line 97
    const/4 v0, 0x0

    .line 98
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 99
    .line 100
    .line 101
    const v1, 0x5a265a2b

    .line 102
    .line 103
    .line 104
    invoke-virtual {v5, v1}, Ll2/t;->Z(I)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v5, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    if-nez v1, :cond_8

    .line 116
    .line 117
    if-ne v4, v2, :cond_9

    .line 118
    .line 119
    :cond_8
    new-instance v4, Ltv/m;

    .line 120
    .line 121
    const/4 v1, 0x2

    .line 122
    invoke-direct {v4, p1, v1}, Ltv/m;-><init>(Luv/q;I)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v5, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 126
    .line 127
    .line 128
    :cond_9
    check-cast v4, Lay0/k;

    .line 129
    .line 130
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 131
    .line 132
    .line 133
    and-int/lit8 v6, p2, 0xe

    .line 134
    .line 135
    const/4 v2, 0x0

    .line 136
    move-object v1, p0

    .line 137
    invoke-static/range {v1 .. v6}, Lvv/z0;->a(Lvv/m0;Lx2/s;Lay0/k;Lay0/k;Ll2/o;I)V

    .line 138
    .line 139
    .line 140
    :goto_4
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    if-eqz p0, :cond_a

    .line 145
    .line 146
    new-instance p2, Ltv/b;

    .line 147
    .line 148
    const/4 v0, 0x4

    .line 149
    invoke-direct {p2, v1, p1, p3, v0}, Ltv/b;-><init>(Lvv/m0;Luv/q;II)V

    .line 150
    .line 151
    .line 152
    iput-object p2, p0, Ll2/u1;->d:Lay0/n;

    .line 153
    .line 154
    :cond_a
    return-void
.end method

.method public static b(Landroid/widget/EdgeEffect;)F
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x1f

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    invoke-static {p0}, Lh6/c;->b(Landroid/widget/EdgeEffect;)F

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0
.end method

.method public static c(Landroid/widget/EdgeEffect;FF)F
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x1f

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    invoke-static {p0, p1, p2}, Lh6/c;->c(Landroid/widget/EdgeEffect;FF)F

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    invoke-static {p0, p1, p2}, Lh6/b;->a(Landroid/widget/EdgeEffect;FF)V

    .line 13
    .line 14
    .line 15
    return p1
.end method
