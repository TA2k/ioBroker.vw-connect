.class public abstract Lkp/p9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 11

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, -0x656bdc29

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v1

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_4

    .line 23
    .line 24
    const v2, -0x6040e0aa

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v2}, Ll2/t;->Y(I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    invoke-static {p0}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 41
    .line 42
    .line 43
    move-result-object v8

    .line 44
    const-class v3, Ls70/c;

    .line 45
    .line 46
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 47
    .line 48
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    invoke-static/range {v3 .. v9}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 64
    .line 65
    .line 66
    check-cast v2, Lql0/j;

    .line 67
    .line 68
    invoke-static {v2, p0, v1, v0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 69
    .line 70
    .line 71
    move-object v5, v2

    .line 72
    check-cast v5, Ls70/c;

    .line 73
    .line 74
    iget-object v2, v5, Lql0/j;->g:Lyy0/l1;

    .line 75
    .line 76
    const/4 v3, 0x0

    .line 77
    invoke-static {v2, v3, p0, v0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    check-cast v0, Ls70/b;

    .line 86
    .line 87
    iget-object v0, v0, Ls70/b;->a:Lql0/g;

    .line 88
    .line 89
    invoke-virtual {p0, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    if-nez v2, :cond_1

    .line 98
    .line 99
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 100
    .line 101
    if-ne v3, v2, :cond_2

    .line 102
    .line 103
    :cond_1
    new-instance v3, Ls60/x;

    .line 104
    .line 105
    const/4 v9, 0x0

    .line 106
    const/16 v10, 0x1d

    .line 107
    .line 108
    const/4 v4, 0x0

    .line 109
    const-class v6, Ls70/c;

    .line 110
    .line 111
    const-string v7, "onContinue"

    .line 112
    .line 113
    const-string v8, "onContinue()V"

    .line 114
    .line 115
    invoke-direct/range {v3 .. v10}, Ls60/x;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {p0, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :cond_2
    check-cast v3, Lhy0/g;

    .line 122
    .line 123
    check-cast v3, Lay0/a;

    .line 124
    .line 125
    invoke-static {v0, v3, p0, v1}, Lkp/p9;->b(Lql0/g;Lay0/a;Ll2/o;I)V

    .line 126
    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 130
    .line 131
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 132
    .line 133
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    throw p0

    .line 137
    :cond_4
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 138
    .line 139
    .line 140
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    if-eqz p0, :cond_5

    .line 145
    .line 146
    new-instance v0, Lt10/b;

    .line 147
    .line 148
    const/16 v1, 0x15

    .line 149
    .line 150
    invoke-direct {v0, p1, v1}, Lt10/b;-><init>(II)V

    .line 151
    .line 152
    .line 153
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 154
    .line 155
    :cond_5
    return-void
.end method

.method public static final b(Lql0/g;Lay0/a;Ll2/o;I)V
    .locals 7

    .line 1
    move-object v3, p2

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p2, -0x10da1e55

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v3, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    const/4 p2, 0x4

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p2, 0x2

    .line 19
    :goto_0
    or-int/2addr p2, p3

    .line 20
    invoke-virtual {v3, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/16 v1, 0x20

    .line 25
    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    move v0, v1

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    const/16 v0, 0x10

    .line 31
    .line 32
    :goto_1
    or-int/2addr p2, v0

    .line 33
    and-int/lit8 v0, p2, 0x13

    .line 34
    .line 35
    const/16 v2, 0x12

    .line 36
    .line 37
    const/4 v4, 0x1

    .line 38
    const/4 v6, 0x0

    .line 39
    if-eq v0, v2, :cond_2

    .line 40
    .line 41
    move v0, v4

    .line 42
    goto :goto_2

    .line 43
    :cond_2
    move v0, v6

    .line 44
    :goto_2
    and-int/lit8 v2, p2, 0x1

    .line 45
    .line 46
    invoke-virtual {v3, v2, v0}, Ll2/t;->O(IZ)Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-eqz v0, :cond_7

    .line 51
    .line 52
    if-nez p0, :cond_3

    .line 53
    .line 54
    const p2, -0x16ae0c46

    .line 55
    .line 56
    .line 57
    invoke-virtual {v3, p2}, Ll2/t;->Y(I)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 61
    .line 62
    .line 63
    move-object v0, p0

    .line 64
    goto :goto_4

    .line 65
    :cond_3
    const v0, -0x16ae0c45

    .line 66
    .line 67
    .line 68
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 69
    .line 70
    .line 71
    and-int/lit8 p2, p2, 0x70

    .line 72
    .line 73
    if-ne p2, v1, :cond_4

    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_4
    move v4, v6

    .line 77
    :goto_3
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    if-nez v4, :cond_5

    .line 82
    .line 83
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 84
    .line 85
    if-ne p2, v0, :cond_6

    .line 86
    .line 87
    :cond_5
    new-instance p2, Lr40/d;

    .line 88
    .line 89
    const/16 v0, 0xe

    .line 90
    .line 91
    invoke-direct {p2, p1, v0}, Lr40/d;-><init>(Lay0/a;I)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v3, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    :cond_6
    move-object v1, p2

    .line 98
    check-cast v1, Lay0/k;

    .line 99
    .line 100
    const/4 v4, 0x0

    .line 101
    const/4 v5, 0x4

    .line 102
    const/4 v2, 0x0

    .line 103
    move-object v0, p0

    .line 104
    invoke-static/range {v0 .. v5}, Lyg0/a;->a(Lql0/g;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 108
    .line 109
    .line 110
    goto :goto_4

    .line 111
    :cond_7
    move-object v0, p0

    .line 112
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 113
    .line 114
    .line 115
    :goto_4
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    if-eqz p0, :cond_8

    .line 120
    .line 121
    new-instance p2, Lo50/b;

    .line 122
    .line 123
    const/16 v1, 0x17

    .line 124
    .line 125
    invoke-direct {p2, v0, p1, p3, v1}, Lo50/b;-><init>(Ljava/lang/Object;Lay0/a;II)V

    .line 126
    .line 127
    .line 128
    iput-object p2, p0, Ll2/u1;->d:Lay0/n;

    .line 129
    .line 130
    :cond_8
    return-void
.end method

.method public static final c(Lcm0/b;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    if-eqz p0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p0, v0, :cond_2

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-eq p0, v0, :cond_1

    .line 17
    .line 18
    const/4 v0, 0x3

    .line 19
    if-eq p0, v0, :cond_1

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    if-ne p0, v0, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, La8/r0;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    :goto_0
    const-string p0, "vehicle-activation-service-sandbox.vas.cariad.digital"

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_2
    const-string p0, "vehicle-activation-service-prod.vas.cariad.digital"

    .line 35
    .line 36
    return-object p0
.end method
