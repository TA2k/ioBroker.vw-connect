.class public abstract Llp/bg;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 14

    .line 1
    move-object v3, p0

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p0, 0x7d2f42b4

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    const/4 v6, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v0, p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v0, v6

    .line 17
    :goto_0
    and-int/lit8 v1, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v3, v1, v0}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_7

    .line 24
    .line 25
    const v0, -0x6040e0aa

    .line 26
    .line 27
    .line 28
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v3}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    if-eqz v0, :cond_6

    .line 36
    .line 37
    invoke-static {v0}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 38
    .line 39
    .line 40
    move-result-object v10

    .line 41
    invoke-static {v3}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 42
    .line 43
    .line 44
    move-result-object v12

    .line 45
    const-class v1, Lx60/b;

    .line 46
    .line 47
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 48
    .line 49
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 50
    .line 51
    .line 52
    move-result-object v7

    .line 53
    invoke-interface {v0}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 54
    .line 55
    .line 56
    move-result-object v8

    .line 57
    const/4 v9, 0x0

    .line 58
    const/4 v11, 0x0

    .line 59
    const/4 v13, 0x0

    .line 60
    invoke-static/range {v7 .. v13}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 65
    .line 66
    .line 67
    check-cast v0, Lx60/b;

    .line 68
    .line 69
    iget-object v1, v0, Lql0/j;->g:Lyy0/l1;

    .line 70
    .line 71
    const/4 v2, 0x0

    .line 72
    invoke-static {v1, v2, v3, p0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    check-cast p0, Lx60/a;

    .line 81
    .line 82
    iget-object p0, p0, Lx60/a;->a:Lql0/g;

    .line 83
    .line 84
    if-nez p0, :cond_1

    .line 85
    .line 86
    const p0, -0x213a0ffa

    .line 87
    .line 88
    .line 89
    invoke-virtual {v3, p0}, Ll2/t;->Y(I)V

    .line 90
    .line 91
    .line 92
    :goto_1
    invoke-virtual {v3, v6}, Ll2/t;->q(Z)V

    .line 93
    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_1
    const v1, -0x213a0ff9

    .line 97
    .line 98
    .line 99
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v3, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 111
    .line 112
    if-nez v1, :cond_2

    .line 113
    .line 114
    if-ne v2, v4, :cond_3

    .line 115
    .line 116
    :cond_2
    new-instance v2, Ly60/a;

    .line 117
    .line 118
    const/4 v1, 0x0

    .line 119
    invoke-direct {v2, v0, v1}, Ly60/a;-><init>(Lx60/b;I)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v3, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    :cond_3
    move-object v1, v2

    .line 126
    check-cast v1, Lay0/k;

    .line 127
    .line 128
    invoke-virtual {v3, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v2

    .line 132
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v5

    .line 136
    if-nez v2, :cond_4

    .line 137
    .line 138
    if-ne v5, v4, :cond_5

    .line 139
    .line 140
    :cond_4
    new-instance v5, Ly60/a;

    .line 141
    .line 142
    const/4 v2, 0x1

    .line 143
    invoke-direct {v5, v0, v2}, Ly60/a;-><init>(Lx60/b;I)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {v3, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    :cond_5
    move-object v2, v5

    .line 150
    check-cast v2, Lay0/k;

    .line 151
    .line 152
    const/4 v4, 0x0

    .line 153
    const/4 v5, 0x0

    .line 154
    move-object v0, p0

    .line 155
    invoke-static/range {v0 .. v5}, Lyg0/a;->a(Lql0/g;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 156
    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 160
    .line 161
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 162
    .line 163
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    throw p0

    .line 167
    :cond_7
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 168
    .line 169
    .line 170
    :goto_2
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    if-eqz p0, :cond_8

    .line 175
    .line 176
    new-instance v0, Lxk0/z;

    .line 177
    .line 178
    const/16 v1, 0x9

    .line 179
    .line 180
    invoke-direct {v0, p1, v1}, Lxk0/z;-><init>(II)V

    .line 181
    .line 182
    .line 183
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 184
    .line 185
    :cond_8
    return-void
.end method

.method public static b(Ljava/lang/Object;)I
    .locals 4

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    :goto_0
    int-to-long v0, p0

    .line 10
    const-wide/32 v2, -0x3361d2af

    .line 11
    .line 12
    .line 13
    mul-long/2addr v0, v2

    .line 14
    long-to-int p0, v0

    .line 15
    const/16 v0, 0xf

    .line 16
    .line 17
    invoke-static {p0, v0}, Ljava/lang/Integer;->rotateLeft(II)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    int-to-long v0, p0

    .line 22
    const-wide/32 v2, 0x1b873593

    .line 23
    .line 24
    .line 25
    mul-long/2addr v0, v2

    .line 26
    long-to-int p0, v0

    .line 27
    return p0
.end method
