.class public abstract Lkp/u8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lt2/b;Ll2/o;I)V
    .locals 7

    .line 1
    move-object v5, p1

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p1, 0x6ca4f966

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p1, p2, 0x3

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    const/4 v6, 0x0

    .line 14
    if-eq p1, v0, :cond_0

    .line 15
    .line 16
    const/4 p1, 0x1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move p1, v6

    .line 19
    :goto_0
    and-int/lit8 v0, p2, 0x1

    .line 20
    .line 21
    invoke-virtual {v5, v0, p1}, Ll2/t;->O(IZ)Z

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    if-eqz p1, :cond_6

    .line 26
    .line 27
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 32
    .line 33
    if-ne p1, v0, :cond_1

    .line 34
    .line 35
    new-instance p1, Lg4/a0;

    .line 36
    .line 37
    const/16 v0, 0x11

    .line 38
    .line 39
    invoke-direct {p1, v0}, Lg4/a0;-><init>(I)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v5, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    :cond_1
    check-cast p1, Lay0/k;

    .line 46
    .line 47
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 48
    .line 49
    invoke-virtual {v5, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    check-cast v0, Ljava/lang/Boolean;

    .line 54
    .line 55
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-eqz v0, :cond_2

    .line 60
    .line 61
    const v0, -0x105bcaaa

    .line 62
    .line 63
    .line 64
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v5, v6}, Ll2/t;->q(Z)V

    .line 68
    .line 69
    .line 70
    const/4 v0, 0x0

    .line 71
    goto :goto_1

    .line 72
    :cond_2
    const v0, 0x31054eee

    .line 73
    .line 74
    .line 75
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 76
    .line 77
    .line 78
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 79
    .line 80
    invoke-virtual {v5, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    check-cast v0, Lhi/a;

    .line 85
    .line 86
    invoke-virtual {v5, v6}, Ll2/t;->q(Z)V

    .line 87
    .line 88
    .line 89
    :goto_1
    new-instance v3, Lvh/i;

    .line 90
    .line 91
    const/16 v1, 0x9

    .line 92
    .line 93
    invoke-direct {v3, v1, v0, p1}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    invoke-static {v5}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    if-eqz v1, :cond_5

    .line 101
    .line 102
    instance-of p1, v1, Landroidx/lifecycle/k;

    .line 103
    .line 104
    if-eqz p1, :cond_3

    .line 105
    .line 106
    move-object p1, v1

    .line 107
    check-cast p1, Landroidx/lifecycle/k;

    .line 108
    .line 109
    invoke-interface {p1}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    :goto_2
    move-object v4, p1

    .line 114
    goto :goto_3

    .line 115
    :cond_3
    sget-object p1, Lp7/a;->b:Lp7/a;

    .line 116
    .line 117
    goto :goto_2

    .line 118
    :goto_3
    const-class p1, Lgc/b;

    .line 119
    .line 120
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 121
    .line 122
    invoke-virtual {v0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    const/4 v2, 0x0

    .line 127
    invoke-static/range {v0 .. v5}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    check-cast p1, Lgc/b;

    .line 132
    .line 133
    iget-object p1, p1, Lgc/b;->d:Lyy0/l1;

    .line 134
    .line 135
    invoke-static {p1, v5}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    check-cast p1, Ljava/lang/Boolean;

    .line 144
    .line 145
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 146
    .line 147
    .line 148
    move-result p1

    .line 149
    const/4 v0, 0x6

    .line 150
    if-eqz p1, :cond_4

    .line 151
    .line 152
    const p1, 0x123de35a

    .line 153
    .line 154
    .line 155
    invoke-virtual {v5, p1}, Ll2/t;->Y(I)V

    .line 156
    .line 157
    .line 158
    invoke-static {v0, v6, v5, v6}, Lfc/a;->a(IILl2/o;Z)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v5, v6}, Ll2/t;->q(Z)V

    .line 162
    .line 163
    .line 164
    goto :goto_4

    .line 165
    :cond_4
    const p1, 0x123ef563

    .line 166
    .line 167
    .line 168
    invoke-virtual {v5, p1}, Ll2/t;->Y(I)V

    .line 169
    .line 170
    .line 171
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    invoke-virtual {p0, v5, p1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    invoke-virtual {v5, v6}, Ll2/t;->q(Z)V

    .line 179
    .line 180
    .line 181
    goto :goto_4

    .line 182
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 183
    .line 184
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 185
    .line 186
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    throw p0

    .line 190
    :cond_6
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 191
    .line 192
    .line 193
    :goto_4
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 194
    .line 195
    .line 196
    move-result-object p1

    .line 197
    if-eqz p1, :cond_7

    .line 198
    .line 199
    new-instance v0, Ld71/d;

    .line 200
    .line 201
    const/4 v1, 0x5

    .line 202
    invoke-direct {v0, p0, p2, v1}, Ld71/d;-><init>(Lt2/b;II)V

    .line 203
    .line 204
    .line 205
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 206
    .line 207
    :cond_7
    return-void
.end method

.method public static final b([Ljava/lang/Enum;)Lsx0/b;
    .locals 1

    .line 1
    const-string v0, "entries"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lsx0/b;

    .line 7
    .line 8
    invoke-direct {v0, p0}, Lsx0/b;-><init>([Ljava/lang/Enum;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method
