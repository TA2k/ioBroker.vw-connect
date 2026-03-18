.class public abstract Llp/v9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lay0/k;Lv31/c;Lay0/k;Ll2/o;I)V
    .locals 7

    .line 1
    const-string v0, "setAppBarTitle"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "viewState"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "onFeatureStep"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    check-cast p3, Ll2/t;

    .line 17
    .line 18
    const v0, -0x3f84882f

    .line 19
    .line 20
    .line 21
    invoke-virtual {p3, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p3, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    const/4 v1, 0x4

    .line 29
    if-eqz v0, :cond_0

    .line 30
    .line 31
    move v0, v1

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v0, 0x2

    .line 34
    :goto_0
    or-int/2addr v0, p4

    .line 35
    invoke-virtual {p3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-eqz v2, :cond_1

    .line 40
    .line 41
    const/16 v2, 0x20

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    const/16 v2, 0x10

    .line 45
    .line 46
    :goto_1
    or-int/2addr v0, v2

    .line 47
    invoke-virtual {p3, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    const/16 v3, 0x100

    .line 52
    .line 53
    if-eqz v2, :cond_2

    .line 54
    .line 55
    move v2, v3

    .line 56
    goto :goto_2

    .line 57
    :cond_2
    const/16 v2, 0x80

    .line 58
    .line 59
    :goto_2
    or-int/2addr v0, v2

    .line 60
    and-int/lit16 v2, v0, 0x93

    .line 61
    .line 62
    const/16 v4, 0x92

    .line 63
    .line 64
    const/4 v5, 0x1

    .line 65
    const/4 v6, 0x0

    .line 66
    if-eq v2, v4, :cond_3

    .line 67
    .line 68
    move v2, v5

    .line 69
    goto :goto_3

    .line 70
    :cond_3
    move v2, v6

    .line 71
    :goto_3
    and-int/lit8 v4, v0, 0x1

    .line 72
    .line 73
    invoke-virtual {p3, v4, v2}, Ll2/t;->O(IZ)Z

    .line 74
    .line 75
    .line 76
    move-result v2

    .line 77
    if-eqz v2, :cond_9

    .line 78
    .line 79
    and-int/lit8 v2, v0, 0xe

    .line 80
    .line 81
    if-ne v2, v1, :cond_4

    .line 82
    .line 83
    move v1, v5

    .line 84
    goto :goto_4

    .line 85
    :cond_4
    move v1, v6

    .line 86
    :goto_4
    and-int/lit16 v0, v0, 0x380

    .line 87
    .line 88
    if-ne v0, v3, :cond_5

    .line 89
    .line 90
    goto :goto_5

    .line 91
    :cond_5
    move v5, v6

    .line 92
    :goto_5
    or-int v0, v1, v5

    .line 93
    .line 94
    invoke-virtual {p3}, Ll2/t;->L()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    if-nez v0, :cond_6

    .line 99
    .line 100
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 101
    .line 102
    if-ne v1, v0, :cond_7

    .line 103
    .line 104
    :cond_6
    new-instance v1, Le30/p;

    .line 105
    .line 106
    const/4 v0, 0x0

    .line 107
    const/16 v2, 0x1d

    .line 108
    .line 109
    invoke-direct {v1, v2, p0, p2, v0}, Le30/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 110
    .line 111
    .line 112
    invoke-virtual {p3, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    :cond_7
    check-cast v1, Lay0/n;

    .line 116
    .line 117
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 118
    .line 119
    invoke-static {v1, v0, p3}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 120
    .line 121
    .line 122
    iget-boolean v0, p1, Lv31/c;->a:Z

    .line 123
    .line 124
    if-eqz v0, :cond_8

    .line 125
    .line 126
    const v0, -0x708310dc

    .line 127
    .line 128
    .line 129
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 130
    .line 131
    .line 132
    invoke-static {p3, v6}, Ljp/bd;->a(Ll2/o;I)V

    .line 133
    .line 134
    .line 135
    :goto_6
    invoke-virtual {p3, v6}, Ll2/t;->q(Z)V

    .line 136
    .line 137
    .line 138
    goto :goto_7

    .line 139
    :cond_8
    const v0, 0x6002a931

    .line 140
    .line 141
    .line 142
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 143
    .line 144
    .line 145
    goto :goto_6

    .line 146
    :cond_9
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 147
    .line 148
    .line 149
    :goto_7
    invoke-virtual {p3}, Ll2/t;->s()Ll2/u1;

    .line 150
    .line 151
    .line 152
    move-result-object p3

    .line 153
    if-eqz p3, :cond_a

    .line 154
    .line 155
    new-instance v0, Lf20/f;

    .line 156
    .line 157
    const/16 v2, 0x1b

    .line 158
    .line 159
    move-object v3, p0

    .line 160
    move-object v4, p1

    .line 161
    move-object v5, p2

    .line 162
    move v1, p4

    .line 163
    invoke-direct/range {v0 .. v5}, Lf20/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 167
    .line 168
    :cond_a
    return-void
.end method

.method public static final b(Lto0/l;Ljava/lang/String;Ljava/lang/String;)Llp/v1;
    .locals 1

    .line 1
    const-string v0, "$this$toScreenFlow"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lto0/a;->a:Lto0/a;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    sget-object p0, Luo0/c;->a:Luo0/c;

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    sget-object v0, Lto0/b;->a:Lto0/b;

    .line 18
    .line 19
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    sget-object p0, Luo0/d;->a:Luo0/d;

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_1
    sget-object v0, Lto0/c;->a:Lto0/c;

    .line 29
    .line 30
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    new-instance p0, Luo0/e;

    .line 37
    .line 38
    invoke-direct {p0, p1}, Luo0/e;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_2
    sget-object v0, Lto0/g;->a:Lto0/g;

    .line 43
    .line 44
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_3

    .line 49
    .line 50
    new-instance p0, Luo0/g;

    .line 51
    .line 52
    invoke-direct {p0, p1}, Luo0/g;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    return-object p0

    .line 56
    :cond_3
    sget-object v0, Lto0/i;->a:Lto0/i;

    .line 57
    .line 58
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    if-eqz v0, :cond_4

    .line 63
    .line 64
    sget-object p0, Luo0/h;->a:Luo0/h;

    .line 65
    .line 66
    return-object p0

    .line 67
    :cond_4
    sget-object v0, Lto0/j;->a:Lto0/j;

    .line 68
    .line 69
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-eqz v0, :cond_5

    .line 74
    .line 75
    sget-object p0, Luo0/i;->a:Luo0/i;

    .line 76
    .line 77
    return-object p0

    .line 78
    :cond_5
    sget-object v0, Lto0/x;->a:Lto0/x;

    .line 79
    .line 80
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    if-eqz v0, :cond_6

    .line 85
    .line 86
    new-instance p0, Luo0/l;

    .line 87
    .line 88
    invoke-direct {p0, p1}, Luo0/l;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    return-object p0

    .line 92
    :cond_6
    sget-object v0, Lto0/w;->a:Lto0/w;

    .line 93
    .line 94
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    if-eqz v0, :cond_7

    .line 99
    .line 100
    new-instance p0, Luo0/m;

    .line 101
    .line 102
    invoke-direct {p0, p1}, Luo0/m;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    return-object p0

    .line 106
    :cond_7
    sget-object v0, Lto0/y;->a:Lto0/y;

    .line 107
    .line 108
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    if-eqz v0, :cond_8

    .line 113
    .line 114
    sget-object p0, Luo0/n;->a:Luo0/n;

    .line 115
    .line 116
    return-object p0

    .line 117
    :cond_8
    sget-object v0, Lto0/f;->a:Lto0/f;

    .line 118
    .line 119
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    if-eqz v0, :cond_9

    .line 124
    .line 125
    sget-object p0, Luo0/f;->a:Luo0/f;

    .line 126
    .line 127
    return-object p0

    .line 128
    :cond_9
    sget-object v0, Lto0/k;->a:Lto0/k;

    .line 129
    .line 130
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-eqz v0, :cond_b

    .line 135
    .line 136
    if-eqz p1, :cond_a

    .line 137
    .line 138
    new-instance p0, Luo0/j;

    .line 139
    .line 140
    invoke-direct {p0, p1}, Luo0/j;-><init>(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    return-object p0

    .line 144
    :cond_a
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 145
    .line 146
    const-string p1, "PlugAndChargeFlow requires non-null vin"

    .line 147
    .line 148
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    throw p0

    .line 152
    :cond_b
    sget-object p1, Lto0/v;->a:Lto0/v;

    .line 153
    .line 154
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result p0

    .line 158
    if-eqz p0, :cond_e

    .line 159
    .line 160
    if-eqz p2, :cond_c

    .line 161
    .line 162
    new-instance p0, Lto0/h;

    .line 163
    .line 164
    invoke-direct {p0, p2}, Lto0/h;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    goto :goto_0

    .line 168
    :cond_c
    const/4 p0, 0x0

    .line 169
    :goto_0
    if-eqz p0, :cond_d

    .line 170
    .line 171
    iget-object p0, p0, Lto0/h;->a:Ljava/lang/String;

    .line 172
    .line 173
    new-instance p1, Luo0/k;

    .line 174
    .line 175
    invoke-direct {p1, p0}, Luo0/k;-><init>(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    return-object p1

    .line 179
    :cond_d
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 180
    .line 181
    const-string p1, "RemoteAuthorizationFlow requires non-null evseId"

    .line 182
    .line 183
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    throw p0

    .line 187
    :cond_e
    new-instance p0, La8/r0;

    .line 188
    .line 189
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 190
    .line 191
    .line 192
    throw p0
.end method
