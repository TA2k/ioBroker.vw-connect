.class public abstract Lkp/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lki/j;Ll2/o;I)V
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v6, p2

    .line 4
    .line 5
    const-string v0, "params"

    .line 6
    .line 7
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v7, p1

    .line 11
    .line 12
    check-cast v7, Ll2/t;

    .line 13
    .line 14
    const v0, 0x228c2e05

    .line 15
    .line 16
    .line 17
    invoke-virtual {v7, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v7, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/4 v2, 0x2

    .line 25
    const/4 v3, 0x4

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    move v0, v3

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    move v0, v2

    .line 31
    :goto_0
    or-int/2addr v0, v6

    .line 32
    and-int/lit8 v4, v0, 0x3

    .line 33
    .line 34
    const/4 v5, 0x0

    .line 35
    const/4 v8, 0x1

    .line 36
    if-eq v4, v2, :cond_1

    .line 37
    .line 38
    move v2, v8

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    move v2, v5

    .line 41
    :goto_1
    and-int/lit8 v4, v0, 0x1

    .line 42
    .line 43
    invoke-virtual {v7, v4, v2}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-eqz v2, :cond_9

    .line 48
    .line 49
    const-string v2, "ChargingStatisticsFlowScreen"

    .line 50
    .line 51
    invoke-static {v2, v7}, Lzb/b;->C(Ljava/lang/String;Ll2/o;)Lzb/v0;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    new-array v4, v5, [Ljava/lang/Object;

    .line 56
    .line 57
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v9

    .line 61
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 62
    .line 63
    if-ne v9, v10, :cond_2

    .line 64
    .line 65
    new-instance v9, Lqf0/d;

    .line 66
    .line 67
    const/4 v11, 0x7

    .line 68
    invoke-direct {v9, v11}, Lqf0/d;-><init>(I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v7, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    :cond_2
    check-cast v9, Lay0/a;

    .line 75
    .line 76
    const/16 v11, 0x30

    .line 77
    .line 78
    invoke-static {v4, v9, v7, v11}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    check-cast v4, Ll2/b1;

    .line 83
    .line 84
    new-instance v9, Lzb/s0;

    .line 85
    .line 86
    const/4 v11, 0x2

    .line 87
    invoke-direct {v9, v2, v11}, Lzb/s0;-><init>(Lzb/v0;I)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v7, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v11

    .line 94
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v12

    .line 98
    if-nez v11, :cond_3

    .line 99
    .line 100
    if-ne v12, v10, :cond_4

    .line 101
    .line 102
    :cond_3
    new-instance v12, Lqf/c;

    .line 103
    .line 104
    const/4 v11, 0x3

    .line 105
    invoke-direct {v12, v4, v11}, Lqf/c;-><init>(Ll2/b1;I)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v7, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    :cond_4
    check-cast v12, Lay0/n;

    .line 112
    .line 113
    invoke-virtual {v2, v12}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 114
    .line 115
    .line 116
    move-result-object v11

    .line 117
    invoke-virtual {v2}, Lzb/v0;->b()Lz9/y;

    .line 118
    .line 119
    .line 120
    move-result-object v12

    .line 121
    and-int/lit8 v0, v0, 0xe

    .line 122
    .line 123
    if-eq v0, v3, :cond_5

    .line 124
    .line 125
    invoke-virtual {v7, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    if-eqz v0, :cond_6

    .line 130
    .line 131
    :cond_5
    move v5, v8

    .line 132
    :cond_6
    invoke-virtual {v7, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    or-int/2addr v0, v5

    .line 137
    invoke-virtual {v7, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    or-int/2addr v0, v2

    .line 142
    invoke-virtual {v7, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    move-result v2

    .line 146
    or-int/2addr v0, v2

    .line 147
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v2

    .line 151
    if-nez v0, :cond_7

    .line 152
    .line 153
    if-ne v2, v10, :cond_8

    .line 154
    .line 155
    :cond_7
    new-instance v0, Lbg/a;

    .line 156
    .line 157
    const/16 v5, 0x10

    .line 158
    .line 159
    move-object v3, v4

    .line 160
    move-object v4, v9

    .line 161
    move-object v2, v11

    .line 162
    invoke-direct/range {v0 .. v5}, Lbg/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v7, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    move-object v2, v0

    .line 169
    :cond_8
    move-object v15, v2

    .line 170
    check-cast v15, Lay0/k;

    .line 171
    .line 172
    const/16 v18, 0x0

    .line 173
    .line 174
    const/16 v19, 0x3fc

    .line 175
    .line 176
    const-string v8, "/overview"

    .line 177
    .line 178
    const/4 v9, 0x0

    .line 179
    const/4 v10, 0x0

    .line 180
    const/4 v11, 0x0

    .line 181
    move-object/from16 v16, v7

    .line 182
    .line 183
    move-object v7, v12

    .line 184
    const/4 v12, 0x0

    .line 185
    const/4 v13, 0x0

    .line 186
    const/4 v14, 0x0

    .line 187
    const/16 v17, 0x30

    .line 188
    .line 189
    invoke-static/range {v7 .. v19}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 190
    .line 191
    .line 192
    goto :goto_2

    .line 193
    :cond_9
    move-object/from16 v16, v7

    .line 194
    .line 195
    invoke-virtual/range {v16 .. v16}, Ll2/t;->R()V

    .line 196
    .line 197
    .line 198
    :goto_2
    invoke-virtual/range {v16 .. v16}, Ll2/t;->s()Ll2/u1;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    if-eqz v0, :cond_a

    .line 203
    .line 204
    new-instance v2, Lrd/b;

    .line 205
    .line 206
    invoke-direct {v2, v1, v6}, Lrd/b;-><init>(Lki/j;I)V

    .line 207
    .line 208
    .line 209
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 210
    .line 211
    :cond_a
    return-void
.end method

.method public static final b(Ld30/a;)Ljava/lang/String;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ld30/a;->c:Ljava/lang/String;

    .line 7
    .line 8
    iget-object p0, p0, Ld30/a;->d:Ljava/lang/String;

    .line 9
    .line 10
    filled-new-array {v0, p0}, [Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-static {p0}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const/4 v4, 0x0

    .line 19
    const/16 v5, 0x3e

    .line 20
    .line 21
    const-string v1, " "

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    const/4 v3, 0x0

    .line 25
    invoke-static/range {v0 .. v5}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-lez v0, :cond_0

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_0
    const/4 p0, 0x0

    .line 37
    return-object p0
.end method

.method public static final c(Ld30/a;Lij0/a;Z)Le30/v;
    .locals 11

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "stringResource"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v2, p0, Ld30/a;->a:Ljava/lang/String;

    .line 12
    .line 13
    iget-boolean v0, p0, Ld30/a;->i:Z

    .line 14
    .line 15
    const v1, 0x7f1201aa

    .line 16
    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    const/4 v4, 0x0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-static {p0}, Lkp/y;->b(Ld30/a;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    if-eqz v5, :cond_0

    .line 27
    .line 28
    invoke-static {p0}, Lkp/y;->b(Ld30/a;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    if-nez v0, :cond_1

    .line 34
    .line 35
    move-object v5, v3

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    new-array v5, v4, [Ljava/lang/Object;

    .line 38
    .line 39
    move-object v6, p1

    .line 40
    check-cast v6, Ljj0/f;

    .line 41
    .line 42
    invoke-virtual {v6, v1, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    :goto_0
    if-eqz v0, :cond_2

    .line 47
    .line 48
    iget-object v6, p0, Ld30/a;->e:Ljava/lang/String;

    .line 49
    .line 50
    if-eqz v6, :cond_2

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    if-nez v0, :cond_3

    .line 54
    .line 55
    if-eqz p2, :cond_3

    .line 56
    .line 57
    new-array v0, v4, [Ljava/lang/Object;

    .line 58
    .line 59
    move-object v1, p1

    .line 60
    check-cast v1, Ljj0/f;

    .line 61
    .line 62
    const v6, 0x7f1203d8

    .line 63
    .line 64
    .line 65
    invoke-virtual {v1, v6, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    goto :goto_1

    .line 70
    :cond_3
    if-nez v0, :cond_4

    .line 71
    .line 72
    if-nez p2, :cond_4

    .line 73
    .line 74
    new-array v0, v4, [Ljava/lang/Object;

    .line 75
    .line 76
    move-object v1, p1

    .line 77
    check-cast v1, Ljj0/f;

    .line 78
    .line 79
    const v6, 0x7f1203d7

    .line 80
    .line 81
    .line 82
    invoke-virtual {v1, v6, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    goto :goto_1

    .line 87
    :cond_4
    new-array v0, v4, [Ljava/lang/Object;

    .line 88
    .line 89
    move-object v6, p1

    .line 90
    check-cast v6, Ljj0/f;

    .line 91
    .line 92
    invoke-virtual {v6, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v6

    .line 96
    :goto_1
    iget-object v8, p0, Ld30/a;->b:Ljava/lang/String;

    .line 97
    .line 98
    iget-object v9, p0, Ld30/a;->f:Ljava/lang/String;

    .line 99
    .line 100
    iget-object v10, p0, Ld30/a;->g:Ljava/lang/String;

    .line 101
    .line 102
    iget-boolean v0, p0, Ld30/a;->h:Z

    .line 103
    .line 104
    if-nez v0, :cond_5

    .line 105
    .line 106
    if-nez p2, :cond_5

    .line 107
    .line 108
    const/4 v0, 0x1

    .line 109
    goto :goto_2

    .line 110
    :cond_5
    move v0, v4

    .line 111
    :goto_2
    iget-boolean p0, p0, Ld30/a;->i:Z

    .line 112
    .line 113
    if-nez p0, :cond_7

    .line 114
    .line 115
    if-eqz p2, :cond_7

    .line 116
    .line 117
    new-array p2, v4, [Ljava/lang/Object;

    .line 118
    .line 119
    check-cast p1, Ljj0/f;

    .line 120
    .line 121
    const v1, 0x7f1203d6

    .line 122
    .line 123
    .line 124
    invoke-virtual {p1, v1, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v3

    .line 128
    :cond_6
    :goto_3
    move-object v7, v3

    .line 129
    goto :goto_4

    .line 130
    :cond_7
    if-nez p0, :cond_6

    .line 131
    .line 132
    if-nez p2, :cond_6

    .line 133
    .line 134
    new-array p2, v4, [Ljava/lang/Object;

    .line 135
    .line 136
    check-cast p1, Ljj0/f;

    .line 137
    .line 138
    const v1, 0x7f1203d5

    .line 139
    .line 140
    .line 141
    invoke-virtual {p1, v1, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    goto :goto_3

    .line 146
    :goto_4
    new-instance v1, Le30/v;

    .line 147
    .line 148
    move v4, p0

    .line 149
    move v3, v0

    .line 150
    invoke-direct/range {v1 .. v10}, Le30/v;-><init>(Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    return-object v1
.end method
