.class public abstract Ljp/dc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lss0/b;Lij0/a;)Lc00/d0;
    .locals 4

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
    sget-object v0, Lc00/y;->d:Lc00/y;

    .line 12
    .line 13
    sget-object v0, Lc00/c0;->d:Lc00/c0;

    .line 14
    .line 15
    sget-object v0, Lss0/e;->g:Lss0/e;

    .line 16
    .line 17
    invoke-static {p0, v0}, Lkp/u6;->d(Lss0/b;Lss0/e;)Ler0/g;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-static {p0, v0}, Llp/pf;->i(Lss0/b;Lss0/e;)Llf0/i;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    new-instance v0, Lc00/d0;

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    const v3, 0x3f1819

    .line 29
    .line 30
    .line 31
    invoke-direct {v0, v2, v1, p0, v3}, Lc00/d0;-><init>(Lc00/z;Ler0/g;Llf0/i;I)V

    .line 32
    .line 33
    .line 34
    new-instance p0, Lqr0/q;

    .line 35
    .line 36
    const-wide/high16 v1, 0x4036000000000000L    # 22.0

    .line 37
    .line 38
    sget-object v3, Lqr0/r;->d:Lqr0/r;

    .line 39
    .line 40
    invoke-direct {p0, v1, v2, v3}, Lqr0/q;-><init>(DLqr0/r;)V

    .line 41
    .line 42
    .line 43
    invoke-static {v0, p0, p1}, Ljp/dc;->e(Lc00/d0;Lqr0/q;Lij0/a;)Lc00/d0;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0
.end method

.method public static final b(Lij0/a;)Lc00/z;
    .locals 6

    .line 1
    new-instance v0, Lc00/z;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Ljj0/f;

    .line 7
    .line 8
    const v3, 0x7f1201c5

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const v3, 0x7f1201aa

    .line 16
    .line 17
    .line 18
    new-array v1, v1, [Ljava/lang/Object;

    .line 19
    .line 20
    invoke-virtual {p0, v3, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    const/4 v4, 0x0

    .line 25
    const/16 v5, 0x20

    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    move-object v1, v2

    .line 29
    move-object v2, p0

    .line 30
    invoke-direct/range {v0 .. v5}, Lc00/z;-><init>(Ljava/lang/String;Ljava/lang/String;FZI)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method

.method public static final c(Lc00/d0;Lij0/a;Lcn0/a;)Lc00/d0;
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    const-string v2, "<this>"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "stringResource"

    .line 11
    .line 12
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Enum;->ordinal()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const/4 v3, 0x2

    .line 20
    if-eq v2, v3, :cond_0

    .line 21
    .line 22
    const/4 v3, 0x3

    .line 23
    if-eq v2, v3, :cond_0

    .line 24
    .line 25
    iget-object v2, v1, Lc00/d0;->i:Lc00/c0;

    .line 26
    .line 27
    :goto_0
    move-object v10, v2

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    sget-object v2, Lc00/c0;->g:Lc00/c0;

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :goto_1
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Enum;->ordinal()I

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    const/4 v3, 0x1

    .line 39
    if-eq v2, v3, :cond_2

    .line 40
    .line 41
    const/4 v3, 0x4

    .line 42
    if-eq v2, v3, :cond_1

    .line 43
    .line 44
    iget-object v2, v1, Lc00/d0;->j:Lc00/b0;

    .line 45
    .line 46
    :goto_2
    move-object v11, v2

    .line 47
    goto :goto_3

    .line 48
    :cond_1
    sget-object v2, Lc00/b0;->f:Lc00/b0;

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    sget-object v2, Lc00/b0;->e:Lc00/b0;

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_3
    sget-object v2, Lc00/b0;->d:Lc00/b0;

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :goto_3
    const/4 v2, 0x0

    .line 58
    new-array v2, v2, [Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Ljj0/f;

    .line 61
    .line 62
    const v3, 0x7f1200a2

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v12

    .line 69
    const/16 v22, 0x0

    .line 70
    .line 71
    const v23, 0x3fd8ff

    .line 72
    .line 73
    .line 74
    const/4 v2, 0x0

    .line 75
    const/4 v3, 0x0

    .line 76
    const/4 v4, 0x0

    .line 77
    const/4 v5, 0x0

    .line 78
    const/4 v6, 0x0

    .line 79
    const/4 v7, 0x0

    .line 80
    const/4 v8, 0x0

    .line 81
    const/4 v9, 0x0

    .line 82
    const/4 v13, 0x0

    .line 83
    const/4 v14, 0x0

    .line 84
    const/4 v15, 0x0

    .line 85
    const/16 v16, 0x0

    .line 86
    .line 87
    const/16 v17, 0x0

    .line 88
    .line 89
    const/16 v18, 0x0

    .line 90
    .line 91
    const/16 v19, 0x0

    .line 92
    .line 93
    const/16 v20, 0x0

    .line 94
    .line 95
    const/16 v21, 0x0

    .line 96
    .line 97
    invoke-static/range {v1 .. v23}, Lc00/d0;->a(Lc00/d0;Lc00/z;ZZLc00/a0;ZZZLc00/y;Lc00/c0;Lc00/b0;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Llf0/i;ZZZZZZI)Lc00/d0;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    return-object v0
.end method

.method public static final d(Lc00/d0;Lmb0/f;ZLqr0/q;Lij0/a;)Lc00/d0;
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    const-string v3, "<this>"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "airConditioningStatus"

    .line 13
    .line 14
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v3, v0, Lmb0/f;->b:Lmb0/n;

    .line 18
    .line 19
    const-string v4, "stringResource"

    .line 20
    .line 21
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-object v4, v0, Lmb0/f;->a:Lmb0/e;

    .line 25
    .line 26
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    packed-switch v5, :pswitch_data_0

    .line 31
    .line 32
    .line 33
    new-instance v0, La8/r0;

    .line 34
    .line 35
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 36
    .line 37
    .line 38
    throw v0

    .line 39
    :pswitch_0
    sget-object v5, Lc00/y;->d:Lc00/y;

    .line 40
    .line 41
    :goto_0
    move-object v9, v5

    .line 42
    goto :goto_1

    .line 43
    :pswitch_1
    sget-object v5, Lc00/y;->f:Lc00/y;

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_2
    sget-object v5, Lc00/y;->g:Lc00/y;

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :pswitch_3
    sget-object v5, Lc00/y;->e:Lc00/y;

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :goto_1
    invoke-static {v0}, Ljp/vb;->e(Lmb0/f;)Z

    .line 53
    .line 54
    .line 55
    move-result v5

    .line 56
    const/4 v6, 0x0

    .line 57
    if-eqz v5, :cond_0

    .line 58
    .line 59
    new-array v5, v6, [Ljava/lang/Object;

    .line 60
    .line 61
    move-object v7, v2

    .line 62
    check-cast v7, Ljj0/f;

    .line 63
    .line 64
    const v8, 0x7f120074

    .line 65
    .line 66
    .line 67
    invoke-virtual {v7, v8, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    :goto_2
    move-object v12, v5

    .line 72
    goto :goto_3

    .line 73
    :cond_0
    invoke-static {v3}, Ljp/b1;->b(Lmb0/n;)Z

    .line 74
    .line 75
    .line 76
    move-result v5

    .line 77
    invoke-static {v4, v5, v2}, Ljp/vb;->c(Lmb0/e;ZLij0/a;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    goto :goto_2

    .line 82
    :goto_3
    invoke-static {v0}, Ljp/vb;->e(Lmb0/f;)Z

    .line 83
    .line 84
    .line 85
    move-result v5

    .line 86
    const/4 v7, 0x0

    .line 87
    if-eqz v5, :cond_1

    .line 88
    .line 89
    new-array v5, v6, [Ljava/lang/Object;

    .line 90
    .line 91
    move-object v8, v2

    .line 92
    check-cast v8, Ljj0/f;

    .line 93
    .line 94
    const v10, 0x7f120071

    .line 95
    .line 96
    .line 97
    invoke-virtual {v8, v10, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v5

    .line 101
    move-object v13, v5

    .line 102
    goto :goto_4

    .line 103
    :cond_1
    move-object v13, v7

    .line 104
    :goto_4
    invoke-static {v3}, Ljp/b1;->b(Lmb0/n;)Z

    .line 105
    .line 106
    .line 107
    move-result v5

    .line 108
    if-eqz v5, :cond_2

    .line 109
    .line 110
    sget-object v5, Lc00/c0;->e:Lc00/c0;

    .line 111
    .line 112
    :goto_5
    move-object v10, v5

    .line 113
    goto :goto_6

    .line 114
    :cond_2
    invoke-static {v3}, Ljp/b1;->a(Lmb0/n;)Z

    .line 115
    .line 116
    .line 117
    move-result v5

    .line 118
    if-eqz v5, :cond_3

    .line 119
    .line 120
    sget-object v5, Lc00/c0;->f:Lc00/c0;

    .line 121
    .line 122
    goto :goto_5

    .line 123
    :cond_3
    sget-object v5, Lc00/c0;->d:Lc00/c0;

    .line 124
    .line 125
    goto :goto_5

    .line 126
    :goto_6
    iget-object v14, v1, Lc00/d0;->a:Lc00/z;

    .line 127
    .line 128
    iget-object v5, v3, Lmb0/n;->a:Lmb0/o;

    .line 129
    .line 130
    sget-object v8, Lmb0/o;->g:Lmb0/o;

    .line 131
    .line 132
    const/4 v11, 0x1

    .line 133
    if-ne v5, v8, :cond_5

    .line 134
    .line 135
    iget-object v5, v3, Lmb0/n;->b:Lmb0/o;

    .line 136
    .line 137
    if-eq v5, v8, :cond_4

    .line 138
    .line 139
    goto :goto_7

    .line 140
    :cond_4
    move/from16 v18, v6

    .line 141
    .line 142
    goto :goto_8

    .line 143
    :cond_5
    :goto_7
    move/from16 v18, v11

    .line 144
    .line 145
    :goto_8
    iget-object v5, v0, Lmb0/f;->p:Lmb0/c;

    .line 146
    .line 147
    iget-boolean v8, v1, Lc00/d0;->v:Z

    .line 148
    .line 149
    invoke-static {v5, v8, v2}, Ljp/ia;->b(Lmb0/c;ZLij0/a;)Lvf0/g;

    .line 150
    .line 151
    .line 152
    move-result-object v19

    .line 153
    const/16 v20, 0xf

    .line 154
    .line 155
    const/4 v15, 0x0

    .line 156
    const/16 v16, 0x0

    .line 157
    .line 158
    const/16 v17, 0x0

    .line 159
    .line 160
    invoke-static/range {v14 .. v20}, Lc00/z;->a(Lc00/z;Ljava/lang/String;Ljava/lang/String;FZLvf0/g;I)Lc00/z;

    .line 161
    .line 162
    .line 163
    move-result-object v5

    .line 164
    invoke-static {v3}, Ljp/b1;->b(Lmb0/n;)Z

    .line 165
    .line 166
    .line 167
    move-result v3

    .line 168
    if-eqz v3, :cond_6

    .line 169
    .line 170
    new-array v3, v6, [Ljava/lang/Object;

    .line 171
    .line 172
    move-object v6, v2

    .line 173
    check-cast v6, Ljj0/f;

    .line 174
    .line 175
    const v7, 0x7f1200a5

    .line 176
    .line 177
    .line 178
    invoke-virtual {v6, v7, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v7

    .line 182
    :cond_6
    move-object v15, v7

    .line 183
    sget-object v3, Ler0/g;->d:Ler0/g;

    .line 184
    .line 185
    sget-object v16, Llf0/i;->j:Llf0/i;

    .line 186
    .line 187
    invoke-static {v4}, Ljp/a1;->c(Lmb0/e;)Z

    .line 188
    .line 189
    .line 190
    move-result v3

    .line 191
    xor-int/lit8 v8, v3, 0x1

    .line 192
    .line 193
    iget-object v0, v0, Lmb0/f;->j:Lmb0/i;

    .line 194
    .line 195
    sget-object v3, Lc00/j0;->a:[I

    .line 196
    .line 197
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 198
    .line 199
    .line 200
    move-result v0

    .line 201
    aget v0, v3, v0

    .line 202
    .line 203
    if-eq v0, v11, :cond_8

    .line 204
    .line 205
    const/4 v3, 0x2

    .line 206
    if-eq v0, v3, :cond_7

    .line 207
    .line 208
    sget-object v0, Lc00/a0;->e:Lc00/a0;

    .line 209
    .line 210
    goto :goto_9

    .line 211
    :cond_7
    sget-object v0, Lc00/a0;->d:Lc00/a0;

    .line 212
    .line 213
    goto :goto_9

    .line 214
    :cond_8
    sget-object v0, Lc00/a0;->e:Lc00/a0;

    .line 215
    .line 216
    :goto_9
    const/16 v22, 0x0

    .line 217
    .line 218
    const v23, 0x3d1214

    .line 219
    .line 220
    .line 221
    const/4 v3, 0x1

    .line 222
    const/4 v4, 0x0

    .line 223
    const/4 v6, 0x0

    .line 224
    const/4 v7, 0x0

    .line 225
    const/4 v11, 0x0

    .line 226
    const/4 v14, 0x0

    .line 227
    const/16 v17, 0x0

    .line 228
    .line 229
    const/16 v19, 0x0

    .line 230
    .line 231
    const/16 v20, 0x0

    .line 232
    .line 233
    const/16 v21, 0x0

    .line 234
    .line 235
    move-object/from16 v18, v5

    .line 236
    .line 237
    move-object v5, v0

    .line 238
    move-object v0, v2

    .line 239
    move-object/from16 v2, v18

    .line 240
    .line 241
    move/from16 v18, p2

    .line 242
    .line 243
    invoke-static/range {v1 .. v23}, Lc00/d0;->a(Lc00/d0;Lc00/z;ZZLc00/a0;ZZZLc00/y;Lc00/c0;Lc00/b0;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Llf0/i;ZZZZZZI)Lc00/d0;

    .line 244
    .line 245
    .line 246
    move-result-object v1

    .line 247
    move-object/from16 v2, p3

    .line 248
    .line 249
    invoke-static {v1, v2, v0}, Ljp/dc;->e(Lc00/d0;Lqr0/q;Lij0/a;)Lc00/d0;

    .line 250
    .line 251
    .line 252
    move-result-object v0

    .line 253
    return-object v0

    .line 254
    nop

    .line 255
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_1
        :pswitch_2
        :pswitch_3
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public static final e(Lc00/d0;Lqr0/q;Lij0/a;)Lc00/d0;
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    const-string v3, "<this>"

    .line 8
    .line 9
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v3, "stringResource"

    .line 13
    .line 14
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    iget-wide v3, v0, Lqr0/q;->a:D

    .line 20
    .line 21
    invoke-static {v0}, Lkp/p6;->e(Lqr0/q;)D

    .line 22
    .line 23
    .line 24
    move-result-wide v5

    .line 25
    cmpg-double v5, v3, v5

    .line 26
    .line 27
    const/4 v6, 0x0

    .line 28
    if-nez v5, :cond_0

    .line 29
    .line 30
    new-array v3, v6, [Ljava/lang/Object;

    .line 31
    .line 32
    move-object v4, v2

    .line 33
    check-cast v4, Ljj0/f;

    .line 34
    .line 35
    const v5, 0x7f1200cf

    .line 36
    .line 37
    .line 38
    invoke-virtual {v4, v5, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    :goto_0
    move-object v9, v3

    .line 43
    goto :goto_1

    .line 44
    :cond_0
    invoke-static {v0}, Lkp/p6;->d(Lqr0/q;)D

    .line 45
    .line 46
    .line 47
    move-result-wide v7

    .line 48
    cmpg-double v3, v3, v7

    .line 49
    .line 50
    if-nez v3, :cond_1

    .line 51
    .line 52
    new-array v3, v6, [Ljava/lang/Object;

    .line 53
    .line 54
    move-object v4, v2

    .line 55
    check-cast v4, Ljj0/f;

    .line 56
    .line 57
    const v5, 0x7f1200ce

    .line 58
    .line 59
    .line 60
    invoke-virtual {v4, v5, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    goto :goto_0

    .line 65
    :cond_1
    invoke-static/range {p1 .. p2}, Lkp/p6;->b(Lqr0/q;Lij0/a;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    goto :goto_0

    .line 70
    :goto_1
    iget-object v7, v1, Lc00/d0;->a:Lc00/z;

    .line 71
    .line 72
    new-array v3, v6, [Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v2, Ljj0/f;

    .line 75
    .line 76
    const v4, 0x7f120088

    .line 77
    .line 78
    .line 79
    invoke-virtual {v2, v4, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v8

    .line 83
    invoke-static {v0}, Lkp/p6;->c(Lqr0/q;)F

    .line 84
    .line 85
    .line 86
    move-result v10

    .line 87
    const/4 v12, 0x0

    .line 88
    const/16 v13, 0x30

    .line 89
    .line 90
    const/4 v11, 0x0

    .line 91
    invoke-static/range {v7 .. v13}, Lc00/z;->a(Lc00/z;Ljava/lang/String;Ljava/lang/String;FZLvf0/g;I)Lc00/z;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    :goto_2
    move-object v2, v0

    .line 96
    goto :goto_3

    .line 97
    :cond_2
    invoke-static {v2}, Ljp/dc;->b(Lij0/a;)Lc00/z;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    goto :goto_2

    .line 102
    :goto_3
    const/16 v22, 0x0

    .line 103
    .line 104
    const v23, 0x3ffffe

    .line 105
    .line 106
    .line 107
    const/4 v3, 0x0

    .line 108
    const/4 v4, 0x0

    .line 109
    const/4 v5, 0x0

    .line 110
    const/4 v6, 0x0

    .line 111
    const/4 v7, 0x0

    .line 112
    const/4 v8, 0x0

    .line 113
    const/4 v9, 0x0

    .line 114
    const/4 v10, 0x0

    .line 115
    const/4 v11, 0x0

    .line 116
    const/4 v12, 0x0

    .line 117
    const/4 v13, 0x0

    .line 118
    const/4 v14, 0x0

    .line 119
    const/4 v15, 0x0

    .line 120
    const/16 v16, 0x0

    .line 121
    .line 122
    const/16 v17, 0x0

    .line 123
    .line 124
    const/16 v18, 0x0

    .line 125
    .line 126
    const/16 v19, 0x0

    .line 127
    .line 128
    const/16 v20, 0x0

    .line 129
    .line 130
    const/16 v21, 0x0

    .line 131
    .line 132
    invoke-static/range {v1 .. v23}, Lc00/d0;->a(Lc00/d0;Lc00/z;ZZLc00/a0;ZZZLc00/y;Lc00/c0;Lc00/b0;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Llf0/i;ZZZZZZI)Lc00/d0;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    return-object v0
.end method

.method public static f(Landroid/os/Parcel;ILandroid/os/Bundle;)V
    .locals 0

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p0, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    invoke-virtual {p0, p2}, Landroid/os/Parcel;->writeBundle(Landroid/os/Bundle;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static g(Landroid/os/Parcel;I[B)V
    .locals 0

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p0, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    invoke-virtual {p0, p2}, Landroid/os/Parcel;->writeByteArray([B)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static h(Landroid/os/Parcel;ILjava/lang/Float;)V
    .locals 1

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    const/4 v0, 0x4

    .line 5
    invoke-static {p0, p1, v0}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->writeFloat(F)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public static i(Landroid/os/Parcel;ILandroid/os/IBinder;)V
    .locals 0

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p0, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    invoke-virtual {p0, p2}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static j(Landroid/os/Parcel;I[I)V
    .locals 0

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p0, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    invoke-virtual {p0, p2}, Landroid/os/Parcel;->writeIntArray([I)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static k(Landroid/os/Parcel;ILjava/util/List;)V
    .locals 3

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p0, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    invoke-virtual {p0, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    :goto_0
    if-ge v1, v0, :cond_1

    .line 17
    .line 18
    invoke-interface {p2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    check-cast v2, Ljava/lang/Integer;

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    invoke-virtual {p0, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 29
    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    invoke-static {p0, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public static l(Landroid/os/Parcel;ILjava/lang/Long;)V
    .locals 1

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    const/16 v0, 0x8

    .line 5
    .line 6
    invoke-static {p0, p1, v0}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 10
    .line 11
    .line 12
    move-result-wide p1

    .line 13
    invoke-virtual {p0, p1, p2}, Landroid/os/Parcel;->writeLong(J)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public static m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V
    .locals 0

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p0, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    invoke-interface {p2, p0, p3}, Landroid/os/Parcelable;->writeToParcel(Landroid/os/Parcel;I)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static n(Landroid/os/Parcel;Ljava/lang/String;I)V
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p0, p2}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 5
    .line 6
    .line 7
    move-result p2

    .line 8
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, p2}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static o(Landroid/os/Parcel;I[Ljava/lang/String;)V
    .locals 0

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p0, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    invoke-virtual {p0, p2}, Landroid/os/Parcel;->writeStringArray([Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static p(Landroid/os/Parcel;ILjava/util/List;)V
    .locals 0

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p0, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    invoke-virtual {p0, p2}, Landroid/os/Parcel;->writeStringList(Ljava/util/List;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V
    .locals 6

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p0, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    array-length v0, p2

    .line 9
    invoke-virtual {p0, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 10
    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    move v2, v1

    .line 14
    :goto_0
    if-ge v2, v0, :cond_2

    .line 15
    .line 16
    aget-object v3, p2, v2

    .line 17
    .line 18
    if-nez v3, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 21
    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_1
    invoke-virtual {p0}, Landroid/os/Parcel;->dataPosition()I

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    const/4 v5, 0x1

    .line 29
    invoke-virtual {p0, v5}, Landroid/os/Parcel;->writeInt(I)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0}, Landroid/os/Parcel;->dataPosition()I

    .line 33
    .line 34
    .line 35
    move-result v5

    .line 36
    invoke-interface {v3, p0, p3}, Landroid/os/Parcelable;->writeToParcel(Landroid/os/Parcel;I)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Landroid/os/Parcel;->dataPosition()I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    invoke-virtual {p0, v4}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 44
    .line 45
    .line 46
    sub-int v4, v3, v5

    .line 47
    .line 48
    invoke-virtual {p0, v4}, Landroid/os/Parcel;->writeInt(I)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, v3}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 52
    .line 53
    .line 54
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    invoke-static {p0, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public static r(Landroid/os/Parcel;ILjava/util/List;)V
    .locals 6

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    invoke-static {p0, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    invoke-virtual {p0, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    move v2, v1

    .line 17
    :goto_0
    if-ge v2, v0, :cond_2

    .line 18
    .line 19
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    check-cast v3, Landroid/os/Parcelable;

    .line 24
    .line 25
    if-nez v3, :cond_1

    .line 26
    .line 27
    invoke-virtual {p0, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 28
    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    invoke-virtual {p0}, Landroid/os/Parcel;->dataPosition()I

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    const/4 v5, 0x1

    .line 36
    invoke-virtual {p0, v5}, Landroid/os/Parcel;->writeInt(I)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Landroid/os/Parcel;->dataPosition()I

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    invoke-interface {v3, p0, v1}, Landroid/os/Parcelable;->writeToParcel(Landroid/os/Parcel;I)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0}, Landroid/os/Parcel;->dataPosition()I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    invoke-virtual {p0, v4}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 51
    .line 52
    .line 53
    sub-int v4, v3, v5

    .line 54
    .line 55
    invoke-virtual {p0, v4}, Landroid/os/Parcel;->writeInt(I)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p0, v3}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 59
    .line 60
    .line 61
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_2
    invoke-static {p0, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 65
    .line 66
    .line 67
    return-void
.end method

.method public static s(Landroid/os/Parcel;I)I
    .locals 1

    .line 1
    const/high16 v0, -0x10000

    .line 2
    .line 3
    or-int/2addr p1, v0

    .line 4
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->writeInt(I)V

    .line 5
    .line 6
    .line 7
    const/4 p1, 0x0

    .line 8
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->writeInt(I)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Landroid/os/Parcel;->dataPosition()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public static t(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/os/Parcel;->dataPosition()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sub-int v1, v0, p1

    .line 6
    .line 7
    add-int/lit8 p1, p1, -0x4

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, v0}, Landroid/os/Parcel;->setDataPosition(I)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public static u(Landroid/os/Parcel;II)V
    .locals 0

    .line 1
    shl-int/lit8 p2, p2, 0x10

    .line 2
    .line 3
    or-int/2addr p1, p2

    .line 4
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->writeInt(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method
