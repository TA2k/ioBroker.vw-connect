.class public abstract Llp/sf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lss0/k;Lss0/e;)Z
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lss0/k;->i:Lss0/a0;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lss0/a0;->a:Lss0/b;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    :goto_0
    sget-object v0, Llf0/i;->i:Llf0/i;

    .line 15
    .line 16
    iget-object v0, v0, Llf0/i;->d:Ljava/util/List;

    .line 17
    .line 18
    check-cast v0, Ljava/util/Collection;

    .line 19
    .line 20
    sget-object v1, Llf0/i;->e:Llf0/i;

    .line 21
    .line 22
    iget-object v1, v1, Llf0/i;->d:Ljava/util/List;

    .line 23
    .line 24
    check-cast v1, Ljava/lang/Iterable;

    .line 25
    .line 26
    invoke-static {v1, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sget-object v1, Llf0/i;->f:Llf0/i;

    .line 31
    .line 32
    iget-object v1, v1, Llf0/i;->d:Ljava/util/List;

    .line 33
    .line 34
    check-cast v1, Ljava/lang/Iterable;

    .line 35
    .line 36
    invoke-static {v1, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    sget-object v1, Llf0/i;->g:Llf0/i;

    .line 41
    .line 42
    iget-object v1, v1, Llf0/i;->d:Ljava/util/List;

    .line 43
    .line 44
    check-cast v1, Ljava/lang/Iterable;

    .line 45
    .line 46
    invoke-static {v1, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    sget-object v1, Llf0/i;->h:Llf0/i;

    .line 51
    .line 52
    iget-object v1, v1, Llf0/i;->d:Ljava/util/List;

    .line 53
    .line 54
    check-cast v1, Ljava/lang/Iterable;

    .line 55
    .line 56
    invoke-static {v1, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    invoke-static {p0, p1, v0}, Llp/pf;->h(Lss0/b;Lss0/e;Ljava/util/List;)Z

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    return p0
.end method

.method public static final b(Lne0/t;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Llf0/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Llf0/d;

    .line 7
    .line 8
    iget v1, v0, Llf0/d;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Llf0/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Llf0/d;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Llf0/d;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Llf0/d;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Llf0/d;->d:Lne0/c;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    instance-of p2, p0, Lne0/e;

    .line 54
    .line 55
    if-eqz p2, :cond_5

    .line 56
    .line 57
    move-object p2, p0

    .line 58
    check-cast p2, Lne0/e;

    .line 59
    .line 60
    iget-object p2, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p2, Lss0/k;

    .line 63
    .line 64
    iget-object p2, p2, Lss0/k;->i:Lss0/a0;

    .line 65
    .line 66
    if-eqz p2, :cond_3

    .line 67
    .line 68
    iget-object p2, p2, Lss0/a0;->a:Lss0/b;

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_3
    const/4 p2, 0x0

    .line 72
    :goto_1
    sget-object v2, Lss0/e;->R1:Lss0/e;

    .line 73
    .line 74
    invoke-static {p2, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 75
    .line 76
    .line 77
    move-result p2

    .line 78
    if-eqz p2, :cond_5

    .line 79
    .line 80
    new-instance v4, Lne0/c;

    .line 81
    .line 82
    sget-object v5, Lss0/i0;->d:Lss0/i0;

    .line 83
    .line 84
    const/4 v8, 0x0

    .line 85
    const/16 v9, 0x1e

    .line 86
    .line 87
    const/4 v6, 0x0

    .line 88
    const/4 v7, 0x0

    .line 89
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 90
    .line 91
    .line 92
    iput-object v4, v0, Llf0/d;->d:Lne0/c;

    .line 93
    .line 94
    iput v3, v0, Llf0/d;->f:I

    .line 95
    .line 96
    invoke-interface {p1, v4, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-ne p0, v1, :cond_4

    .line 101
    .line 102
    return-object v1

    .line 103
    :cond_4
    return-object v4

    .line 104
    :cond_5
    return-object p0
.end method

.method public static final c(Lyy0/m1;Lay0/n;)Lyy0/m1;
    .locals 2

    .line 1
    new-instance v0, Lk31/l;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1, p1}, Lk31/l;-><init>(Lyy0/m1;Lkotlin/coroutines/Continuation;Lay0/n;)V

    .line 5
    .line 6
    .line 7
    new-instance p0, Lyy0/m1;

    .line 8
    .line 9
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method

.method public static final d(Landroid/view/ViewStructure;Lv3/h0;Landroid/view/autofill/AutofillId;Ljava/lang/String;Le4/a;)V
    .locals 38

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 7
    .line 8
    .line 9
    move-result-object v3

    .line 10
    sget-object v4, Ld4/v;->a:Ld4/z;

    .line 11
    .line 12
    sget-object v4, Ld4/k;->a:Ld4/z;

    .line 13
    .line 14
    invoke-virtual {v1}, Lv3/h0;->x()Ld4/l;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    const/4 v10, 0x2

    .line 19
    const/16 v13, 0x8

    .line 20
    .line 21
    if-eqz v4, :cond_13

    .line 22
    .line 23
    iget-object v4, v4, Ld4/l;->d:Landroidx/collection/q0;

    .line 24
    .line 25
    if-eqz v4, :cond_13

    .line 26
    .line 27
    const-wide/16 v16, 0x80

    .line 28
    .line 29
    iget-object v5, v4, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 30
    .line 31
    iget-object v6, v4, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 32
    .line 33
    iget-object v4, v4, Landroidx/collection/q0;->a:[J

    .line 34
    .line 35
    const-wide/16 v18, 0xff

    .line 36
    .line 37
    array-length v7, v4

    .line 38
    sub-int/2addr v7, v10

    .line 39
    move/from16 v30, v10

    .line 40
    .line 41
    if-ltz v7, :cond_11

    .line 42
    .line 43
    const/4 v8, 0x0

    .line 44
    const/16 v20, 0x0

    .line 45
    .line 46
    const/16 v21, 0x0

    .line 47
    .line 48
    const/16 v22, 0x0

    .line 49
    .line 50
    const/16 v23, 0x0

    .line 51
    .line 52
    const/16 v24, 0x0

    .line 53
    .line 54
    const/16 v25, 0x0

    .line 55
    .line 56
    const/16 v26, 0x0

    .line 57
    .line 58
    const/16 v27, 0x0

    .line 59
    .line 60
    const/16 v28, 0x0

    .line 61
    .line 62
    const/16 v29, 0x7

    .line 63
    .line 64
    :goto_0
    aget-wide v9, v4, v8

    .line 65
    .line 66
    const-wide v31, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 67
    .line 68
    .line 69
    .line 70
    .line 71
    not-long v11, v9

    .line 72
    shl-long v11, v11, v29

    .line 73
    .line 74
    and-long/2addr v11, v9

    .line 75
    and-long v11, v11, v31

    .line 76
    .line 77
    cmp-long v11, v11, v31

    .line 78
    .line 79
    if-eqz v11, :cond_10

    .line 80
    .line 81
    sub-int v11, v8, v7

    .line 82
    .line 83
    not-int v11, v11

    .line 84
    ushr-int/lit8 v11, v11, 0x1f

    .line 85
    .line 86
    rsub-int/lit8 v11, v11, 0x8

    .line 87
    .line 88
    const/4 v12, 0x0

    .line 89
    :goto_1
    if-ge v12, v11, :cond_f

    .line 90
    .line 91
    and-long v33, v9, v18

    .line 92
    .line 93
    cmp-long v33, v33, v16

    .line 94
    .line 95
    if-gez v33, :cond_d

    .line 96
    .line 97
    shl-int/lit8 v33, v8, 0x3

    .line 98
    .line 99
    add-int v33, v33, v12

    .line 100
    .line 101
    aget-object v34, v5, v33

    .line 102
    .line 103
    aget-object v14, v6, v33

    .line 104
    .line 105
    move-object/from16 v15, v34

    .line 106
    .line 107
    check-cast v15, Ld4/z;

    .line 108
    .line 109
    move/from16 v34, v13

    .line 110
    .line 111
    sget-object v13, Ld4/v;->r:Ld4/z;

    .line 112
    .line 113
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result v13

    .line 117
    if-eqz v13, :cond_0

    .line 118
    .line 119
    const-string v13, "null cannot be cast to non-null type androidx.compose.ui.autofill.ContentDataType"

    .line 120
    .line 121
    invoke-static {v14, v13}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    move-object/from16 v20, v14

    .line 125
    .line 126
    check-cast v20, Ly2/c;

    .line 127
    .line 128
    goto/16 :goto_2

    .line 129
    .line 130
    :cond_0
    sget-object v13, Ld4/v;->a:Ld4/z;

    .line 131
    .line 132
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v13

    .line 136
    if-eqz v13, :cond_1

    .line 137
    .line 138
    const-string v13, "null cannot be cast to non-null type kotlin.collections.List<kotlin.String>"

    .line 139
    .line 140
    invoke-static {v14, v13}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    check-cast v14, Ljava/util/List;

    .line 144
    .line 145
    invoke-static {v14}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v13

    .line 149
    check-cast v13, Ljava/lang/String;

    .line 150
    .line 151
    if-eqz v13, :cond_e

    .line 152
    .line 153
    invoke-virtual {v0, v13}, Landroid/view/ViewStructure;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 154
    .line 155
    .line 156
    goto/16 :goto_2

    .line 157
    .line 158
    :cond_1
    sget-object v13, Ld4/v;->q:Ld4/z;

    .line 159
    .line 160
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v13

    .line 164
    if-eqz v13, :cond_2

    .line 165
    .line 166
    const-string v13, "null cannot be cast to non-null type androidx.compose.ui.autofill.ContentType"

    .line 167
    .line 168
    invoke-static {v14, v13}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    move-object/from16 v23, v14

    .line 172
    .line 173
    check-cast v23, Ly2/k;

    .line 174
    .line 175
    goto/16 :goto_2

    .line 176
    .line 177
    :cond_2
    sget-object v13, Ld4/v;->E:Ld4/z;

    .line 178
    .line 179
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v13

    .line 183
    if-eqz v13, :cond_3

    .line 184
    .line 185
    const-string v13, "null cannot be cast to non-null type androidx.compose.ui.text.AnnotatedString"

    .line 186
    .line 187
    invoke-static {v14, v13}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    move-object/from16 v28, v14

    .line 191
    .line 192
    check-cast v28, Lg4/g;

    .line 193
    .line 194
    goto/16 :goto_2

    .line 195
    .line 196
    :cond_3
    sget-object v13, Ld4/v;->k:Ld4/z;

    .line 197
    .line 198
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result v13

    .line 202
    const-string v2, "null cannot be cast to non-null type kotlin.Boolean"

    .line 203
    .line 204
    if-eqz v13, :cond_4

    .line 205
    .line 206
    invoke-static {v14, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    check-cast v14, Ljava/lang/Boolean;

    .line 210
    .line 211
    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    .line 212
    .line 213
    .line 214
    move-result v2

    .line 215
    invoke-virtual {v0, v2}, Landroid/view/ViewStructure;->setFocused(Z)V

    .line 216
    .line 217
    .line 218
    goto/16 :goto_2

    .line 219
    .line 220
    :cond_4
    sget-object v13, Ld4/v;->N:Ld4/z;

    .line 221
    .line 222
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    move-result v13

    .line 226
    if-eqz v13, :cond_5

    .line 227
    .line 228
    const-string v2, "null cannot be cast to non-null type kotlin.Int"

    .line 229
    .line 230
    invoke-static {v14, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    move-object/from16 v27, v14

    .line 234
    .line 235
    check-cast v27, Ljava/lang/Integer;

    .line 236
    .line 237
    goto/16 :goto_2

    .line 238
    .line 239
    :cond_5
    sget-object v13, Ld4/v;->J:Ld4/z;

    .line 240
    .line 241
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    move-result v13

    .line 245
    if-eqz v13, :cond_6

    .line 246
    .line 247
    const/16 v26, 0x1

    .line 248
    .line 249
    goto/16 :goto_2

    .line 250
    .line 251
    :cond_6
    sget-object v13, Ld4/v;->x:Ld4/z;

    .line 252
    .line 253
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 254
    .line 255
    .line 256
    move-result v13

    .line 257
    if-eqz v13, :cond_7

    .line 258
    .line 259
    const-string v2, "null cannot be cast to non-null type androidx.compose.ui.semantics.Role"

    .line 260
    .line 261
    invoke-static {v14, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    move-object/from16 v25, v14

    .line 265
    .line 266
    check-cast v25, Ld4/i;

    .line 267
    .line 268
    goto :goto_2

    .line 269
    :cond_7
    sget-object v13, Ld4/v;->H:Ld4/z;

    .line 270
    .line 271
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    move-result v13

    .line 275
    if-eqz v13, :cond_8

    .line 276
    .line 277
    invoke-static {v14, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 278
    .line 279
    .line 280
    move-object/from16 v24, v14

    .line 281
    .line 282
    check-cast v24, Ljava/lang/Boolean;

    .line 283
    .line 284
    goto :goto_2

    .line 285
    :cond_8
    sget-object v2, Ld4/v;->I:Ld4/z;

    .line 286
    .line 287
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 288
    .line 289
    .line 290
    move-result v2

    .line 291
    if-eqz v2, :cond_9

    .line 292
    .line 293
    const-string v2, "null cannot be cast to non-null type androidx.compose.ui.state.ToggleableState"

    .line 294
    .line 295
    invoke-static {v14, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    move-object/from16 v22, v14

    .line 299
    .line 300
    check-cast v22, Lf4/a;

    .line 301
    .line 302
    goto :goto_2

    .line 303
    :cond_9
    sget-object v2, Ld4/k;->b:Ld4/z;

    .line 304
    .line 305
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 306
    .line 307
    .line 308
    move-result v2

    .line 309
    if-eqz v2, :cond_a

    .line 310
    .line 311
    const/4 v2, 0x1

    .line 312
    invoke-virtual {v0, v2}, Landroid/view/ViewStructure;->setClickable(Z)V

    .line 313
    .line 314
    .line 315
    goto :goto_2

    .line 316
    :cond_a
    const/4 v2, 0x1

    .line 317
    sget-object v13, Ld4/k;->c:Ld4/z;

    .line 318
    .line 319
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 320
    .line 321
    .line 322
    move-result v13

    .line 323
    if-eqz v13, :cond_b

    .line 324
    .line 325
    invoke-virtual {v0, v2}, Landroid/view/ViewStructure;->setLongClickable(Z)V

    .line 326
    .line 327
    .line 328
    goto :goto_2

    .line 329
    :cond_b
    sget-object v13, Ld4/k;->v:Ld4/z;

    .line 330
    .line 331
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 332
    .line 333
    .line 334
    move-result v13

    .line 335
    if-eqz v13, :cond_c

    .line 336
    .line 337
    invoke-virtual {v0, v2}, Landroid/view/ViewStructure;->setFocusable(Z)V

    .line 338
    .line 339
    .line 340
    goto :goto_2

    .line 341
    :cond_c
    sget-object v2, Ld4/k;->j:Ld4/z;

    .line 342
    .line 343
    invoke-static {v15, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 344
    .line 345
    .line 346
    move-result v2

    .line 347
    if-eqz v2, :cond_e

    .line 348
    .line 349
    const/16 v21, 0x1

    .line 350
    .line 351
    goto :goto_2

    .line 352
    :cond_d
    move/from16 v34, v13

    .line 353
    .line 354
    :cond_e
    :goto_2
    shr-long v9, v9, v34

    .line 355
    .line 356
    add-int/lit8 v12, v12, 0x1

    .line 357
    .line 358
    move/from16 v13, v34

    .line 359
    .line 360
    const/4 v2, 0x1

    .line 361
    goto/16 :goto_1

    .line 362
    .line 363
    :cond_f
    move v2, v13

    .line 364
    if-ne v11, v2, :cond_12

    .line 365
    .line 366
    :cond_10
    if-eq v8, v7, :cond_12

    .line 367
    .line 368
    add-int/lit8 v8, v8, 0x1

    .line 369
    .line 370
    const/4 v2, 0x1

    .line 371
    const/16 v13, 0x8

    .line 372
    .line 373
    goto/16 :goto_0

    .line 374
    .line 375
    :cond_11
    const/16 v29, 0x7

    .line 376
    .line 377
    const-wide v31, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 378
    .line 379
    .line 380
    .line 381
    .line 382
    const/16 v20, 0x0

    .line 383
    .line 384
    const/16 v21, 0x0

    .line 385
    .line 386
    const/16 v22, 0x0

    .line 387
    .line 388
    const/16 v23, 0x0

    .line 389
    .line 390
    const/16 v24, 0x0

    .line 391
    .line 392
    const/16 v25, 0x0

    .line 393
    .line 394
    const/16 v26, 0x0

    .line 395
    .line 396
    const/16 v27, 0x0

    .line 397
    .line 398
    const/16 v28, 0x0

    .line 399
    .line 400
    :cond_12
    move-object/from16 v2, v22

    .line 401
    .line 402
    move-object/from16 v4, v25

    .line 403
    .line 404
    move-object/from16 v5, v28

    .line 405
    .line 406
    goto :goto_3

    .line 407
    :cond_13
    move/from16 v30, v10

    .line 408
    .line 409
    const-wide/16 v16, 0x80

    .line 410
    .line 411
    const-wide/16 v18, 0xff

    .line 412
    .line 413
    const/16 v29, 0x7

    .line 414
    .line 415
    const-wide v31, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 416
    .line 417
    .line 418
    .line 419
    .line 420
    const/4 v2, 0x0

    .line 421
    const/4 v4, 0x0

    .line 422
    const/4 v5, 0x0

    .line 423
    const/16 v20, 0x0

    .line 424
    .line 425
    const/16 v21, 0x0

    .line 426
    .line 427
    const/16 v23, 0x0

    .line 428
    .line 429
    const/16 v24, 0x0

    .line 430
    .line 431
    const/16 v26, 0x0

    .line 432
    .line 433
    const/16 v27, 0x0

    .line 434
    .line 435
    :goto_3
    invoke-virtual {v1}, Lv3/h0;->x()Ld4/l;

    .line 436
    .line 437
    .line 438
    move-result-object v6

    .line 439
    if-eqz v6, :cond_17

    .line 440
    .line 441
    iget-boolean v7, v6, Ld4/l;->f:Z

    .line 442
    .line 443
    if-eqz v7, :cond_17

    .line 444
    .line 445
    iget-boolean v7, v6, Ld4/l;->g:Z

    .line 446
    .line 447
    if-eqz v7, :cond_14

    .line 448
    .line 449
    goto :goto_5

    .line 450
    :cond_14
    invoke-virtual {v6}, Ld4/l;->c()Ld4/l;

    .line 451
    .line 452
    .line 453
    move-result-object v6

    .line 454
    new-instance v7, Landroidx/collection/l0;

    .line 455
    .line 456
    invoke-virtual {v1}, Lv3/h0;->o()Ljava/util/List;

    .line 457
    .line 458
    .line 459
    move-result-object v8

    .line 460
    check-cast v8, Landroidx/collection/j0;

    .line 461
    .line 462
    iget-object v8, v8, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 463
    .line 464
    check-cast v8, Ln2/b;

    .line 465
    .line 466
    iget v8, v8, Ln2/b;->f:I

    .line 467
    .line 468
    invoke-direct {v7, v8}, Landroidx/collection/l0;-><init>(I)V

    .line 469
    .line 470
    .line 471
    invoke-virtual {v1}, Lv3/h0;->o()Ljava/util/List;

    .line 472
    .line 473
    .line 474
    move-result-object v8

    .line 475
    invoke-virtual {v7, v8}, Landroidx/collection/l0;->b(Ljava/util/List;)V

    .line 476
    .line 477
    .line 478
    :cond_15
    :goto_4
    invoke-virtual {v7}, Landroidx/collection/l0;->h()Z

    .line 479
    .line 480
    .line 481
    move-result v8

    .line 482
    if-eqz v8, :cond_17

    .line 483
    .line 484
    iget v8, v7, Landroidx/collection/l0;->b:I

    .line 485
    .line 486
    const/16 v35, 0x1

    .line 487
    .line 488
    add-int/lit8 v8, v8, -0x1

    .line 489
    .line 490
    invoke-virtual {v7, v8}, Landroidx/collection/l0;->j(I)Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    move-result-object v8

    .line 494
    check-cast v8, Lv3/h0;

    .line 495
    .line 496
    invoke-virtual {v8}, Lv3/h0;->x()Ld4/l;

    .line 497
    .line 498
    .line 499
    move-result-object v9

    .line 500
    if-eqz v9, :cond_15

    .line 501
    .line 502
    iget-boolean v10, v9, Ld4/l;->f:Z

    .line 503
    .line 504
    if-eqz v10, :cond_16

    .line 505
    .line 506
    goto :goto_4

    .line 507
    :cond_16
    invoke-virtual {v6, v9}, Ld4/l;->g(Ld4/l;)V

    .line 508
    .line 509
    .line 510
    iget-boolean v9, v9, Ld4/l;->g:Z

    .line 511
    .line 512
    if-nez v9, :cond_15

    .line 513
    .line 514
    invoke-virtual {v8}, Lv3/h0;->o()Ljava/util/List;

    .line 515
    .line 516
    .line 517
    move-result-object v8

    .line 518
    invoke-virtual {v7, v8}, Landroidx/collection/l0;->b(Ljava/util/List;)V

    .line 519
    .line 520
    .line 521
    goto :goto_4

    .line 522
    :cond_17
    :goto_5
    if-eqz v6, :cond_1d

    .line 523
    .line 524
    iget-object v6, v6, Ld4/l;->d:Landroidx/collection/q0;

    .line 525
    .line 526
    if-eqz v6, :cond_1d

    .line 527
    .line 528
    iget-object v7, v6, Landroidx/collection/q0;->b:[Ljava/lang/Object;

    .line 529
    .line 530
    iget-object v8, v6, Landroidx/collection/q0;->c:[Ljava/lang/Object;

    .line 531
    .line 532
    iget-object v6, v6, Landroidx/collection/q0;->a:[J

    .line 533
    .line 534
    array-length v9, v6

    .line 535
    add-int/lit8 v9, v9, -0x2

    .line 536
    .line 537
    if-ltz v9, :cond_1d

    .line 538
    .line 539
    const/4 v10, 0x0

    .line 540
    const/4 v11, 0x0

    .line 541
    :goto_6
    aget-wide v12, v6, v10

    .line 542
    .line 543
    not-long v14, v12

    .line 544
    shl-long v14, v14, v29

    .line 545
    .line 546
    and-long/2addr v14, v12

    .line 547
    and-long v14, v14, v31

    .line 548
    .line 549
    cmp-long v14, v14, v31

    .line 550
    .line 551
    if-eqz v14, :cond_1c

    .line 552
    .line 553
    sub-int v14, v10, v9

    .line 554
    .line 555
    not-int v14, v14

    .line 556
    ushr-int/lit8 v14, v14, 0x1f

    .line 557
    .line 558
    const/16 v34, 0x8

    .line 559
    .line 560
    rsub-int/lit8 v14, v14, 0x8

    .line 561
    .line 562
    const/4 v15, 0x0

    .line 563
    :goto_7
    if-ge v15, v14, :cond_1b

    .line 564
    .line 565
    and-long v36, v12, v18

    .line 566
    .line 567
    cmp-long v22, v36, v16

    .line 568
    .line 569
    if-gez v22, :cond_1a

    .line 570
    .line 571
    shl-int/lit8 v22, v10, 0x3

    .line 572
    .line 573
    add-int v22, v22, v15

    .line 574
    .line 575
    aget-object v25, v7, v22

    .line 576
    .line 577
    move-object/from16 v28, v3

    .line 578
    .line 579
    aget-object v3, v8, v22

    .line 580
    .line 581
    move-object/from16 v22, v6

    .line 582
    .line 583
    move-object/from16 v6, v25

    .line 584
    .line 585
    check-cast v6, Ld4/z;

    .line 586
    .line 587
    move-object/from16 v25, v7

    .line 588
    .line 589
    sget-object v7, Ld4/v;->i:Ld4/z;

    .line 590
    .line 591
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 592
    .line 593
    .line 594
    move-result v7

    .line 595
    if-eqz v7, :cond_18

    .line 596
    .line 597
    const/4 v7, 0x0

    .line 598
    invoke-virtual {v0, v7}, Landroid/view/ViewStructure;->setEnabled(Z)V

    .line 599
    .line 600
    .line 601
    goto :goto_8

    .line 602
    :cond_18
    sget-object v7, Ld4/v;->A:Ld4/z;

    .line 603
    .line 604
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 605
    .line 606
    .line 607
    move-result v6

    .line 608
    if-eqz v6, :cond_19

    .line 609
    .line 610
    const-string v6, "null cannot be cast to non-null type kotlin.collections.List<androidx.compose.ui.text.AnnotatedString>"

    .line 611
    .line 612
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 613
    .line 614
    .line 615
    move-object v11, v3

    .line 616
    check-cast v11, Ljava/util/List;

    .line 617
    .line 618
    :cond_19
    :goto_8
    const/16 v3, 0x8

    .line 619
    .line 620
    goto :goto_9

    .line 621
    :cond_1a
    move-object/from16 v28, v3

    .line 622
    .line 623
    move-object/from16 v22, v6

    .line 624
    .line 625
    move-object/from16 v25, v7

    .line 626
    .line 627
    goto :goto_8

    .line 628
    :goto_9
    shr-long/2addr v12, v3

    .line 629
    add-int/lit8 v15, v15, 0x1

    .line 630
    .line 631
    move-object/from16 v6, v22

    .line 632
    .line 633
    move-object/from16 v7, v25

    .line 634
    .line 635
    move-object/from16 v3, v28

    .line 636
    .line 637
    goto :goto_7

    .line 638
    :cond_1b
    move-object/from16 v28, v3

    .line 639
    .line 640
    move-object/from16 v22, v6

    .line 641
    .line 642
    move-object/from16 v25, v7

    .line 643
    .line 644
    const/16 v3, 0x8

    .line 645
    .line 646
    if-ne v14, v3, :cond_1e

    .line 647
    .line 648
    goto :goto_a

    .line 649
    :cond_1c
    move-object/from16 v28, v3

    .line 650
    .line 651
    move-object/from16 v22, v6

    .line 652
    .line 653
    move-object/from16 v25, v7

    .line 654
    .line 655
    const/16 v3, 0x8

    .line 656
    .line 657
    :goto_a
    if-eq v10, v9, :cond_1e

    .line 658
    .line 659
    add-int/lit8 v10, v10, 0x1

    .line 660
    .line 661
    move-object/from16 v6, v22

    .line 662
    .line 663
    move-object/from16 v7, v25

    .line 664
    .line 665
    move-object/from16 v3, v28

    .line 666
    .line 667
    goto :goto_6

    .line 668
    :cond_1d
    move-object/from16 v28, v3

    .line 669
    .line 670
    const/4 v11, 0x0

    .line 671
    :cond_1e
    iget v3, v1, Lv3/h0;->e:I

    .line 672
    .line 673
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 674
    .line 675
    .line 676
    move-result-object v3

    .line 677
    invoke-virtual {v1}, Lv3/h0;->v()Lv3/h0;

    .line 678
    .line 679
    .line 680
    move-result-object v6

    .line 681
    if-nez v6, :cond_1f

    .line 682
    .line 683
    const/4 v3, 0x0

    .line 684
    :cond_1f
    if-eqz v3, :cond_20

    .line 685
    .line 686
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 687
    .line 688
    .line 689
    move-result v3

    .line 690
    :goto_b
    move-object/from16 v6, p2

    .line 691
    .line 692
    goto :goto_c

    .line 693
    :cond_20
    const/4 v3, -0x1

    .line 694
    goto :goto_b

    .line 695
    :goto_c
    invoke-virtual {v0, v6, v3}, Landroid/view/ViewStructure;->setAutofillId(Landroid/view/autofill/AutofillId;I)V

    .line 696
    .line 697
    .line 698
    move-object/from16 v6, p3

    .line 699
    .line 700
    const/4 v7, 0x0

    .line 701
    invoke-virtual {v0, v3, v6, v7, v7}, Landroid/view/ViewStructure;->setId(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 702
    .line 703
    .line 704
    if-eqz v20, :cond_21

    .line 705
    .line 706
    :goto_d
    move-object/from16 v3, v28

    .line 707
    .line 708
    goto :goto_e

    .line 709
    :cond_21
    if-eqz v21, :cond_22

    .line 710
    .line 711
    goto :goto_d

    .line 712
    :cond_22
    if-eqz v2, :cond_23

    .line 713
    .line 714
    invoke-static/range {v30 .. v30}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 715
    .line 716
    .line 717
    move-result-object v3

    .line 718
    goto :goto_e

    .line 719
    :cond_23
    move-object v3, v7

    .line 720
    :goto_e
    if-eqz v3, :cond_24

    .line 721
    .line 722
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 723
    .line 724
    .line 725
    move-result v3

    .line 726
    invoke-virtual {v0, v3}, Landroid/view/ViewStructure;->setAutofillType(I)V

    .line 727
    .line 728
    .line 729
    :cond_24
    if-eqz v23, :cond_25

    .line 730
    .line 731
    invoke-static/range {v23 .. v23}, Llp/rf;->b(Ly2/k;)[Ljava/lang/String;

    .line 732
    .line 733
    .line 734
    move-result-object v3

    .line 735
    if-eqz v3, :cond_25

    .line 736
    .line 737
    invoke-virtual {v0, v3}, Landroid/view/ViewStructure;->setAutofillHints([Ljava/lang/String;)V

    .line 738
    .line 739
    .line 740
    :cond_25
    move-object/from16 v3, p4

    .line 741
    .line 742
    iget-object v3, v3, Le4/a;->a:Lbb/g0;

    .line 743
    .line 744
    iget v6, v1, Lv3/h0;->e:I

    .line 745
    .line 746
    new-instance v7, Ltv/i;

    .line 747
    .line 748
    const/4 v8, 0x1

    .line 749
    invoke-direct {v7, v0, v8}, Ltv/i;-><init>(Ljava/lang/Object;I)V

    .line 750
    .line 751
    .line 752
    invoke-virtual {v3, v6, v7}, Lbb/g0;->u(ILay0/p;)V

    .line 753
    .line 754
    .line 755
    if-eqz v24, :cond_26

    .line 756
    .line 757
    invoke-virtual/range {v24 .. v24}, Ljava/lang/Boolean;->booleanValue()Z

    .line 758
    .line 759
    .line 760
    move-result v3

    .line 761
    invoke-virtual {v0, v3}, Landroid/view/ViewStructure;->setSelected(Z)V

    .line 762
    .line 763
    .line 764
    :cond_26
    const/4 v3, 0x4

    .line 765
    if-eqz v2, :cond_28

    .line 766
    .line 767
    invoke-virtual {v0, v8}, Landroid/view/ViewStructure;->setCheckable(Z)V

    .line 768
    .line 769
    .line 770
    sget-object v6, Lf4/a;->d:Lf4/a;

    .line 771
    .line 772
    if-ne v2, v6, :cond_27

    .line 773
    .line 774
    const/4 v2, 0x1

    .line 775
    goto :goto_f

    .line 776
    :cond_27
    const/4 v2, 0x0

    .line 777
    :goto_f
    invoke-virtual {v0, v2}, Landroid/view/ViewStructure;->setChecked(Z)V

    .line 778
    .line 779
    .line 780
    goto :goto_11

    .line 781
    :cond_28
    if-eqz v24, :cond_2b

    .line 782
    .line 783
    if-nez v4, :cond_2a

    .line 784
    .line 785
    :cond_29
    const/4 v2, 0x1

    .line 786
    goto :goto_10

    .line 787
    :cond_2a
    iget v2, v4, Ld4/i;->a:I

    .line 788
    .line 789
    if-ne v2, v3, :cond_29

    .line 790
    .line 791
    goto :goto_11

    .line 792
    :goto_10
    invoke-virtual {v0, v2}, Landroid/view/ViewStructure;->setCheckable(Z)V

    .line 793
    .line 794
    .line 795
    invoke-virtual/range {v24 .. v24}, Ljava/lang/Boolean;->booleanValue()Z

    .line 796
    .line 797
    .line 798
    move-result v2

    .line 799
    invoke-virtual {v0, v2}, Landroid/view/ViewStructure;->setChecked(Z)V

    .line 800
    .line 801
    .line 802
    :cond_2b
    :goto_11
    sget-object v2, Ly2/k;->a:Ly2/j;

    .line 803
    .line 804
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 805
    .line 806
    .line 807
    sget-object v2, Ly2/j;->b:Ly2/d;

    .line 808
    .line 809
    invoke-static {v2}, Llp/rf;->b(Ly2/k;)[Ljava/lang/String;

    .line 810
    .line 811
    .line 812
    move-result-object v2

    .line 813
    invoke-static {v2}, Lmx0/n;->u([Ljava/lang/Object;)Ljava/lang/Object;

    .line 814
    .line 815
    .line 816
    move-result-object v2

    .line 817
    check-cast v2, Ljava/lang/String;

    .line 818
    .line 819
    if-eqz v23, :cond_2c

    .line 820
    .line 821
    invoke-static/range {v23 .. v23}, Llp/rf;->b(Ly2/k;)[Ljava/lang/String;

    .line 822
    .line 823
    .line 824
    move-result-object v6

    .line 825
    if-eqz v6, :cond_2c

    .line 826
    .line 827
    invoke-static {v2, v6}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 828
    .line 829
    .line 830
    move-result v2

    .line 831
    const/4 v8, 0x1

    .line 832
    if-ne v2, v8, :cond_2c

    .line 833
    .line 834
    const/4 v2, 0x1

    .line 835
    goto :goto_12

    .line 836
    :cond_2c
    const/4 v2, 0x0

    .line 837
    :goto_12
    if-nez v26, :cond_2e

    .line 838
    .line 839
    if-eqz v2, :cond_2d

    .line 840
    .line 841
    goto :goto_13

    .line 842
    :cond_2d
    const/4 v2, 0x0

    .line 843
    goto :goto_14

    .line 844
    :cond_2e
    :goto_13
    const/4 v2, 0x1

    .line 845
    :goto_14
    if-eqz v2, :cond_2f

    .line 846
    .line 847
    const/4 v8, 0x1

    .line 848
    invoke-virtual {v0, v8}, Landroid/view/ViewStructure;->setDataIsSensitive(Z)V

    .line 849
    .line 850
    .line 851
    :cond_2f
    iget-object v6, v1, Lv3/h0;->H:Lg1/q;

    .line 852
    .line 853
    iget-object v6, v6, Lg1/q;->e:Ljava/lang/Object;

    .line 854
    .line 855
    check-cast v6, Lv3/f1;

    .line 856
    .line 857
    invoke-virtual {v6}, Lv3/f1;->n1()Z

    .line 858
    .line 859
    .line 860
    move-result v6

    .line 861
    if-eqz v6, :cond_30

    .line 862
    .line 863
    goto :goto_15

    .line 864
    :cond_30
    const/4 v3, 0x0

    .line 865
    :goto_15
    invoke-virtual {v0, v3}, Landroid/view/ViewStructure;->setVisibility(I)V

    .line 866
    .line 867
    .line 868
    if-eqz v11, :cond_32

    .line 869
    .line 870
    move-object v3, v11

    .line 871
    check-cast v3, Ljava/util/Collection;

    .line 872
    .line 873
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 874
    .line 875
    .line 876
    move-result v3

    .line 877
    const-string v6, ""

    .line 878
    .line 879
    const/4 v15, 0x0

    .line 880
    :goto_16
    if-ge v15, v3, :cond_31

    .line 881
    .line 882
    invoke-interface {v11, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 883
    .line 884
    .line 885
    move-result-object v7

    .line 886
    check-cast v7, Lg4/g;

    .line 887
    .line 888
    invoke-static {v6}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 889
    .line 890
    .line 891
    move-result-object v6

    .line 892
    iget-object v7, v7, Lg4/g;->e:Ljava/lang/String;

    .line 893
    .line 894
    const/16 v8, 0xa

    .line 895
    .line 896
    invoke-static {v6, v7, v8}, La7/g0;->j(Ljava/lang/StringBuilder;Ljava/lang/String;C)Ljava/lang/String;

    .line 897
    .line 898
    .line 899
    move-result-object v6

    .line 900
    add-int/lit8 v15, v15, 0x1

    .line 901
    .line 902
    goto :goto_16

    .line 903
    :cond_31
    invoke-virtual {v0, v6}, Landroid/view/ViewStructure;->setText(Ljava/lang/CharSequence;)V

    .line 904
    .line 905
    .line 906
    const-string v3, "android.widget.TextView"

    .line 907
    .line 908
    invoke-virtual {v0, v3}, Landroid/view/ViewStructure;->setClassName(Ljava/lang/String;)V

    .line 909
    .line 910
    .line 911
    :cond_32
    invoke-virtual {v1}, Lv3/h0;->o()Ljava/util/List;

    .line 912
    .line 913
    .line 914
    move-result-object v1

    .line 915
    check-cast v1, Landroidx/collection/j0;

    .line 916
    .line 917
    invoke-virtual {v1}, Landroidx/collection/j0;->isEmpty()Z

    .line 918
    .line 919
    .line 920
    move-result v1

    .line 921
    if-eqz v1, :cond_33

    .line 922
    .line 923
    if-eqz v4, :cond_33

    .line 924
    .line 925
    iget v1, v4, Ld4/i;->a:I

    .line 926
    .line 927
    invoke-static {v1}, Lw3/h0;->B(I)Ljava/lang/String;

    .line 928
    .line 929
    .line 930
    move-result-object v1

    .line 931
    if-eqz v1, :cond_33

    .line 932
    .line 933
    invoke-virtual {v0, v1}, Landroid/view/ViewStructure;->setClassName(Ljava/lang/String;)V

    .line 934
    .line 935
    .line 936
    :cond_33
    if-eqz v21, :cond_36

    .line 937
    .line 938
    const-string v1, "android.widget.EditText"

    .line 939
    .line 940
    invoke-virtual {v0, v1}, Landroid/view/ViewStructure;->setClassName(Ljava/lang/String;)V

    .line 941
    .line 942
    .line 943
    if-eqz v27, :cond_34

    .line 944
    .line 945
    invoke-virtual/range {v27 .. v27}, Ljava/lang/Number;->intValue()I

    .line 946
    .line 947
    .line 948
    move-result v1

    .line 949
    invoke-virtual {v0, v1}, Landroid/view/ViewStructure;->setMaxTextLength(I)V

    .line 950
    .line 951
    .line 952
    :cond_34
    if-eqz v5, :cond_35

    .line 953
    .line 954
    iget-object v1, v5, Lg4/g;->e:Ljava/lang/String;

    .line 955
    .line 956
    invoke-static {v1}, Landroid/view/autofill/AutofillValue;->forText(Ljava/lang/CharSequence;)Landroid/view/autofill/AutofillValue;

    .line 957
    .line 958
    .line 959
    move-result-object v1

    .line 960
    invoke-virtual {v0, v1}, Landroid/view/ViewStructure;->setAutofillValue(Landroid/view/autofill/AutofillValue;)V

    .line 961
    .line 962
    .line 963
    :cond_35
    if-eqz v2, :cond_36

    .line 964
    .line 965
    const/16 v1, 0x81

    .line 966
    .line 967
    invoke-virtual {v0, v1}, Landroid/view/ViewStructure;->setInputType(I)V

    .line 968
    .line 969
    .line 970
    :cond_36
    return-void
.end method
