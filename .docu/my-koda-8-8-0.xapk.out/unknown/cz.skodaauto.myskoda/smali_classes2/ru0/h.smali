.class public final Lru0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lkf0/k;

.field public final b:Lhh0/a;


# direct methods
.method public constructor <init>(Lkf0/k;Lhh0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lru0/h;->a:Lkf0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lru0/h;->b:Lhh0/a;

    .line 7
    .line 8
    return-void
.end method

.method public static b(Lss0/b;Lss0/e;)Z
    .locals 1

    .line 1
    sget-object v0, Llf0/i;->i:Llf0/i;

    .line 2
    .line 3
    iget-object v0, v0, Llf0/i;->d:Ljava/util/List;

    .line 4
    .line 5
    invoke-static {p0, p1, v0}, Llp/pf;->h(Lss0/b;Lss0/e;Ljava/util/List;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lss0/l;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lru0/h;->d(Lss0/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final c(Lss0/b;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lru0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lru0/e;

    .line 7
    .line 8
    iget v1, v0, Lru0/e;->f:I

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
    iput v1, v0, Lru0/e;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lru0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lru0/e;-><init>(Lru0/h;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lru0/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lru0/e;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object p2, Lss0/e;->u:Lss0/e;

    .line 52
    .line 53
    invoke-static {p1, p2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    if-eqz p1, :cond_4

    .line 58
    .line 59
    sget-object p1, Lih0/a;->f:Lih0/a;

    .line 60
    .line 61
    iput v3, v0, Lru0/e;->f:I

    .line 62
    .line 63
    iget-object p0, p0, Lru0/h;->b:Lhh0/a;

    .line 64
    .line 65
    invoke-virtual {p0, p1, v0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    if-ne p2, v1, :cond_3

    .line 70
    .line 71
    return-object v1

    .line 72
    :cond_3
    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    .line 73
    .line 74
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    if-nez p0, :cond_4

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_4
    const/4 v3, 0x0

    .line 82
    :goto_2
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    return-object p0
.end method

.method public final d(Lss0/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lru0/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lru0/f;

    .line 7
    .line 8
    iget v1, v0, Lru0/f;->f:I

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
    iput v1, v0, Lru0/f;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lru0/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lru0/f;-><init>(Lru0/h;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lru0/f;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lru0/f;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    if-eqz p1, :cond_5

    .line 52
    .line 53
    iput v3, v0, Lru0/f;->f:I

    .line 54
    .line 55
    invoke-virtual {p0, v0}, Lru0/h;->e(Lrx0/c;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    if-ne p2, v1, :cond_3

    .line 60
    .line 61
    return-object v1

    .line 62
    :cond_3
    :goto_1
    check-cast p2, Ljava/util/List;

    .line 63
    .line 64
    if-nez p2, :cond_4

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_4
    return-object p2

    .line 68
    :cond_5
    :goto_2
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 69
    .line 70
    return-object p0
.end method

.method public final e(Lrx0/c;)Ljava/lang/Object;
    .locals 14

    .line 1
    instance-of v0, p1, Lru0/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lru0/g;

    .line 7
    .line 8
    iget v1, v0, Lru0/g;->l:I

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
    iput v1, v0, Lru0/g;->l:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lru0/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lru0/g;-><init>(Lru0/h;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lru0/g;->j:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lru0/g;->l:I

    .line 30
    .line 31
    iget-object v3, p0, Lru0/h;->b:Lhh0/a;

    .line 32
    .line 33
    const/4 v4, 0x4

    .line 34
    const/4 v5, 0x3

    .line 35
    const/4 v6, 0x2

    .line 36
    const/4 v7, 0x1

    .line 37
    const/4 v8, 0x0

    .line 38
    if-eqz v2, :cond_5

    .line 39
    .line 40
    if-eq v2, v7, :cond_4

    .line 41
    .line 42
    if-eq v2, v6, :cond_3

    .line 43
    .line 44
    if-eq v2, v5, :cond_2

    .line 45
    .line 46
    if-ne v2, v4, :cond_1

    .line 47
    .line 48
    iget p0, v0, Lru0/g;->i:I

    .line 49
    .line 50
    iget-object v1, v0, Lru0/g;->g:[Ltu0/b;

    .line 51
    .line 52
    iget-object v2, v0, Lru0/g;->f:Ltu0/b;

    .line 53
    .line 54
    iget-object v3, v0, Lru0/g;->e:[Ltu0/b;

    .line 55
    .line 56
    iget-object v0, v0, Lru0/g;->d:Lss0/b;

    .line 57
    .line 58
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto/16 :goto_11

    .line 62
    .line 63
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 64
    .line 65
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw p0

    .line 71
    :cond_2
    iget p0, v0, Lru0/g;->i:I

    .line 72
    .line 73
    iget v2, v0, Lru0/g;->h:I

    .line 74
    .line 75
    iget-object v5, v0, Lru0/g;->g:[Ltu0/b;

    .line 76
    .line 77
    iget-object v6, v0, Lru0/g;->f:Ltu0/b;

    .line 78
    .line 79
    iget-object v7, v0, Lru0/g;->e:[Ltu0/b;

    .line 80
    .line 81
    iget-object v9, v0, Lru0/g;->d:Lss0/b;

    .line 82
    .line 83
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    goto/16 :goto_c

    .line 87
    .line 88
    :cond_3
    iget v6, v0, Lru0/g;->i:I

    .line 89
    .line 90
    iget v2, v0, Lru0/g;->h:I

    .line 91
    .line 92
    iget-object v7, v0, Lru0/g;->g:[Ltu0/b;

    .line 93
    .line 94
    iget-object v9, v0, Lru0/g;->f:Ltu0/b;

    .line 95
    .line 96
    iget-object v10, v0, Lru0/g;->e:[Ltu0/b;

    .line 97
    .line 98
    iget-object v11, v0, Lru0/g;->d:Lss0/b;

    .line 99
    .line 100
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    goto/16 :goto_5

    .line 104
    .line 105
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    iput v7, v0, Lru0/g;->l:I

    .line 113
    .line 114
    iget-object p1, p0, Lru0/h;->a:Lkf0/k;

    .line 115
    .line 116
    invoke-virtual {p1, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    if-ne p1, v1, :cond_6

    .line 121
    .line 122
    goto/16 :goto_10

    .line 123
    .line 124
    :cond_6
    :goto_1
    move-object v11, p1

    .line 125
    check-cast v11, Lss0/b;

    .line 126
    .line 127
    const/16 p1, 0xe

    .line 128
    .line 129
    new-array p1, p1, [Ltu0/b;

    .line 130
    .line 131
    sget-object v2, Ltu0/b;->m:Ltu0/b;

    .line 132
    .line 133
    sget-object v9, Lss0/e;->s1:Lss0/e;

    .line 134
    .line 135
    invoke-static {v11, v9}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 136
    .line 137
    .line 138
    move-result v9

    .line 139
    if-eqz v9, :cond_7

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_7
    move-object v2, v8

    .line 143
    :goto_2
    const/4 v9, 0x0

    .line 144
    aput-object v2, p1, v9

    .line 145
    .line 146
    sget-object v2, Ltu0/b;->q:Ltu0/b;

    .line 147
    .line 148
    sget-object v10, Lss0/e;->G1:Lss0/e;

    .line 149
    .line 150
    sget-object v12, Llf0/i;->i:Llf0/i;

    .line 151
    .line 152
    iget-object v12, v12, Llf0/i;->d:Ljava/util/List;

    .line 153
    .line 154
    check-cast v12, Ljava/util/Collection;

    .line 155
    .line 156
    sget-object v13, Lss0/f;->k:Lss0/f;

    .line 157
    .line 158
    invoke-static {v12, v13}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 159
    .line 160
    .line 161
    move-result-object v12

    .line 162
    invoke-static {v11, v10, v12}, Llp/pf;->h(Lss0/b;Lss0/e;Ljava/util/List;)Z

    .line 163
    .line 164
    .line 165
    move-result v10

    .line 166
    if-eqz v10, :cond_8

    .line 167
    .line 168
    goto :goto_3

    .line 169
    :cond_8
    move-object v2, v8

    .line 170
    :goto_3
    aput-object v2, p1, v7

    .line 171
    .line 172
    sget-object v2, Ltu0/b;->k:Ltu0/b;

    .line 173
    .line 174
    iput-object v11, v0, Lru0/g;->d:Lss0/b;

    .line 175
    .line 176
    iput-object p1, v0, Lru0/g;->e:[Ltu0/b;

    .line 177
    .line 178
    iput-object v2, v0, Lru0/g;->f:Ltu0/b;

    .line 179
    .line 180
    iput-object p1, v0, Lru0/g;->g:[Ltu0/b;

    .line 181
    .line 182
    iput v9, v0, Lru0/g;->h:I

    .line 183
    .line 184
    iput v6, v0, Lru0/g;->i:I

    .line 185
    .line 186
    iput v6, v0, Lru0/g;->l:I

    .line 187
    .line 188
    sget-object v7, Lss0/e;->Z:Lss0/e;

    .line 189
    .line 190
    invoke-static {v11, v7}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 191
    .line 192
    .line 193
    move-result v7

    .line 194
    if-eqz v7, :cond_9

    .line 195
    .line 196
    sget-object v7, Lih0/a;->n:Lih0/a;

    .line 197
    .line 198
    invoke-virtual {v3, v7, v0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v7

    .line 202
    goto :goto_4

    .line 203
    :cond_9
    sget-object v7, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 204
    .line 205
    :goto_4
    if-ne v7, v1, :cond_a

    .line 206
    .line 207
    goto/16 :goto_10

    .line 208
    .line 209
    :cond_a
    move v10, v9

    .line 210
    move-object v9, v2

    .line 211
    move v2, v10

    .line 212
    move-object v10, p1

    .line 213
    move-object p1, v7

    .line 214
    move-object v7, v10

    .line 215
    :goto_5
    check-cast p1, Ljava/lang/Boolean;

    .line 216
    .line 217
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 218
    .line 219
    .line 220
    move-result p1

    .line 221
    if-eqz p1, :cond_b

    .line 222
    .line 223
    goto :goto_6

    .line 224
    :cond_b
    move-object v9, v8

    .line 225
    :goto_6
    aput-object v9, v7, v6

    .line 226
    .line 227
    sget-object p1, Ltu0/b;->n:Ltu0/b;

    .line 228
    .line 229
    sget-object v6, Lss0/e;->N:Lss0/e;

    .line 230
    .line 231
    invoke-static {v11, v6}, Lru0/h;->b(Lss0/b;Lss0/e;)Z

    .line 232
    .line 233
    .line 234
    move-result v6

    .line 235
    if-eqz v6, :cond_c

    .line 236
    .line 237
    goto :goto_7

    .line 238
    :cond_c
    move-object p1, v8

    .line 239
    :goto_7
    aput-object p1, v10, v5

    .line 240
    .line 241
    sget-object p1, Ltu0/b;->f:Ltu0/b;

    .line 242
    .line 243
    sget-object v6, Lss0/e;->s:Lss0/e;

    .line 244
    .line 245
    invoke-static {v11, v6}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 246
    .line 247
    .line 248
    move-result v6

    .line 249
    if-eqz v6, :cond_d

    .line 250
    .line 251
    goto :goto_8

    .line 252
    :cond_d
    move-object p1, v8

    .line 253
    :goto_8
    aput-object p1, v10, v4

    .line 254
    .line 255
    sget-object p1, Ltu0/b;->i:Ltu0/b;

    .line 256
    .line 257
    sget-object v6, Lss0/e;->g:Lss0/e;

    .line 258
    .line 259
    invoke-static {v11, v6}, Lru0/h;->b(Lss0/b;Lss0/e;)Z

    .line 260
    .line 261
    .line 262
    move-result v7

    .line 263
    if-eqz v7, :cond_e

    .line 264
    .line 265
    sget-object v7, Lss0/e;->h:Lss0/e;

    .line 266
    .line 267
    invoke-static {v11, v7}, Lru0/h;->b(Lss0/b;Lss0/e;)Z

    .line 268
    .line 269
    .line 270
    move-result v7

    .line 271
    if-nez v7, :cond_f

    .line 272
    .line 273
    sget-object v7, Lss0/e;->i:Lss0/e;

    .line 274
    .line 275
    invoke-static {v11, v7}, Lru0/h;->b(Lss0/b;Lss0/e;)Z

    .line 276
    .line 277
    .line 278
    move-result v7

    .line 279
    if-eqz v7, :cond_e

    .line 280
    .line 281
    goto :goto_9

    .line 282
    :cond_e
    move-object p1, v8

    .line 283
    :cond_f
    :goto_9
    const/4 v7, 0x5

    .line 284
    aput-object p1, v10, v7

    .line 285
    .line 286
    sget-object p1, Ltu0/b;->h:Ltu0/b;

    .line 287
    .line 288
    invoke-static {v11, v6}, Lru0/h;->b(Lss0/b;Lss0/e;)Z

    .line 289
    .line 290
    .line 291
    move-result v6

    .line 292
    if-eqz v6, :cond_10

    .line 293
    .line 294
    sget-object v6, Lss0/e;->h:Lss0/e;

    .line 295
    .line 296
    invoke-static {v11, v6}, Lru0/h;->b(Lss0/b;Lss0/e;)Z

    .line 297
    .line 298
    .line 299
    move-result v6

    .line 300
    if-nez v6, :cond_10

    .line 301
    .line 302
    sget-object v6, Lss0/e;->i:Lss0/e;

    .line 303
    .line 304
    invoke-static {v11, v6}, Lru0/h;->b(Lss0/b;Lss0/e;)Z

    .line 305
    .line 306
    .line 307
    move-result v6

    .line 308
    if-eqz v6, :cond_11

    .line 309
    .line 310
    :cond_10
    move-object p1, v8

    .line 311
    :cond_11
    const/4 v6, 0x6

    .line 312
    aput-object p1, v10, v6

    .line 313
    .line 314
    sget-object p1, Ltu0/b;->e:Ltu0/b;

    .line 315
    .line 316
    sget-object v6, Lss0/e;->m:Lss0/e;

    .line 317
    .line 318
    invoke-static {v11, v6}, Lru0/h;->b(Lss0/b;Lss0/e;)Z

    .line 319
    .line 320
    .line 321
    move-result v6

    .line 322
    if-eqz v6, :cond_12

    .line 323
    .line 324
    sget-object v6, Lss0/e;->n:Lss0/e;

    .line 325
    .line 326
    invoke-static {v11, v6}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 327
    .line 328
    .line 329
    move-result v6

    .line 330
    if-eqz v6, :cond_13

    .line 331
    .line 332
    sget-object v6, Lss0/e;->o:Lss0/e;

    .line 333
    .line 334
    invoke-static {v11, v6}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 335
    .line 336
    .line 337
    move-result v6

    .line 338
    if-eqz v6, :cond_13

    .line 339
    .line 340
    :cond_12
    move-object p1, v8

    .line 341
    :cond_13
    const/4 v6, 0x7

    .line 342
    aput-object p1, v10, v6

    .line 343
    .line 344
    sget-object p1, Ltu0/b;->d:Ltu0/b;

    .line 345
    .line 346
    sget-object v6, Lss0/e;->f:Lss0/e;

    .line 347
    .line 348
    invoke-static {v11, v6}, Lru0/h;->b(Lss0/b;Lss0/e;)Z

    .line 349
    .line 350
    .line 351
    move-result v6

    .line 352
    if-eqz v6, :cond_14

    .line 353
    .line 354
    goto :goto_a

    .line 355
    :cond_14
    move-object p1, v8

    .line 356
    :goto_a
    const/16 v6, 0x8

    .line 357
    .line 358
    aput-object p1, v10, v6

    .line 359
    .line 360
    sget-object p1, Ltu0/b;->j:Ltu0/b;

    .line 361
    .line 362
    sget-object v6, Lss0/e;->A:Lss0/e;

    .line 363
    .line 364
    invoke-static {v11, v6}, Lru0/h;->b(Lss0/b;Lss0/e;)Z

    .line 365
    .line 366
    .line 367
    move-result v6

    .line 368
    if-eqz v6, :cond_15

    .line 369
    .line 370
    goto :goto_b

    .line 371
    :cond_15
    move-object p1, v8

    .line 372
    :goto_b
    const/16 v6, 0x9

    .line 373
    .line 374
    aput-object p1, v10, v6

    .line 375
    .line 376
    sget-object v6, Ltu0/b;->g:Ltu0/b;

    .line 377
    .line 378
    iput-object v11, v0, Lru0/g;->d:Lss0/b;

    .line 379
    .line 380
    iput-object v10, v0, Lru0/g;->e:[Ltu0/b;

    .line 381
    .line 382
    iput-object v6, v0, Lru0/g;->f:Ltu0/b;

    .line 383
    .line 384
    iput-object v10, v0, Lru0/g;->g:[Ltu0/b;

    .line 385
    .line 386
    iput v2, v0, Lru0/g;->h:I

    .line 387
    .line 388
    const/16 p1, 0xa

    .line 389
    .line 390
    iput p1, v0, Lru0/g;->i:I

    .line 391
    .line 392
    iput v5, v0, Lru0/g;->l:I

    .line 393
    .line 394
    invoke-virtual {p0, v11, v0}, Lru0/h;->c(Lss0/b;Lrx0/c;)Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    move-result-object p0

    .line 398
    if-ne p0, v1, :cond_16

    .line 399
    .line 400
    goto :goto_10

    .line 401
    :cond_16
    move v5, p1

    .line 402
    move-object p1, p0

    .line 403
    move p0, v5

    .line 404
    move-object v5, v10

    .line 405
    move-object v7, v5

    .line 406
    move-object v9, v11

    .line 407
    :goto_c
    check-cast p1, Ljava/lang/Boolean;

    .line 408
    .line 409
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 410
    .line 411
    .line 412
    move-result p1

    .line 413
    if-eqz p1, :cond_17

    .line 414
    .line 415
    goto :goto_d

    .line 416
    :cond_17
    move-object v6, v8

    .line 417
    :goto_d
    aput-object v6, v5, p0

    .line 418
    .line 419
    sget-object p0, Ltu0/b;->p:Ltu0/b;

    .line 420
    .line 421
    sget-object p1, Lss0/e;->K1:Lss0/e;

    .line 422
    .line 423
    invoke-static {v9, p1}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 424
    .line 425
    .line 426
    move-result p1

    .line 427
    if-eqz p1, :cond_18

    .line 428
    .line 429
    goto :goto_e

    .line 430
    :cond_18
    move-object p0, v8

    .line 431
    :goto_e
    const/16 p1, 0xb

    .line 432
    .line 433
    aput-object p0, v7, p1

    .line 434
    .line 435
    sget-object p0, Ltu0/b;->l:Ltu0/b;

    .line 436
    .line 437
    iput-object v9, v0, Lru0/g;->d:Lss0/b;

    .line 438
    .line 439
    iput-object v7, v0, Lru0/g;->e:[Ltu0/b;

    .line 440
    .line 441
    iput-object p0, v0, Lru0/g;->f:Ltu0/b;

    .line 442
    .line 443
    iput-object v7, v0, Lru0/g;->g:[Ltu0/b;

    .line 444
    .line 445
    iput v2, v0, Lru0/g;->h:I

    .line 446
    .line 447
    const/16 p1, 0xc

    .line 448
    .line 449
    iput p1, v0, Lru0/g;->i:I

    .line 450
    .line 451
    iput v4, v0, Lru0/g;->l:I

    .line 452
    .line 453
    sget-object v2, Lss0/e;->L1:Lss0/e;

    .line 454
    .line 455
    invoke-static {v9, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 456
    .line 457
    .line 458
    move-result v2

    .line 459
    if-eqz v2, :cond_19

    .line 460
    .line 461
    sget-object v2, Lih0/a;->h:Lih0/a;

    .line 462
    .line 463
    invoke-virtual {v3, v2, v0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 464
    .line 465
    .line 466
    move-result-object v0

    .line 467
    goto :goto_f

    .line 468
    :cond_19
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 469
    .line 470
    :goto_f
    if-ne v0, v1, :cond_1a

    .line 471
    .line 472
    :goto_10
    return-object v1

    .line 473
    :cond_1a
    move-object v2, p0

    .line 474
    move p0, p1

    .line 475
    move-object p1, v0

    .line 476
    move-object v1, v7

    .line 477
    move-object v3, v1

    .line 478
    move-object v0, v9

    .line 479
    :goto_11
    check-cast p1, Ljava/lang/Boolean;

    .line 480
    .line 481
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 482
    .line 483
    .line 484
    move-result p1

    .line 485
    if-eqz p1, :cond_1b

    .line 486
    .line 487
    goto :goto_12

    .line 488
    :cond_1b
    move-object v2, v8

    .line 489
    :goto_12
    aput-object v2, v1, p0

    .line 490
    .line 491
    sget-object p0, Ltu0/b;->o:Ltu0/b;

    .line 492
    .line 493
    sget-object p1, Lss0/e;->y1:Lss0/e;

    .line 494
    .line 495
    invoke-static {v0, p1}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 496
    .line 497
    .line 498
    move-result p1

    .line 499
    if-eqz p1, :cond_1c

    .line 500
    .line 501
    move-object v8, p0

    .line 502
    :cond_1c
    const/16 p0, 0xd

    .line 503
    .line 504
    aput-object v8, v3, p0

    .line 505
    .line 506
    invoke-static {v3}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 507
    .line 508
    .line 509
    move-result-object p0

    .line 510
    return-object p0
.end method
