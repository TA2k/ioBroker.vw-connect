.class public final Lw80/e;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lkc0/h0;

.field public final j:Lq80/k;

.field public final k:Lij0/a;

.field public final l:Lcr0/g;

.field public final m:Lcr0/e;

.field public final n:Lcr0/a;


# direct methods
.method public constructor <init>(Ltr0/b;Lkc0/h0;Lq80/k;Lv80/a;Lij0/a;Lcr0/g;Lcr0/e;Lcr0/a;)V
    .locals 14

    .line 1
    new-instance v0, Lw80/d;

    .line 2
    .line 3
    const/4 v7, 0x0

    .line 4
    const/4 v10, 0x0

    .line 5
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    const/4 v5, 0x0

    .line 10
    const/4 v8, 0x0

    .line 11
    const/4 v9, 0x0

    .line 12
    const/4 v11, 0x0

    .line 13
    move-object v3, v1

    .line 14
    move-object v6, v1

    .line 15
    invoke-direct/range {v0 .. v11}, Lw80/d;-><init>(Ljava/util/List;Lw80/b;Ljava/util/List;ZILjava/util/List;ZLjava/lang/String;Ljava/lang/String;ZLql0/g;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lw80/e;->h:Ltr0/b;

    .line 22
    .line 23
    move-object/from16 v0, p2

    .line 24
    .line 25
    iput-object v0, p0, Lw80/e;->i:Lkc0/h0;

    .line 26
    .line 27
    move-object/from16 v0, p3

    .line 28
    .line 29
    iput-object v0, p0, Lw80/e;->j:Lq80/k;

    .line 30
    .line 31
    move-object/from16 v0, p5

    .line 32
    .line 33
    iput-object v0, p0, Lw80/e;->k:Lij0/a;

    .line 34
    .line 35
    move-object/from16 v0, p6

    .line 36
    .line 37
    iput-object v0, p0, Lw80/e;->l:Lcr0/g;

    .line 38
    .line 39
    move-object/from16 v0, p7

    .line 40
    .line 41
    iput-object v0, p0, Lw80/e;->m:Lcr0/e;

    .line 42
    .line 43
    move-object/from16 v0, p8

    .line 44
    .line 45
    iput-object v0, p0, Lw80/e;->n:Lcr0/a;

    .line 46
    .line 47
    invoke-virtual/range {p4 .. p4}, Lv80/a;->invoke()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    move-object v2, v0

    .line 52
    check-cast v2, Ljava/util/List;

    .line 53
    .line 54
    move-object v0, v2

    .line 55
    check-cast v0, Ljava/lang/Iterable;

    .line 56
    .line 57
    new-instance v1, Ljava/util/ArrayList;

    .line 58
    .line 59
    const/16 v3, 0xa

    .line 60
    .line 61
    invoke-static {v0, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    invoke-direct {v1, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 66
    .line 67
    .line 68
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    if-eqz v4, :cond_0

    .line 77
    .line 78
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    check-cast v4, Ler0/c;

    .line 83
    .line 84
    iget-object v4, v4, Ler0/c;->i:Ler0/j;

    .line 85
    .line 86
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 95
    .line 96
    .line 97
    move-result v4

    .line 98
    const/4 v5, 0x0

    .line 99
    if-eqz v4, :cond_2

    .line 100
    .line 101
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v4

    .line 105
    move-object v6, v4

    .line 106
    check-cast v6, Ler0/j;

    .line 107
    .line 108
    iget-boolean v6, v6, Ler0/j;->c:Z

    .line 109
    .line 110
    if-eqz v6, :cond_1

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_2
    move-object v4, v5

    .line 114
    :goto_1
    check-cast v4, Ler0/j;

    .line 115
    .line 116
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    check-cast v0, Lw80/d;

    .line 121
    .line 122
    new-instance v7, Ljava/util/ArrayList;

    .line 123
    .line 124
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 125
    .line 126
    .line 127
    move-result v3

    .line 128
    invoke-direct {v7, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    if-eqz v3, :cond_3

    .line 140
    .line 141
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    check-cast v3, Ler0/j;

    .line 146
    .line 147
    iget-object v6, p0, Lw80/e;->k:Lij0/a;

    .line 148
    .line 149
    invoke-static {v3, v6}, Llp/cd;->b(Ler0/j;Lij0/a;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    invoke-virtual {v7, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 154
    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_3
    const-string v1, "stringResource"

    .line 158
    .line 159
    if-eqz v4, :cond_4

    .line 160
    .line 161
    iget-object v3, p0, Lw80/e;->k:Lij0/a;

    .line 162
    .line 163
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    invoke-static {v4, v3}, Llp/cd;->a(Ler0/j;Lij0/a;)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v6

    .line 170
    filled-new-array {v6}, [Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v6

    .line 174
    check-cast v3, Ljj0/f;

    .line 175
    .line 176
    const v8, 0x7f121272

    .line 177
    .line 178
    .line 179
    invoke-virtual {v3, v8, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object v3

    .line 183
    move-object v9, v3

    .line 184
    goto :goto_3

    .line 185
    :cond_4
    move-object v9, v5

    .line 186
    :goto_3
    if-eqz v4, :cond_5

    .line 187
    .line 188
    iget-object v3, p0, Lw80/e;->k:Lij0/a;

    .line 189
    .line 190
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    invoke-static {v4, v3}, Llp/cd;->a(Ler0/j;Lij0/a;)Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object v1

    .line 197
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    check-cast v3, Ljj0/f;

    .line 202
    .line 203
    const v4, 0x7f121282

    .line 204
    .line 205
    .line 206
    invoke-virtual {v3, v4, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v5

    .line 210
    :cond_5
    move-object v10, v5

    .line 211
    const/4 v12, 0x0

    .line 212
    const/16 v13, 0x65e

    .line 213
    .line 214
    const/4 v3, 0x0

    .line 215
    const/4 v4, 0x0

    .line 216
    const/4 v5, 0x0

    .line 217
    const/4 v6, 0x0

    .line 218
    const/4 v8, 0x0

    .line 219
    const/4 v11, 0x0

    .line 220
    move-object v1, v0

    .line 221
    invoke-static/range {v1 .. v13}, Lw80/d;->a(Lw80/d;Ljava/util/List;Lw80/b;Ljava/util/List;ZILjava/util/ArrayList;ZLjava/lang/String;Ljava/lang/String;ZLql0/g;I)Lw80/d;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 226
    .line 227
    .line 228
    check-cast v2, Ljava/util/Collection;

    .line 229
    .line 230
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 231
    .line 232
    .line 233
    move-result v0

    .line 234
    if-nez v0, :cond_6

    .line 235
    .line 236
    const/4 v0, 0x0

    .line 237
    invoke-virtual {p0, v0}, Lw80/e;->h(I)V

    .line 238
    .line 239
    .line 240
    return-void

    .line 241
    :cond_6
    iget-object p0, p0, Lw80/e;->h:Ltr0/b;

    .line 242
    .line 243
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    return-void
.end method


# virtual methods
.method public final h(I)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lw80/d;

    .line 8
    .line 9
    iget-object v1, v1, Lw80/d;->a:Ljava/util/List;

    .line 10
    .line 11
    move/from16 v7, p1

    .line 12
    .line 13
    invoke-static {v7, v1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Ler0/c;

    .line 18
    .line 19
    if-eqz v1, :cond_2

    .line 20
    .line 21
    const-string v2, "stringResource"

    .line 22
    .line 23
    iget-object v3, v0, Lw80/e;->k:Lij0/a;

    .line 24
    .line 25
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    new-instance v4, Lw80/b;

    .line 29
    .line 30
    iget-object v2, v1, Ler0/c;->k:Ljava/net/URL;

    .line 31
    .line 32
    if-eqz v2, :cond_0

    .line 33
    .line 34
    invoke-static {v2}, Ljp/sf;->h(Ljava/net/URL;)Landroid/net/Uri;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    :goto_0
    move-object v9, v2

    .line 39
    goto :goto_1

    .line 40
    :cond_0
    const/4 v2, 0x0

    .line 41
    goto :goto_0

    .line 42
    :goto_1
    iget-object v10, v1, Ler0/c;->c:Ljava/lang/String;

    .line 43
    .line 44
    iget-object v11, v1, Ler0/c;->g:Ljava/lang/String;

    .line 45
    .line 46
    iget-object v12, v1, Ler0/c;->e:Ler0/d;

    .line 47
    .line 48
    invoke-static {v12}, Llp/cd;->d(Ler0/d;)I

    .line 49
    .line 50
    .line 51
    move-result v13

    .line 52
    invoke-static {v1, v3}, Llp/cd;->e(Ler0/c;Lij0/a;)Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v14

    .line 56
    iget-object v15, v1, Ler0/c;->f:Ljava/lang/Object;

    .line 57
    .line 58
    iget-object v2, v1, Ler0/c;->b:Ljava/lang/String;

    .line 59
    .line 60
    iget-object v5, v1, Ler0/c;->h:Ler0/i;

    .line 61
    .line 62
    iget-object v1, v1, Ler0/c;->i:Ler0/j;

    .line 63
    .line 64
    new-instance v6, Lw80/c;

    .line 65
    .line 66
    iget-object v8, v1, Ler0/j;->a:Ler0/k;

    .line 67
    .line 68
    move-object/from16 v16, v2

    .line 69
    .line 70
    iget-object v2, v1, Ler0/j;->b:Ljava/lang/Integer;

    .line 71
    .line 72
    move-object/from16 v17, v4

    .line 73
    .line 74
    iget-boolean v4, v1, Ler0/j;->c:Z

    .line 75
    .line 76
    invoke-static {v1, v3}, Llp/cd;->b(Ler0/j;Lij0/a;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    invoke-direct {v6, v8, v2, v4, v1}, Lw80/c;-><init>(Ler0/k;Ljava/lang/Integer;ZLjava/lang/String;)V

    .line 81
    .line 82
    .line 83
    move-object/from16 v18, v6

    .line 84
    .line 85
    move-object/from16 v8, v17

    .line 86
    .line 87
    move-object/from16 v17, v5

    .line 88
    .line 89
    invoke-direct/range {v8 .. v18}, Lw80/b;-><init>(Landroid/net/Uri;Ljava/lang/String;Ljava/lang/String;Ler0/d;ILjava/lang/String;Ljava/util/List;Ljava/lang/String;Ler0/i;Lw80/c;)V

    .line 90
    .line 91
    .line 92
    move-object/from16 v17, v8

    .line 93
    .line 94
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    move-object v2, v1

    .line 99
    check-cast v2, Lw80/d;

    .line 100
    .line 101
    sget-object v1, Ler0/d;->i:Ler0/d;

    .line 102
    .line 103
    if-ne v12, v1, :cond_1

    .line 104
    .line 105
    const/4 v1, 0x1

    .line 106
    :goto_2
    move v6, v1

    .line 107
    goto :goto_3

    .line 108
    :cond_1
    const/4 v1, 0x0

    .line 109
    goto :goto_2

    .line 110
    :goto_3
    const/4 v13, 0x0

    .line 111
    const/16 v14, 0x7e1

    .line 112
    .line 113
    const/4 v3, 0x0

    .line 114
    sget-object v5, Lmx0/s;->d:Lmx0/s;

    .line 115
    .line 116
    const/4 v8, 0x0

    .line 117
    const/4 v9, 0x0

    .line 118
    const/4 v10, 0x0

    .line 119
    const/4 v11, 0x0

    .line 120
    const/4 v12, 0x0

    .line 121
    move-object/from16 v4, v17

    .line 122
    .line 123
    invoke-static/range {v2 .. v14}, Lw80/d;->a(Lw80/d;Ljava/util/List;Lw80/b;Ljava/util/List;ZILjava/util/ArrayList;ZLjava/lang/String;Ljava/lang/String;ZLql0/g;I)Lw80/d;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 128
    .line 129
    .line 130
    :cond_2
    return-void
.end method
