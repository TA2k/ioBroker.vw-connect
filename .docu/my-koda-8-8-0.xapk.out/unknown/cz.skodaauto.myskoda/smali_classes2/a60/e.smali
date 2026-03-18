.class public final La60/e;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ly50/b;

.field public final i:Ly50/h;

.field public final j:Ly50/g;

.field public final k:Ly50/c;

.field public final l:Ltr0/b;

.field public final m:Lij0/a;


# direct methods
.method public constructor <init>(Ly50/b;Ly50/h;Ly50/g;Ly50/c;Ltr0/b;Lij0/a;)V
    .locals 5

    .line 1
    new-instance v0, La60/d;

    .line 2
    .line 3
    sget-object v1, Lz50/d;->d:Lz50/d;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    invoke-direct {v0, v1, v2, v3, v4}, La60/d;-><init>(Lz50/d;ZLjava/util/List;Lql0/g;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, La60/e;->h:Ly50/b;

    .line 16
    .line 17
    iput-object p2, p0, La60/e;->i:Ly50/h;

    .line 18
    .line 19
    iput-object p3, p0, La60/e;->j:Ly50/g;

    .line 20
    .line 21
    iput-object p4, p0, La60/e;->k:Ly50/c;

    .line 22
    .line 23
    iput-object p5, p0, La60/e;->l:Ltr0/b;

    .line 24
    .line 25
    iput-object p6, p0, La60/e;->m:Lij0/a;

    .line 26
    .line 27
    new-instance p1, La50/a;

    .line 28
    .line 29
    const/4 p2, 0x1

    .line 30
    invoke-direct {p1, p0, v4, p2}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 34
    .line 35
    .line 36
    new-instance p1, La10/a;

    .line 37
    .line 38
    invoke-direct {p1, p0, v4, p2}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public static final h(La60/e;Lne0/s;)V
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, La60/e;->m:Lij0/a;

    .line 6
    .line 7
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    check-cast v3, La60/d;

    .line 12
    .line 13
    instance-of v4, v1, Lne0/d;

    .line 14
    .line 15
    instance-of v5, v1, Lne0/e;

    .line 16
    .line 17
    if-eqz v5, :cond_5

    .line 18
    .line 19
    move-object v5, v1

    .line 20
    check-cast v5, Lne0/e;

    .line 21
    .line 22
    iget-object v5, v5, Lne0/e;->a:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v5, Ljava/lang/Iterable;

    .line 25
    .line 26
    new-instance v6, Ljava/util/ArrayList;

    .line 27
    .line 28
    const/16 v7, 0xa

    .line 29
    .line 30
    invoke-static {v5, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    invoke-direct {v6, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 35
    .line 36
    .line 37
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object v5

    .line 41
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result v7

    .line 45
    if-eqz v7, :cond_4

    .line 46
    .line 47
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v7

    .line 51
    check-cast v7, Lz50/a;

    .line 52
    .line 53
    new-instance v8, La60/c;

    .line 54
    .line 55
    iget v10, v7, Lz50/a;->a:I

    .line 56
    .line 57
    iget-object v9, v7, Lz50/a;->c:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v11, v7, Lz50/a;->d:Ljava/lang/String;

    .line 60
    .line 61
    iget-object v12, v7, Lz50/a;->e:Ljava/time/OffsetDateTime;

    .line 62
    .line 63
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 64
    .line 65
    .line 66
    move-result-object v13

    .line 67
    const-string v14, "now(...)"

    .line 68
    .line 69
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    const-string v14, "<this>"

    .line 73
    .line 74
    invoke-static {v12, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    const-string v14, "stringResource"

    .line 78
    .line 79
    invoke-static {v2, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    sget-object v14, Ljava/time/temporal/ChronoUnit;->DAYS:Ljava/time/temporal/ChronoUnit;

    .line 83
    .line 84
    invoke-virtual {v14, v12, v13}, Ljava/time/temporal/ChronoUnit;->between(Ljava/time/temporal/Temporal;Ljava/time/temporal/Temporal;)J

    .line 85
    .line 86
    .line 87
    move-result-wide v14

    .line 88
    move-object/from16 v16, v5

    .line 89
    .line 90
    sget-object v5, Ljava/time/temporal/ChronoUnit;->WEEKS:Ljava/time/temporal/ChronoUnit;

    .line 91
    .line 92
    move-object/from16 v17, v8

    .line 93
    .line 94
    move-object/from16 v18, v9

    .line 95
    .line 96
    invoke-virtual {v5, v12, v13}, Ljava/time/temporal/ChronoUnit;->between(Ljava/time/temporal/Temporal;Ljava/time/temporal/Temporal;)J

    .line 97
    .line 98
    .line 99
    move-result-wide v8

    .line 100
    sget-object v5, Ljava/time/temporal/ChronoUnit;->MONTHS:Ljava/time/temporal/ChronoUnit;

    .line 101
    .line 102
    move/from16 v19, v10

    .line 103
    .line 104
    move-object/from16 v20, v11

    .line 105
    .line 106
    invoke-virtual {v5, v12, v13}, Ljava/time/temporal/ChronoUnit;->between(Ljava/time/temporal/Temporal;Ljava/time/temporal/Temporal;)J

    .line 107
    .line 108
    .line 109
    move-result-wide v10

    .line 110
    sget-object v5, Ljava/time/temporal/ChronoUnit;->YEARS:Ljava/time/temporal/ChronoUnit;

    .line 111
    .line 112
    move/from16 v21, v4

    .line 113
    .line 114
    invoke-virtual {v5, v12, v13}, Ljava/time/temporal/ChronoUnit;->between(Ljava/time/temporal/Temporal;Ljava/time/temporal/Temporal;)J

    .line 115
    .line 116
    .line 117
    move-result-wide v4

    .line 118
    const-wide/16 v22, 0x0

    .line 119
    .line 120
    cmp-long v13, v4, v22

    .line 121
    .line 122
    move-object/from16 v24, v12

    .line 123
    .line 124
    const/4 v12, 0x0

    .line 125
    if-lez v13, :cond_0

    .line 126
    .line 127
    long-to-int v4, v4

    .line 128
    new-array v5, v12, [Ljava/lang/Object;

    .line 129
    .line 130
    move-object v8, v2

    .line 131
    check-cast v8, Ljj0/f;

    .line 132
    .line 133
    const v9, 0x7f100009

    .line 134
    .line 135
    .line 136
    invoke-virtual {v8, v9, v4, v5}, Ljj0/f;->a(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v4

    .line 140
    :goto_1
    move-object v12, v4

    .line 141
    goto :goto_2

    .line 142
    :cond_0
    cmp-long v4, v10, v22

    .line 143
    .line 144
    if-lez v4, :cond_1

    .line 145
    .line 146
    long-to-int v4, v10

    .line 147
    new-array v5, v12, [Ljava/lang/Object;

    .line 148
    .line 149
    move-object v8, v2

    .line 150
    check-cast v8, Ljj0/f;

    .line 151
    .line 152
    const v9, 0x7f100007

    .line 153
    .line 154
    .line 155
    invoke-virtual {v8, v9, v4, v5}, Ljj0/f;->a(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v4

    .line 159
    goto :goto_1

    .line 160
    :cond_1
    cmp-long v4, v8, v22

    .line 161
    .line 162
    if-lez v4, :cond_2

    .line 163
    .line 164
    long-to-int v4, v8

    .line 165
    new-array v5, v12, [Ljava/lang/Object;

    .line 166
    .line 167
    move-object v8, v2

    .line 168
    check-cast v8, Ljj0/f;

    .line 169
    .line 170
    const v9, 0x7f100008

    .line 171
    .line 172
    .line 173
    invoke-virtual {v8, v9, v4, v5}, Ljj0/f;->a(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v4

    .line 177
    goto :goto_1

    .line 178
    :cond_2
    cmp-long v4, v14, v22

    .line 179
    .line 180
    if-lez v4, :cond_3

    .line 181
    .line 182
    long-to-int v4, v14

    .line 183
    new-array v5, v12, [Ljava/lang/Object;

    .line 184
    .line 185
    move-object v8, v2

    .line 186
    check-cast v8, Ljj0/f;

    .line 187
    .line 188
    const v9, 0x7f100006

    .line 189
    .line 190
    .line 191
    invoke-virtual {v8, v9, v4, v5}, Ljj0/f;->a(II[Ljava/lang/Object;)Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    move-result-object v4

    .line 195
    goto :goto_1

    .line 196
    :cond_3
    invoke-static/range {v24 .. v24}, Lvo/a;->k(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object v4

    .line 200
    goto :goto_1

    .line 201
    :goto_2
    iget-object v13, v7, Lz50/a;->f:Ljava/lang/String;

    .line 202
    .line 203
    move-object/from16 v8, v17

    .line 204
    .line 205
    move-object/from16 v9, v18

    .line 206
    .line 207
    move/from16 v10, v19

    .line 208
    .line 209
    move-object/from16 v11, v20

    .line 210
    .line 211
    invoke-direct/range {v8 .. v13}, La60/c;-><init>(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-object/from16 v5, v16

    .line 218
    .line 219
    move/from16 v4, v21

    .line 220
    .line 221
    goto/16 :goto_0

    .line 222
    .line 223
    :cond_4
    move/from16 v21, v4

    .line 224
    .line 225
    goto :goto_3

    .line 226
    :cond_5
    move/from16 v21, v4

    .line 227
    .line 228
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 229
    .line 230
    :goto_3
    instance-of v4, v1, Lne0/c;

    .line 231
    .line 232
    const/4 v5, 0x0

    .line 233
    if-eqz v4, :cond_6

    .line 234
    .line 235
    check-cast v1, Lne0/c;

    .line 236
    .line 237
    goto :goto_4

    .line 238
    :cond_6
    move-object v1, v5

    .line 239
    :goto_4
    if-eqz v1, :cond_7

    .line 240
    .line 241
    invoke-static {v1, v2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 242
    .line 243
    .line 244
    move-result-object v5

    .line 245
    :cond_7
    iget-object v1, v3, La60/d;->a:Lz50/d;

    .line 246
    .line 247
    const-string v2, "selectedSubsection"

    .line 248
    .line 249
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    new-instance v2, La60/d;

    .line 253
    .line 254
    move/from16 v3, v21

    .line 255
    .line 256
    invoke-direct {v2, v1, v3, v6, v5}, La60/d;-><init>(Lz50/d;ZLjava/util/List;Lql0/g;)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 260
    .line 261
    .line 262
    return-void
.end method
