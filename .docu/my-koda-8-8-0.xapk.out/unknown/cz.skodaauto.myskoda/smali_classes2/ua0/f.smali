.class public final Lua0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lme0/b;


# instance fields
.field public final a:Lti0/a;

.field public final b:Lal0/i;


# direct methods
.method public constructor <init>(Lti0/a;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lua0/f;->a:Lti0/a;

    .line 5
    .line 6
    new-instance p1, Ltr0/e;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    const/16 v1, 0xb

    .line 10
    .line 11
    invoke-direct {p1, p0, v0, v1}, Ltr0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    new-instance v0, Lyy0/m1;

    .line 15
    .line 16
    invoke-direct {v0, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 17
    .line 18
    .line 19
    new-instance p1, Lal0/i;

    .line 20
    .line 21
    const/16 v1, 0xa

    .line 22
    .line 23
    invoke-direct {p1, v0, v1}, Lal0/i;-><init>(Lyy0/m1;I)V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Lua0/f;->b:Lal0/i;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lua0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lua0/c;

    .line 7
    .line 8
    iget v1, v0, Lua0/c;->f:I

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
    iput v1, v0, Lua0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lua0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lua0/c;-><init>(Lua0/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lua0/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lua0/c;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v3

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput v5, v0, Lua0/c;->f:I

    .line 61
    .line 62
    iget-object p0, p0, Lua0/f;->a:Lti0/a;

    .line 63
    .line 64
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-ne p1, v1, :cond_4

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_4
    :goto_1
    check-cast p1, Lua0/h;

    .line 72
    .line 73
    iput v4, v0, Lua0/c;->f:I

    .line 74
    .line 75
    iget-object p0, p1, Lua0/h;->a:Lla/u;

    .line 76
    .line 77
    new-instance p1, Lu2/d;

    .line 78
    .line 79
    const/4 v2, 0x7

    .line 80
    invoke-direct {p1, v2}, Lu2/d;-><init>(I)V

    .line 81
    .line 82
    .line 83
    const/4 v2, 0x0

    .line 84
    invoke-static {v0, p0, v2, v5, p1}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    if-ne p0, v1, :cond_5

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_5
    move-object p0, v3

    .line 92
    :goto_2
    if-ne p0, v1, :cond_6

    .line 93
    .line 94
    :goto_3
    return-object v1

    .line 95
    :cond_6
    return-object v3
.end method

.method public final b(Lxa0/a;Lrx0/c;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Lua0/d;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lua0/d;

    .line 11
    .line 12
    iget v3, v2, Lua0/d;->g:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lua0/d;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lua0/d;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lua0/d;-><init>(Lua0/f;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lua0/d;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lua0/d;->g:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x2

    .line 38
    const/4 v7, 0x1

    .line 39
    if-eqz v4, :cond_3

    .line 40
    .line 41
    if-eq v4, v7, :cond_2

    .line 42
    .line 43
    if-ne v4, v6, :cond_1

    .line 44
    .line 45
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object v5

    .line 49
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw v0

    .line 57
    :cond_2
    iget-object v0, v2, Lua0/d;->d:Lxa0/a;

    .line 58
    .line 59
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    move-object/from16 v1, p1

    .line 67
    .line 68
    iput-object v1, v2, Lua0/d;->d:Lxa0/a;

    .line 69
    .line 70
    iput v7, v2, Lua0/d;->g:I

    .line 71
    .line 72
    iget-object v0, v0, Lua0/f;->a:Lti0/a;

    .line 73
    .line 74
    invoke-interface {v0, v2}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    if-ne v0, v3, :cond_4

    .line 79
    .line 80
    goto/16 :goto_a

    .line 81
    .line 82
    :cond_4
    move-object/from16 v22, v1

    .line 83
    .line 84
    move-object v1, v0

    .line 85
    move-object/from16 v0, v22

    .line 86
    .line 87
    :goto_1
    check-cast v1, Lua0/h;

    .line 88
    .line 89
    const-string v4, "<this>"

    .line 90
    .line 91
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    iget-object v4, v0, Lxa0/a;->i:Lxa0/c;

    .line 95
    .line 96
    new-instance v8, Lua0/i;

    .line 97
    .line 98
    iget-object v10, v0, Lxa0/a;->a:Ljava/lang/String;

    .line 99
    .line 100
    iget-object v9, v0, Lxa0/a;->b:Ljava/net/URL;

    .line 101
    .line 102
    if-eqz v9, :cond_5

    .line 103
    .line 104
    invoke-virtual {v9}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v9

    .line 108
    goto :goto_2

    .line 109
    :cond_5
    const/4 v9, 0x0

    .line 110
    :goto_2
    iget-object v12, v0, Lxa0/a;->c:Ljava/lang/String;

    .line 111
    .line 112
    if-nez v12, :cond_6

    .line 113
    .line 114
    const/4 v12, 0x0

    .line 115
    :cond_6
    iget-object v13, v0, Lxa0/a;->d:Ljava/lang/Boolean;

    .line 116
    .line 117
    iget-boolean v14, v0, Lxa0/a;->g:Z

    .line 118
    .line 119
    iget-object v15, v0, Lxa0/a;->e:Lqr0/d;

    .line 120
    .line 121
    move-object/from16 p1, v12

    .line 122
    .line 123
    if-eqz v15, :cond_7

    .line 124
    .line 125
    iget-wide v11, v15, Lqr0/d;->a:D

    .line 126
    .line 127
    const-wide v15, 0x408f400000000000L    # 1000.0

    .line 128
    .line 129
    .line 130
    .line 131
    .line 132
    div-double/2addr v11, v15

    .line 133
    double-to-int v11, v11

    .line 134
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 135
    .line 136
    .line 137
    move-result-object v11

    .line 138
    move-object v15, v11

    .line 139
    goto :goto_3

    .line 140
    :cond_7
    const/4 v15, 0x0

    .line 141
    :goto_3
    iget-object v11, v0, Lxa0/a;->h:Lmy0/c;

    .line 142
    .line 143
    if-eqz v11, :cond_8

    .line 144
    .line 145
    iget-wide v11, v11, Lmy0/c;->d:J

    .line 146
    .line 147
    sget-object v7, Lmy0/e;->i:Lmy0/e;

    .line 148
    .line 149
    const-string v6, "unit"

    .line 150
    .line 151
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    invoke-static {v11, v12, v7}, Lmy0/c;->n(JLmy0/e;)J

    .line 155
    .line 156
    .line 157
    move-result-wide v16

    .line 158
    const-wide/32 v18, -0x80000000

    .line 159
    .line 160
    .line 161
    const-wide/32 v20, 0x7fffffff

    .line 162
    .line 163
    .line 164
    invoke-static/range {v16 .. v21}, Lkp/r9;->g(JJJ)J

    .line 165
    .line 166
    .line 167
    move-result-wide v6

    .line 168
    long-to-int v6, v6

    .line 169
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 170
    .line 171
    .line 172
    move-result-object v6

    .line 173
    move-object/from16 v16, v6

    .line 174
    .line 175
    goto :goto_4

    .line 176
    :cond_8
    const/16 v16, 0x0

    .line 177
    .line 178
    :goto_4
    iget-object v6, v0, Lxa0/a;->f:Lqr0/l;

    .line 179
    .line 180
    if-eqz v6, :cond_9

    .line 181
    .line 182
    iget v6, v6, Lqr0/l;->d:I

    .line 183
    .line 184
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 185
    .line 186
    .line 187
    move-result-object v6

    .line 188
    move-object/from16 v17, v6

    .line 189
    .line 190
    goto :goto_5

    .line 191
    :cond_9
    const/16 v17, 0x0

    .line 192
    .line 193
    :goto_5
    if-eqz v4, :cond_a

    .line 194
    .line 195
    iget-object v6, v4, Lxa0/c;->a:Ljava/lang/String;

    .line 196
    .line 197
    move-object/from16 v18, v6

    .line 198
    .line 199
    goto :goto_6

    .line 200
    :cond_a
    const/16 v18, 0x0

    .line 201
    .line 202
    :goto_6
    if-eqz v4, :cond_b

    .line 203
    .line 204
    iget-object v6, v4, Lxa0/c;->b:Ljava/net/URL;

    .line 205
    .line 206
    if-eqz v6, :cond_b

    .line 207
    .line 208
    invoke-virtual {v6}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 209
    .line 210
    .line 211
    move-result-object v6

    .line 212
    move-object/from16 v19, v6

    .line 213
    .line 214
    goto :goto_7

    .line 215
    :cond_b
    const/16 v19, 0x0

    .line 216
    .line 217
    :goto_7
    const/4 v6, 0x0

    .line 218
    if-eqz v4, :cond_c

    .line 219
    .line 220
    iget-boolean v4, v4, Lxa0/c;->c:Z

    .line 221
    .line 222
    move/from16 v20, v4

    .line 223
    .line 224
    goto :goto_8

    .line 225
    :cond_c
    move/from16 v20, v6

    .line 226
    .line 227
    :goto_8
    iget-object v0, v0, Lxa0/a;->j:Ljava/time/OffsetDateTime;

    .line 228
    .line 229
    move-object v11, v9

    .line 230
    const/4 v9, 0x1

    .line 231
    move-object/from16 v12, p1

    .line 232
    .line 233
    move-object/from16 v21, v0

    .line 234
    .line 235
    const/4 v0, 0x0

    .line 236
    invoke-direct/range {v8 .. v21}, Lua0/i;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;ZLjava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;ZLjava/time/OffsetDateTime;)V

    .line 237
    .line 238
    .line 239
    iput-object v0, v2, Lua0/d;->d:Lxa0/a;

    .line 240
    .line 241
    const/4 v0, 0x2

    .line 242
    iput v0, v2, Lua0/d;->g:I

    .line 243
    .line 244
    iget-object v0, v1, Lua0/h;->a:Lla/u;

    .line 245
    .line 246
    new-instance v4, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 247
    .line 248
    const/16 v7, 0xc

    .line 249
    .line 250
    invoke-direct {v4, v7, v1, v8}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 251
    .line 252
    .line 253
    const/4 v1, 0x1

    .line 254
    invoke-static {v2, v0, v6, v1, v4}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    if-ne v0, v3, :cond_d

    .line 259
    .line 260
    goto :goto_9

    .line 261
    :cond_d
    move-object v0, v5

    .line 262
    :goto_9
    if-ne v0, v3, :cond_e

    .line 263
    .line 264
    :goto_a
    return-object v3

    .line 265
    :cond_e
    return-object v5
.end method
