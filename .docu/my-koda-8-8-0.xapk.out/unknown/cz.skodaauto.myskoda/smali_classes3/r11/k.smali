.class public final Lr11/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/y;
.implements Lr11/w;


# static fields
.field public static final f:Ljava/util/concurrent/ConcurrentHashMap;


# instance fields
.field public final d:Ln11/b;

.field public final e:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lr11/k;->f:Ljava/util/concurrent/ConcurrentHashMap;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Ln11/b;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr11/k;->d:Ln11/b;

    .line 5
    .line 6
    iput-boolean p2, p0, Lr11/k;->e:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lr11/k;->e()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final b(Ljava/lang/StringBuilder;JLjp/u1;ILn11/f;Ljava/util/Locale;)V
    .locals 0

    .line 1
    :try_start_0
    iget-object p5, p0, Lr11/k;->d:Ln11/b;

    .line 2
    .line 3
    invoke-virtual {p5, p4}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 4
    .line 5
    .line 6
    move-result-object p4

    .line 7
    iget-boolean p0, p0, Lr11/k;->e:Z

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p4, p2, p3, p7}, Ln11/a;->d(JLjava/util/Locale;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p4, p2, p3, p7}, Ln11/a;->g(JLjava/util/Locale;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    :goto_0
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :catch_0
    const p0, 0xfffd

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public final c(Ljava/lang/StringBuilder;Lo11/b;Ljava/util/Locale;)V
    .locals 2

    .line 1
    :try_start_0
    iget-object v0, p0, Lr11/k;->d:Ln11/b;

    .line 2
    .line 3
    invoke-virtual {p2, v0}, Lo11/b;->g(Ln11/b;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    invoke-virtual {p2}, Lo11/b;->c()Ljp/u1;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {v0, v1}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iget-boolean p0, p0, Lr11/k;->e:Z

    .line 18
    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    invoke-virtual {v0, p2, p3}, Ln11/a;->e(Lo11/b;Ljava/util/Locale;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {v0, p2, p3}, Ln11/a;->h(Lo11/b;Ljava/util/Locale;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    goto :goto_0

    .line 31
    :cond_1
    const-string p0, "\ufffd"

    .line 32
    .line 33
    :goto_0
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :catch_0
    const p0, 0xfffd

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/Appendable;

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public final d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 12

    .line 1
    iget-object v0, p1, Lr11/s;->b:Ljava/util/Locale;

    .line 2
    .line 3
    sget-object v1, Lr11/k;->f:Ljava/util/concurrent/ConcurrentHashMap;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    check-cast v2, Ljava/util/Map;

    .line 10
    .line 11
    if-nez v2, :cond_0

    .line 12
    .line 13
    new-instance v2, Ljava/util/concurrent/ConcurrentHashMap;

    .line 14
    .line 15
    invoke-direct {v2}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v1, v0, v2}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    :cond_0
    iget-object p0, p0, Lr11/k;->d:Ln11/b;

    .line 22
    .line 23
    invoke-interface {v2, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, [Ljava/lang/Object;

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    if-nez v1, :cond_5

    .line 31
    .line 32
    new-instance v1, Ljava/util/concurrent/ConcurrentHashMap;

    .line 33
    .line 34
    const/16 v4, 0x20

    .line 35
    .line 36
    invoke-direct {v1, v4}, Ljava/util/concurrent/ConcurrentHashMap;-><init>(I)V

    .line 37
    .line 38
    .line 39
    sget-object v5, Ln11/f;->e:Ln11/n;

    .line 40
    .line 41
    invoke-static {v5}, Lp11/n;->Q(Ln11/f;)Lp11/n;

    .line 42
    .line 43
    .line 44
    move-result-object v5

    .line 45
    sget-object v6, Ln11/c;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 46
    .line 47
    invoke-virtual {p0, v5}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    invoke-virtual {v5}, Ln11/a;->s()Z

    .line 52
    .line 53
    .line 54
    move-result v6

    .line 55
    if-eqz v6, :cond_4

    .line 56
    .line 57
    invoke-virtual {v5}, Ln11/a;->o()I

    .line 58
    .line 59
    .line 60
    move-result v6

    .line 61
    invoke-virtual {v5}, Ln11/a;->l()I

    .line 62
    .line 63
    .line 64
    move-result v7

    .line 65
    sub-int v8, v7, v6

    .line 66
    .line 67
    if-le v8, v4, :cond_1

    .line 68
    .line 69
    not-int p0, p3

    .line 70
    return p0

    .line 71
    :cond_1
    invoke-virtual {v5, v0}, Ln11/a;->k(Ljava/util/Locale;)I

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    const-wide/16 v8, 0x0

    .line 76
    .line 77
    :goto_0
    if-gt v6, v7, :cond_2

    .line 78
    .line 79
    invoke-virtual {v5, v6, v8, v9}, Ln11/a;->v(IJ)J

    .line 80
    .line 81
    .line 82
    move-result-wide v8

    .line 83
    invoke-virtual {v5, v8, v9, v0}, Ln11/a;->d(JLjava/util/Locale;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v10

    .line 87
    sget-object v11, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 88
    .line 89
    invoke-virtual {v1, v10, v11}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v5, v8, v9, v0}, Ln11/a;->d(JLjava/util/Locale;)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v10

    .line 96
    invoke-virtual {v10, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v10

    .line 100
    invoke-virtual {v1, v10, v11}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v5, v8, v9, v0}, Ln11/a;->d(JLjava/util/Locale;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v10

    .line 107
    invoke-virtual {v10, v0}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v10

    .line 111
    invoke-virtual {v1, v10, v11}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v5, v8, v9, v0}, Ln11/a;->g(JLjava/util/Locale;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v10

    .line 118
    invoke-virtual {v1, v10, v11}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    invoke-virtual {v5, v8, v9, v0}, Ln11/a;->g(JLjava/util/Locale;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v10

    .line 125
    invoke-virtual {v10, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v10

    .line 129
    invoke-virtual {v1, v10, v11}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v5, v8, v9, v0}, Ln11/a;->g(JLjava/util/Locale;)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v10

    .line 136
    invoke-virtual {v10, v0}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v10

    .line 140
    invoke-virtual {v1, v10, v11}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    add-int/lit8 v6, v6, 0x1

    .line 144
    .line 145
    goto :goto_0

    .line 146
    :cond_2
    const-string v5, "en"

    .line 147
    .line 148
    invoke-virtual {v0}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v6

    .line 152
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v5

    .line 156
    if-eqz v5, :cond_3

    .line 157
    .line 158
    sget-object v5, Ln11/b;->h:Ln11/b;

    .line 159
    .line 160
    if-ne p0, v5, :cond_3

    .line 161
    .line 162
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 163
    .line 164
    const-string v5, "BCE"

    .line 165
    .line 166
    invoke-virtual {v1, v5, v4}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    const-string v5, "bce"

    .line 170
    .line 171
    invoke-virtual {v1, v5, v4}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    const-string v5, "CE"

    .line 175
    .line 176
    invoke-virtual {v1, v5, v4}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    const-string v5, "ce"

    .line 180
    .line 181
    invoke-virtual {v1, v5, v4}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    const/4 v4, 0x3

    .line 185
    :cond_3
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 186
    .line 187
    .line 188
    move-result-object v5

    .line 189
    filled-new-array {v1, v5}, [Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v5

    .line 193
    invoke-interface {v2, p0, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    goto :goto_1

    .line 197
    :cond_4
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 198
    .line 199
    new-instance p2, Ljava/lang/StringBuilder;

    .line 200
    .line 201
    const-string p3, "Field \'"

    .line 202
    .line 203
    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    const-string p0, "\' is not supported"

    .line 210
    .line 211
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object p0

    .line 218
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    throw p1

    .line 222
    :cond_5
    aget-object v2, v1, v3

    .line 223
    .line 224
    check-cast v2, Ljava/util/Map;

    .line 225
    .line 226
    const/4 v4, 0x1

    .line 227
    aget-object v1, v1, v4

    .line 228
    .line 229
    check-cast v1, Ljava/lang/Integer;

    .line 230
    .line 231
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 232
    .line 233
    .line 234
    move-result v4

    .line 235
    move-object v1, v2

    .line 236
    :goto_1
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 237
    .line 238
    .line 239
    move-result v2

    .line 240
    add-int/2addr v4, p3

    .line 241
    invoke-static {v2, v4}, Ljava/lang/Math;->min(II)I

    .line 242
    .line 243
    .line 244
    move-result v2

    .line 245
    :goto_2
    if-le v2, p3, :cond_7

    .line 246
    .line 247
    invoke-interface {p2, p3, v2}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 248
    .line 249
    .line 250
    move-result-object v4

    .line 251
    invoke-virtual {v4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 252
    .line 253
    .line 254
    move-result-object v4

    .line 255
    invoke-interface {v1, v4}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    move-result v5

    .line 259
    if-eqz v5, :cond_6

    .line 260
    .line 261
    invoke-virtual {p1}, Lr11/s;->c()Lr11/q;

    .line 262
    .line 263
    .line 264
    move-result-object p2

    .line 265
    iget-object p1, p1, Lr11/s;->a:Ljp/u1;

    .line 266
    .line 267
    invoke-virtual {p0, p1}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 268
    .line 269
    .line 270
    move-result-object p0

    .line 271
    iput-object p0, p2, Lr11/q;->d:Ln11/a;

    .line 272
    .line 273
    iput v3, p2, Lr11/q;->e:I

    .line 274
    .line 275
    iput-object v4, p2, Lr11/q;->f:Ljava/lang/String;

    .line 276
    .line 277
    iput-object v0, p2, Lr11/q;->g:Ljava/util/Locale;

    .line 278
    .line 279
    return v2

    .line 280
    :cond_6
    add-int/lit8 v2, v2, -0x1

    .line 281
    .line 282
    goto :goto_2

    .line 283
    :cond_7
    not-int p0, p3

    .line 284
    return p0
.end method

.method public final e()I
    .locals 0

    .line 1
    iget-boolean p0, p0, Lr11/k;->e:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x6

    .line 6
    return p0

    .line 7
    :cond_0
    const/16 p0, 0x14

    .line 8
    .line 9
    return p0
.end method
