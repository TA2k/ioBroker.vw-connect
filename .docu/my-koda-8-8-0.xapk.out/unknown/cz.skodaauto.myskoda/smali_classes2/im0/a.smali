.class public final Lim0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# static fields
.field public static final c:Ljava/nio/charset/Charset;


# instance fields
.field public final a:Lem0/m;

.field public b:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "UTF-8"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lim0/a;->c:Ljava/nio/charset/Charset;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lem0/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lim0/a;->a:Lem0/m;

    .line 5
    .line 6
    const-string p1, ""

    .line 7
    .line 8
    iput-object p1, p0, Lim0/a;->b:Ljava/lang/String;

    .line 9
    .line 10
    return-void
.end method

.method public static a(Ld01/y;)Z
    .locals 2

    .line 1
    const-string v0, "Content-Encoding"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const-string v0, "identity"

    .line 10
    .line 11
    const-string v1, "gzip"

    .line 12
    .line 13
    filled-new-array {v0, v1}, [Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sget-object v1, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 22
    .line 23
    invoke-virtual {p0, v1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    const-string v1, "toLowerCase(...)"

    .line 28
    .line 29
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-interface {v0, p0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    const/4 v0, 0x1

    .line 37
    xor-int/2addr p0, v0

    .line 38
    if-ne p0, v0, :cond_0

    .line 39
    .line 40
    return v0

    .line 41
    :cond_0
    const/4 p0, 0x0

    .line 42
    return p0
.end method

.method public static b(Lhm0/a;Ld01/k0;Lh01/p;)V
    .locals 8

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p1, Ld01/k0;->d:Ld01/r0;

    .line 7
    .line 8
    iget-object v2, p1, Ld01/k0;->c:Ld01/y;

    .line 9
    .line 10
    const/16 v3, 0xa

    .line 11
    .line 12
    if-eqz v1, :cond_4

    .line 13
    .line 14
    invoke-static {v2}, Lim0/a;->a(Ld01/y;)Z

    .line 15
    .line 16
    .line 17
    move-result v4

    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    const-string v1, "(encoded body omitted)"

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    new-instance v4, Lu01/f;

    .line 27
    .line 28
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1, v4}, Ld01/r0;->writeTo(Lu01/g;)V

    .line 32
    .line 33
    .line 34
    invoke-static {v4}, Llp/oa;->b(Lu01/f;)Z

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    if-eqz v5, :cond_3

    .line 39
    .line 40
    invoke-virtual {v1}, Ld01/r0;->contentType()Ld01/d0;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    sget-object v5, Lim0/a;->c:Ljava/nio/charset/Charset;

    .line 45
    .line 46
    if-eqz v1, :cond_2

    .line 47
    .line 48
    invoke-virtual {v1, v5}, Ld01/d0;->a(Ljava/nio/charset/Charset;)Ljava/nio/charset/Charset;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    if-nez v1, :cond_1

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_1
    move-object v5, v1

    .line 56
    :cond_2
    :goto_0
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v4, v5}, Lu01/f;->f0(Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_3
    invoke-virtual {v1}, Ld01/r0;->contentLength()J

    .line 71
    .line 72
    .line 73
    move-result-wide v4

    .line 74
    new-instance v1, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    const-string v6, "(binary "

    .line 77
    .line 78
    invoke-direct {v1, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v1, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v4, "-byte body omitted)"

    .line 85
    .line 86
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    :cond_4
    :goto_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    const-string v1, "<set-?>"

    .line 104
    .line 105
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    iput-object v0, p0, Lhm0/a;->j:Ljava/lang/String;

    .line 109
    .line 110
    new-instance v0, Ljava/lang/StringBuilder;

    .line 111
    .line 112
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v2}, Ld01/y;->iterator()Ljava/util/Iterator;

    .line 116
    .line 117
    .line 118
    move-result-object v2

    .line 119
    :goto_2
    move-object v4, v2

    .line 120
    check-cast v4, Landroidx/collection/d1;

    .line 121
    .line 122
    invoke-virtual {v4}, Landroidx/collection/d1;->hasNext()Z

    .line 123
    .line 124
    .line 125
    move-result v5

    .line 126
    if-eqz v5, :cond_6

    .line 127
    .line 128
    invoke-virtual {v4}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v4

    .line 132
    check-cast v4, Llx0/l;

    .line 133
    .line 134
    iget-object v5, v4, Llx0/l;->d:Ljava/lang/Object;

    .line 135
    .line 136
    move-object v6, v5

    .line 137
    check-cast v6, Ljava/lang/String;

    .line 138
    .line 139
    const-string v7, "Authorization"

    .line 140
    .line 141
    invoke-virtual {v7, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 142
    .line 143
    .line 144
    move-result v6

    .line 145
    if-eqz v6, :cond_5

    .line 146
    .line 147
    new-instance v4, Ljava/lang/StringBuilder;

    .line 148
    .line 149
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    const-string v5, ": ********"

    .line 156
    .line 157
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v4

    .line 164
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 165
    .line 166
    .line 167
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_5
    iget-object v4, v4, Llx0/l;->e:Ljava/lang/Object;

    .line 172
    .line 173
    new-instance v6, Ljava/lang/StringBuilder;

    .line 174
    .line 175
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    const-string v5, ": "

    .line 182
    .line 183
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    goto :goto_2

    .line 200
    :cond_6
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    iput-object v0, p0, Lhm0/a;->k:Ljava/lang/String;

    .line 208
    .line 209
    iget-object v0, p1, Ld01/k0;->b:Ljava/lang/String;

    .line 210
    .line 211
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    iput-object v0, p0, Lhm0/a;->l:Ljava/lang/String;

    .line 215
    .line 216
    if-eqz p2, :cond_7

    .line 217
    .line 218
    iget-object p2, p2, Lh01/p;->g:Ld01/i0;

    .line 219
    .line 220
    if-eqz p2, :cond_7

    .line 221
    .line 222
    iget-object p2, p2, Ld01/i0;->d:Ljava/lang/String;

    .line 223
    .line 224
    goto :goto_3

    .line 225
    :cond_7
    const-string p2, ""

    .line 226
    .line 227
    :goto_3
    iput-object p2, p0, Lhm0/a;->m:Ljava/lang/String;

    .line 228
    .line 229
    iget-object p1, p1, Ld01/k0;->a:Ld01/a0;

    .line 230
    .line 231
    iget-object p1, p1, Ld01/a0;->i:Ljava/lang/String;

    .line 232
    .line 233
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    iput-object p1, p0, Lhm0/a;->o:Ljava/lang/String;

    .line 237
    .line 238
    return-void
.end method

.method public static c(Lhm0/a;Ld01/t0;J)V
    .locals 5

    .line 1
    iput-wide p2, p0, Lhm0/a;->h:J

    .line 2
    .line 3
    iget p2, p1, Ld01/t0;->g:I

    .line 4
    .line 5
    iput p2, p0, Lhm0/a;->e:I

    .line 6
    .line 7
    iget-object p2, p1, Ld01/t0;->f:Ljava/lang/String;

    .line 8
    .line 9
    const-string p3, "<set-?>"

    .line 10
    .line 11
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iput-object p2, p0, Lhm0/a;->g:Ljava/lang/String;

    .line 15
    .line 16
    iget-object p2, p1, Ld01/t0;->d:Ld01/k0;

    .line 17
    .line 18
    iget-object p2, p2, Ld01/k0;->a:Ld01/a0;

    .line 19
    .line 20
    iget-object p2, p2, Ld01/a0;->i:Ljava/lang/String;

    .line 21
    .line 22
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iput-object p2, p0, Lhm0/a;->i:Ljava/lang/String;

    .line 26
    .line 27
    iget-object p2, p1, Ld01/t0;->i:Ld01/y;

    .line 28
    .line 29
    invoke-virtual {p2}, Ld01/y;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-static {v0, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    iput-object v0, p0, Lhm0/a;->f:Ljava/lang/String;

    .line 37
    .line 38
    new-instance v0, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 41
    .line 42
    .line 43
    invoke-static {p1}, Li01/e;->a(Ld01/t0;)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_5

    .line 48
    .line 49
    invoke-static {p2}, Lim0/a;->a(Ld01/y;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-eqz v1, :cond_0

    .line 54
    .line 55
    const-string p1, "(encoded body omitted)"

    .line 56
    .line 57
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    goto/16 :goto_2

    .line 61
    .line 62
    :cond_0
    iget-object p1, p1, Ld01/t0;->j:Ld01/v0;

    .line 63
    .line 64
    invoke-virtual {p1}, Ld01/v0;->p0()Lu01/h;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    const-wide v2, 0x7fffffffffffffffL

    .line 69
    .line 70
    .line 71
    .line 72
    .line 73
    invoke-interface {v1, v2, v3}, Lu01/h;->c(J)Z

    .line 74
    .line 75
    .line 76
    const-string v2, "Content-Encoding"

    .line 77
    .line 78
    invoke-virtual {p2, v2}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    const-string v2, "gzip"

    .line 83
    .line 84
    invoke-virtual {v2, p2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    if-eqz p2, :cond_1

    .line 89
    .line 90
    new-instance p2, Lu01/f;

    .line 91
    .line 92
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 93
    .line 94
    .line 95
    new-instance v2, Lu01/p;

    .line 96
    .line 97
    invoke-interface {v1}, Lu01/h;->n()Lu01/f;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    invoke-virtual {v1}, Lu01/f;->b()Lu01/f;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    invoke-direct {v2, v1}, Lu01/p;-><init>(Lu01/h;)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {p2, v2}, Lu01/f;->P(Lu01/h0;)J

    .line 109
    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_1
    invoke-interface {v1}, Lu01/h;->n()Lu01/f;

    .line 113
    .line 114
    .line 115
    move-result-object p2

    .line 116
    :goto_0
    invoke-static {p2}, Llp/oa;->b(Lu01/f;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-eqz v1, :cond_4

    .line 121
    .line 122
    invoke-virtual {p1}, Ld01/v0;->b()J

    .line 123
    .line 124
    .line 125
    move-result-wide v1

    .line 126
    const-wide/16 v3, 0x0

    .line 127
    .line 128
    cmp-long v1, v1, v3

    .line 129
    .line 130
    if-eqz v1, :cond_4

    .line 131
    .line 132
    invoke-virtual {p2}, Lu01/f;->b()Lu01/f;

    .line 133
    .line 134
    .line 135
    move-result-object p2

    .line 136
    invoke-virtual {p1}, Ld01/v0;->d()Ld01/d0;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    sget-object v1, Lim0/a;->c:Ljava/nio/charset/Charset;

    .line 141
    .line 142
    if-eqz p1, :cond_3

    .line 143
    .line 144
    invoke-virtual {p1, v1}, Ld01/d0;->a(Ljava/nio/charset/Charset;)Ljava/nio/charset/Charset;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    if-nez p1, :cond_2

    .line 149
    .line 150
    goto :goto_1

    .line 151
    :cond_2
    move-object v1, p1

    .line 152
    :cond_3
    :goto_1
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {p2, v1}, Lu01/f;->f0(Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    goto :goto_2

    .line 163
    :cond_4
    iget-wide p1, p2, Lu01/f;->e:J

    .line 164
    .line 165
    new-instance v1, Ljava/lang/StringBuilder;

    .line 166
    .line 167
    const-string v2, "(binary "

    .line 168
    .line 169
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v1, p1, p2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    const-string p1, "-byte body omitted)"

    .line 176
    .line 177
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 185
    .line 186
    .line 187
    :cond_5
    :goto_2
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object p1

    .line 191
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    iput-object p1, p0, Lhm0/a;->d:Ljava/lang/String;

    .line 195
    .line 196
    return-void
.end method


# virtual methods
.method public final intercept(Ld01/b0;)Ld01/t0;
    .locals 8

    .line 1
    new-instance v0, Lhm0/a;

    .line 2
    .line 3
    iget-object v1, p0, Lim0/a;->b:Ljava/lang/String;

    .line 4
    .line 5
    sget-object v2, Lhm0/d;->g:Lhm0/d;

    .line 6
    .line 7
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 8
    .line 9
    .line 10
    move-result-wide v3

    .line 11
    const-string v5, "serviceLabel"

    .line 12
    .line 13
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object v1, v0, Lhm0/a;->a:Ljava/lang/String;

    .line 20
    .line 21
    const-string v1, ""

    .line 22
    .line 23
    iput-object v1, v0, Lhm0/a;->b:Ljava/lang/String;

    .line 24
    .line 25
    const-wide/16 v5, -0x1

    .line 26
    .line 27
    iput-wide v5, v0, Lhm0/a;->c:J

    .line 28
    .line 29
    iput-object v1, v0, Lhm0/a;->d:Ljava/lang/String;

    .line 30
    .line 31
    const/4 v5, 0x0

    .line 32
    iput v5, v0, Lhm0/a;->e:I

    .line 33
    .line 34
    iput-object v1, v0, Lhm0/a;->f:Ljava/lang/String;

    .line 35
    .line 36
    iput-object v1, v0, Lhm0/a;->g:Ljava/lang/String;

    .line 37
    .line 38
    const-wide/16 v5, 0x0

    .line 39
    .line 40
    iput-wide v5, v0, Lhm0/a;->h:J

    .line 41
    .line 42
    iput-object v1, v0, Lhm0/a;->i:Ljava/lang/String;

    .line 43
    .line 44
    iput-object v1, v0, Lhm0/a;->j:Ljava/lang/String;

    .line 45
    .line 46
    iput-object v1, v0, Lhm0/a;->k:Ljava/lang/String;

    .line 47
    .line 48
    iput-object v1, v0, Lhm0/a;->l:Ljava/lang/String;

    .line 49
    .line 50
    iput-object v1, v0, Lhm0/a;->m:Ljava/lang/String;

    .line 51
    .line 52
    iput-object v2, v0, Lhm0/a;->n:Lhm0/d;

    .line 53
    .line 54
    iput-object v1, v0, Lhm0/a;->o:Ljava/lang/String;

    .line 55
    .line 56
    iput-wide v3, v0, Lhm0/a;->p:J

    .line 57
    .line 58
    const/4 v1, 0x3

    .line 59
    const/4 v2, 0x0

    .line 60
    :try_start_0
    move-object v3, p1

    .line 61
    check-cast v3, Li01/f;

    .line 62
    .line 63
    iget-object v3, v3, Li01/f;->e:Ld01/k0;

    .line 64
    .line 65
    check-cast p1, Li01/f;

    .line 66
    .line 67
    iget-object v4, p1, Li01/f;->d:Lh01/g;

    .line 68
    .line 69
    if-eqz v4, :cond_0

    .line 70
    .line 71
    invoke-virtual {v4}, Lh01/g;->c()Lh01/p;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    goto :goto_0

    .line 76
    :cond_0
    move-object v4, v2

    .line 77
    :goto_0
    invoke-static {v0, v3, v4}, Lim0/a;->b(Lhm0/a;Ld01/k0;Lh01/p;)V

    .line 78
    .line 79
    .line 80
    sget-object v4, Lhm0/d;->d:Lhm0/d;

    .line 81
    .line 82
    iput-object v4, v0, Lhm0/a;->n:Lhm0/d;

    .line 83
    .line 84
    new-instance v4, Lg1/y2;

    .line 85
    .line 86
    const/16 v5, 0x1a

    .line 87
    .line 88
    invoke-direct {v4, v5, v0, p0, v2}, Lg1/y2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 89
    .line 90
    .line 91
    invoke-static {v4}, Lvy0/e0;->L(Lay0/n;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 95
    .line 96
    .line 97
    move-result-wide v4

    .line 98
    invoke-virtual {p1, v3}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    sget-object v3, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 103
    .line 104
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 105
    .line 106
    .line 107
    move-result-wide v6

    .line 108
    sub-long/2addr v6, v4

    .line 109
    invoke-virtual {v3, v6, v7}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 110
    .line 111
    .line 112
    move-result-wide v3

    .line 113
    invoke-static {v0, p1, v3, v4}, Lim0/a;->c(Lhm0/a;Ld01/t0;J)V

    .line 114
    .line 115
    .line 116
    iget v3, p1, Ld01/t0;->g:I

    .line 117
    .line 118
    const/16 v4, 0x12c

    .line 119
    .line 120
    if-ge v3, v4, :cond_1

    .line 121
    .line 122
    sget-object v3, Lhm0/d;->e:Lhm0/d;

    .line 123
    .line 124
    iput-object v3, v0, Lhm0/a;->n:Lhm0/d;

    .line 125
    .line 126
    goto :goto_1

    .line 127
    :catchall_0
    move-exception p1

    .line 128
    goto :goto_3

    .line 129
    :catch_0
    move-exception p1

    .line 130
    goto :goto_2

    .line 131
    :cond_1
    const/16 v4, 0x190

    .line 132
    .line 133
    if-lt v3, v4, :cond_2

    .line 134
    .line 135
    sget-object v3, Lhm0/d;->f:Lhm0/d;

    .line 136
    .line 137
    iput-object v3, v0, Lhm0/a;->n:Lhm0/d;
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 138
    .line 139
    :cond_2
    :goto_1
    sget-object v3, Lge0/a;->d:Lge0/a;

    .line 140
    .line 141
    new-instance v4, Lif0/d0;

    .line 142
    .line 143
    const/4 v5, 0x4

    .line 144
    invoke-direct {v4, v5, p0, v0, v2}, Lif0/d0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 145
    .line 146
    .line 147
    invoke-static {v3, v2, v2, v4, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 148
    .line 149
    .line 150
    return-object p1

    .line 151
    :goto_2
    :try_start_1
    invoke-static {p1}, Loa0/b;->b(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v3

    .line 155
    iput-object v3, v0, Lhm0/a;->b:Ljava/lang/String;

    .line 156
    .line 157
    sget-object v3, Lhm0/d;->f:Lhm0/d;

    .line 158
    .line 159
    iput-object v3, v0, Lhm0/a;->n:Lhm0/d;

    .line 160
    .line 161
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 162
    :goto_3
    sget-object v3, Lge0/a;->d:Lge0/a;

    .line 163
    .line 164
    new-instance v4, Lif0/d0;

    .line 165
    .line 166
    const/4 v5, 0x4

    .line 167
    invoke-direct {v4, v5, p0, v0, v2}, Lif0/d0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 168
    .line 169
    .line 170
    invoke-static {v3, v2, v2, v4, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 171
    .line 172
    .line 173
    throw p1
.end method
