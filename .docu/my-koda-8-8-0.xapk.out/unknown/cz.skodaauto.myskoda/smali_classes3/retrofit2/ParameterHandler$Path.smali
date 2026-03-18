.class final Lretrofit2/ParameterHandler$Path;
.super Lretrofit2/ParameterHandler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lretrofit2/ParameterHandler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Path"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Lretrofit2/ParameterHandler<",
        "TT;>;"
    }
.end annotation


# instance fields
.field public final a:Ljava/lang/reflect/Method;

.field public final b:I

.field public final c:Ljava/lang/String;

.field public final d:Lretrofit2/Converter;

.field public final e:Z


# direct methods
.method public constructor <init>(Ljava/lang/reflect/Method;ILjava/lang/String;Lretrofit2/Converter;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lretrofit2/ParameterHandler;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lretrofit2/ParameterHandler$Path;->a:Ljava/lang/reflect/Method;

    .line 5
    .line 6
    iput p2, p0, Lretrofit2/ParameterHandler$Path;->b:I

    .line 7
    .line 8
    const-string p1, "name == null"

    .line 9
    .line 10
    invoke-static {p3, p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    iput-object p3, p0, Lretrofit2/ParameterHandler$Path;->c:Ljava/lang/String;

    .line 14
    .line 15
    iput-object p4, p0, Lretrofit2/ParameterHandler$Path;->d:Lretrofit2/Converter;

    .line 16
    .line 17
    iput-boolean p5, p0, Lretrofit2/ParameterHandler$Path;->e:Z

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a(Lretrofit2/RequestBuilder;Ljava/lang/Object;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    iget-object v4, v0, Lretrofit2/ParameterHandler$Path;->c:Ljava/lang/String;

    .line 9
    .line 10
    if-eqz v2, :cond_c

    .line 11
    .line 12
    iget-object v5, v0, Lretrofit2/ParameterHandler$Path;->d:Lretrofit2/Converter;

    .line 13
    .line 14
    invoke-interface {v5, v2}, Lretrofit2/Converter;->j(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    check-cast v2, Ljava/lang/String;

    .line 19
    .line 20
    iget-object v5, v1, Lretrofit2/RequestBuilder;->c:Ljava/lang/String;

    .line 21
    .line 22
    if-eqz v5, :cond_b

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 25
    .line 26
    .line 27
    move-result v5

    .line 28
    move v6, v3

    .line 29
    :goto_0
    if-ge v6, v5, :cond_9

    .line 30
    .line 31
    invoke-virtual {v2, v6}, Ljava/lang/String;->codePointAt(I)I

    .line 32
    .line 33
    .line 34
    move-result v7

    .line 35
    iget-boolean v8, v0, Lretrofit2/ParameterHandler$Path;->e:Z

    .line 36
    .line 37
    const/16 v9, 0x25

    .line 38
    .line 39
    const/16 v10, 0x2f

    .line 40
    .line 41
    const/4 v11, -0x1

    .line 42
    const-string v12, " \"<>^`{}|\\?#"

    .line 43
    .line 44
    const/16 v13, 0x7f

    .line 45
    .line 46
    const/16 v14, 0x20

    .line 47
    .line 48
    if-lt v7, v14, :cond_1

    .line 49
    .line 50
    if-ge v7, v13, :cond_1

    .line 51
    .line 52
    invoke-virtual {v12, v7}, Ljava/lang/String;->indexOf(I)I

    .line 53
    .line 54
    .line 55
    move-result v15

    .line 56
    if-ne v15, v11, :cond_1

    .line 57
    .line 58
    if-nez v8, :cond_0

    .line 59
    .line 60
    if-eq v7, v10, :cond_1

    .line 61
    .line 62
    if-ne v7, v9, :cond_0

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_0
    invoke-static {v7}, Ljava/lang/Character;->charCount(I)I

    .line 66
    .line 67
    .line 68
    move-result v7

    .line 69
    add-int/2addr v6, v7

    .line 70
    goto :goto_0

    .line 71
    :cond_1
    :goto_1
    new-instance v0, Lu01/f;

    .line 72
    .line 73
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0, v3, v6, v2}, Lu01/f;->r0(IILjava/lang/String;)V

    .line 77
    .line 78
    .line 79
    const/4 v3, 0x0

    .line 80
    :goto_2
    if-ge v6, v5, :cond_8

    .line 81
    .line 82
    invoke-virtual {v2, v6}, Ljava/lang/String;->codePointAt(I)I

    .line 83
    .line 84
    .line 85
    move-result v7

    .line 86
    if-eqz v8, :cond_2

    .line 87
    .line 88
    const/16 v15, 0x9

    .line 89
    .line 90
    if-eq v7, v15, :cond_7

    .line 91
    .line 92
    const/16 v15, 0xa

    .line 93
    .line 94
    if-eq v7, v15, :cond_7

    .line 95
    .line 96
    const/16 v15, 0xc

    .line 97
    .line 98
    if-eq v7, v15, :cond_7

    .line 99
    .line 100
    const/16 v15, 0xd

    .line 101
    .line 102
    if-ne v7, v15, :cond_2

    .line 103
    .line 104
    goto :goto_5

    .line 105
    :cond_2
    if-lt v7, v14, :cond_4

    .line 106
    .line 107
    if-ge v7, v13, :cond_4

    .line 108
    .line 109
    invoke-virtual {v12, v7}, Ljava/lang/String;->indexOf(I)I

    .line 110
    .line 111
    .line 112
    move-result v15

    .line 113
    if-ne v15, v11, :cond_4

    .line 114
    .line 115
    if-nez v8, :cond_3

    .line 116
    .line 117
    if-eq v7, v10, :cond_4

    .line 118
    .line 119
    if-ne v7, v9, :cond_3

    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_3
    invoke-virtual {v0, v7}, Lu01/f;->y0(I)V

    .line 123
    .line 124
    .line 125
    goto :goto_5

    .line 126
    :cond_4
    :goto_3
    if-nez v3, :cond_5

    .line 127
    .line 128
    new-instance v3, Lu01/f;

    .line 129
    .line 130
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 131
    .line 132
    .line 133
    :cond_5
    invoke-virtual {v3, v7}, Lu01/f;->y0(I)V

    .line 134
    .line 135
    .line 136
    iget-wide v10, v3, Lu01/f;->e:J

    .line 137
    .line 138
    const-wide/16 v16, 0x0

    .line 139
    .line 140
    move-wide/from16 v13, v16

    .line 141
    .line 142
    :goto_4
    cmp-long v16, v13, v10

    .line 143
    .line 144
    if-gez v16, :cond_6

    .line 145
    .line 146
    invoke-virtual {v3, v13, v14}, Lu01/f;->h(J)B

    .line 147
    .line 148
    .line 149
    move-result v15

    .line 150
    move-object/from16 v16, v3

    .line 151
    .line 152
    and-int/lit16 v3, v15, 0xff

    .line 153
    .line 154
    invoke-virtual {v0, v9}, Lu01/f;->h0(I)V

    .line 155
    .line 156
    .line 157
    sget-object v17, Lretrofit2/RequestBuilder;->l:[C

    .line 158
    .line 159
    shr-int/lit8 v3, v3, 0x4

    .line 160
    .line 161
    and-int/lit8 v3, v3, 0xf

    .line 162
    .line 163
    aget-char v3, v17, v3

    .line 164
    .line 165
    invoke-virtual {v0, v3}, Lu01/f;->h0(I)V

    .line 166
    .line 167
    .line 168
    and-int/lit8 v3, v15, 0xf

    .line 169
    .line 170
    aget-char v3, v17, v3

    .line 171
    .line 172
    invoke-virtual {v0, v3}, Lu01/f;->h0(I)V

    .line 173
    .line 174
    .line 175
    const-wide/16 v18, 0x1

    .line 176
    .line 177
    add-long v13, v13, v18

    .line 178
    .line 179
    move-object/from16 v3, v16

    .line 180
    .line 181
    goto :goto_4

    .line 182
    :cond_6
    move-object/from16 v16, v3

    .line 183
    .line 184
    invoke-virtual/range {v16 .. v16}, Lu01/f;->a()V

    .line 185
    .line 186
    .line 187
    :cond_7
    :goto_5
    invoke-static {v7}, Ljava/lang/Character;->charCount(I)I

    .line 188
    .line 189
    .line 190
    move-result v7

    .line 191
    add-int/2addr v6, v7

    .line 192
    const/16 v10, 0x2f

    .line 193
    .line 194
    const/4 v11, -0x1

    .line 195
    const/16 v13, 0x7f

    .line 196
    .line 197
    const/16 v14, 0x20

    .line 198
    .line 199
    goto :goto_2

    .line 200
    :cond_8
    invoke-virtual {v0}, Lu01/f;->T()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    goto :goto_6

    .line 205
    :cond_9
    move-object v0, v2

    .line 206
    :goto_6
    iget-object v3, v1, Lretrofit2/RequestBuilder;->c:Ljava/lang/String;

    .line 207
    .line 208
    new-instance v5, Ljava/lang/StringBuilder;

    .line 209
    .line 210
    const-string v6, "{"

    .line 211
    .line 212
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 216
    .line 217
    .line 218
    const-string v4, "}"

    .line 219
    .line 220
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 221
    .line 222
    .line 223
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v4

    .line 227
    invoke-virtual {v3, v4, v0}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object v0

    .line 231
    sget-object v3, Lretrofit2/RequestBuilder;->m:Ljava/util/regex/Pattern;

    .line 232
    .line 233
    invoke-virtual {v3, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 234
    .line 235
    .line 236
    move-result-object v3

    .line 237
    invoke-virtual {v3}, Ljava/util/regex/Matcher;->matches()Z

    .line 238
    .line 239
    .line 240
    move-result v3

    .line 241
    if-nez v3, :cond_a

    .line 242
    .line 243
    iput-object v0, v1, Lretrofit2/RequestBuilder;->c:Ljava/lang/String;

    .line 244
    .line 245
    return-void

    .line 246
    :cond_a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 247
    .line 248
    const-string v1, "@Path parameters shouldn\'t perform path traversal (\'.\' or \'..\'): "

    .line 249
    .line 250
    invoke-virtual {v1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object v1

    .line 254
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    throw v0

    .line 258
    :cond_b
    new-instance v0, Ljava/lang/AssertionError;

    .line 259
    .line 260
    invoke-direct {v0}, Ljava/lang/AssertionError;-><init>()V

    .line 261
    .line 262
    .line 263
    throw v0

    .line 264
    :cond_c
    const-string v1, "Path parameter \""

    .line 265
    .line 266
    const-string v2, "\" value must not be null."

    .line 267
    .line 268
    invoke-static {v1, v4, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v1

    .line 272
    new-array v2, v3, [Ljava/lang/Object;

    .line 273
    .line 274
    iget-object v3, v0, Lretrofit2/ParameterHandler$Path;->a:Ljava/lang/reflect/Method;

    .line 275
    .line 276
    iget v0, v0, Lretrofit2/ParameterHandler$Path;->b:I

    .line 277
    .line 278
    invoke-static {v3, v0, v1, v2}, Lretrofit2/Utils;->j(Ljava/lang/reflect/Method;ILjava/lang/String;[Ljava/lang/Object;)Ljava/lang/IllegalArgumentException;

    .line 279
    .line 280
    .line 281
    move-result-object v0

    .line 282
    throw v0
.end method
