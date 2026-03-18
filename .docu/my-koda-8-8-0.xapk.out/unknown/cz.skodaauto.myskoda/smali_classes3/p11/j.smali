.class public final Lp11/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final n:Ljava/util/concurrent/ConcurrentHashMap;


# instance fields
.field public final a:[Ljava/lang/String;

.field public final b:[Ljava/lang/String;

.field public final c:[Ljava/lang/String;

.field public final d:[Ljava/lang/String;

.field public final e:[Ljava/lang/String;

.field public final f:[Ljava/lang/String;

.field public final g:Ljava/util/TreeMap;

.field public final h:Ljava/util/TreeMap;

.field public final i:Ljava/util/TreeMap;

.field public final j:I

.field public final k:I

.field public final l:I

.field public final m:I


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
    sput-object v0, Lp11/j;->n:Ljava/util/concurrent/ConcurrentHashMap;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Ljava/util/Locale;)V
    .locals 8

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Ln11/c;->a(Ljava/util/Locale;)Ljava/text/DateFormatSymbols;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Ljava/text/DateFormatSymbols;->getEras()[Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    iput-object v1, p0, Lp11/j;->a:[Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/text/DateFormatSymbols;->getWeekdays()[Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const/16 v2, 0x8

    .line 19
    .line 20
    new-array v3, v2, [Ljava/lang/String;

    .line 21
    .line 22
    const/4 v4, 0x1

    .line 23
    move v5, v4

    .line 24
    :goto_0
    const/4 v6, 0x7

    .line 25
    if-ge v5, v2, :cond_1

    .line 26
    .line 27
    if-ge v5, v6, :cond_0

    .line 28
    .line 29
    add-int/lit8 v6, v5, 0x1

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_0
    move v6, v4

    .line 33
    :goto_1
    aget-object v6, v1, v6

    .line 34
    .line 35
    aput-object v6, v3, v5

    .line 36
    .line 37
    add-int/lit8 v5, v5, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    iput-object v3, p0, Lp11/j;->b:[Ljava/lang/String;

    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/text/DateFormatSymbols;->getShortWeekdays()[Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    new-array v3, v2, [Ljava/lang/String;

    .line 47
    .line 48
    move v5, v4

    .line 49
    :goto_2
    if-ge v5, v2, :cond_3

    .line 50
    .line 51
    if-ge v5, v6, :cond_2

    .line 52
    .line 53
    add-int/lit8 v7, v5, 0x1

    .line 54
    .line 55
    goto :goto_3

    .line 56
    :cond_2
    move v7, v4

    .line 57
    :goto_3
    aget-object v7, v1, v7

    .line 58
    .line 59
    aput-object v7, v3, v5

    .line 60
    .line 61
    add-int/lit8 v5, v5, 0x1

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_3
    iput-object v3, p0, Lp11/j;->c:[Ljava/lang/String;

    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/text/DateFormatSymbols;->getMonths()[Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    const/16 v2, 0xd

    .line 71
    .line 72
    new-array v3, v2, [Ljava/lang/String;

    .line 73
    .line 74
    move v5, v4

    .line 75
    :goto_4
    if-ge v5, v2, :cond_4

    .line 76
    .line 77
    add-int/lit8 v7, v5, -0x1

    .line 78
    .line 79
    aget-object v7, v1, v7

    .line 80
    .line 81
    aput-object v7, v3, v5

    .line 82
    .line 83
    add-int/lit8 v5, v5, 0x1

    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_4
    iput-object v3, p0, Lp11/j;->d:[Ljava/lang/String;

    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/text/DateFormatSymbols;->getShortMonths()[Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    new-array v3, v2, [Ljava/lang/String;

    .line 93
    .line 94
    move v5, v4

    .line 95
    :goto_5
    if-ge v5, v2, :cond_5

    .line 96
    .line 97
    add-int/lit8 v7, v5, -0x1

    .line 98
    .line 99
    aget-object v7, v1, v7

    .line 100
    .line 101
    aput-object v7, v3, v5

    .line 102
    .line 103
    add-int/lit8 v5, v5, 0x1

    .line 104
    .line 105
    goto :goto_5

    .line 106
    :cond_5
    iput-object v3, p0, Lp11/j;->e:[Ljava/lang/String;

    .line 107
    .line 108
    invoke-virtual {v0}, Ljava/text/DateFormatSymbols;->getAmPmStrings()[Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    iput-object v0, p0, Lp11/j;->f:[Ljava/lang/String;

    .line 113
    .line 114
    new-array v0, v2, [Ljava/lang/Integer;

    .line 115
    .line 116
    const/4 v1, 0x0

    .line 117
    move v3, v1

    .line 118
    :goto_6
    if-ge v3, v2, :cond_6

    .line 119
    .line 120
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 121
    .line 122
    .line 123
    move-result-object v5

    .line 124
    aput-object v5, v0, v3

    .line 125
    .line 126
    add-int/lit8 v3, v3, 0x1

    .line 127
    .line 128
    goto :goto_6

    .line 129
    :cond_6
    new-instance v2, Ljava/util/TreeMap;

    .line 130
    .line 131
    sget-object v3, Ljava/lang/String;->CASE_INSENSITIVE_ORDER:Ljava/util/Comparator;

    .line 132
    .line 133
    invoke-direct {v2, v3}, Ljava/util/TreeMap;-><init>(Ljava/util/Comparator;)V

    .line 134
    .line 135
    .line 136
    iput-object v2, p0, Lp11/j;->g:Ljava/util/TreeMap;

    .line 137
    .line 138
    iget-object v5, p0, Lp11/j;->a:[Ljava/lang/String;

    .line 139
    .line 140
    invoke-static {v2, v5, v0}, Lp11/j;->a(Ljava/util/TreeMap;[Ljava/lang/String;[Ljava/lang/Integer;)V

    .line 141
    .line 142
    .line 143
    const-string v5, "en"

    .line 144
    .line 145
    invoke-virtual {p1}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    invoke-virtual {v5, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    if-eqz p1, :cond_7

    .line 154
    .line 155
    const-string p1, "BCE"

    .line 156
    .line 157
    aget-object v1, v0, v1

    .line 158
    .line 159
    invoke-virtual {v2, p1, v1}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    const-string p1, "CE"

    .line 163
    .line 164
    aget-object v1, v0, v4

    .line 165
    .line 166
    invoke-virtual {v2, p1, v1}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    :cond_7
    new-instance p1, Ljava/util/TreeMap;

    .line 170
    .line 171
    invoke-direct {p1, v3}, Ljava/util/TreeMap;-><init>(Ljava/util/Comparator;)V

    .line 172
    .line 173
    .line 174
    iput-object p1, p0, Lp11/j;->h:Ljava/util/TreeMap;

    .line 175
    .line 176
    iget-object v1, p0, Lp11/j;->b:[Ljava/lang/String;

    .line 177
    .line 178
    invoke-static {p1, v1, v0}, Lp11/j;->a(Ljava/util/TreeMap;[Ljava/lang/String;[Ljava/lang/Integer;)V

    .line 179
    .line 180
    .line 181
    iget-object v1, p0, Lp11/j;->c:[Ljava/lang/String;

    .line 182
    .line 183
    invoke-static {p1, v1, v0}, Lp11/j;->a(Ljava/util/TreeMap;[Ljava/lang/String;[Ljava/lang/Integer;)V

    .line 184
    .line 185
    .line 186
    move v1, v4

    .line 187
    :goto_7
    if-gt v1, v6, :cond_8

    .line 188
    .line 189
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    invoke-virtual {v2}, Ljava/lang/String;->intern()Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    aget-object v5, v0, v1

    .line 198
    .line 199
    invoke-virtual {p1, v2, v5}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    add-int/lit8 v1, v1, 0x1

    .line 203
    .line 204
    goto :goto_7

    .line 205
    :cond_8
    new-instance p1, Ljava/util/TreeMap;

    .line 206
    .line 207
    invoke-direct {p1, v3}, Ljava/util/TreeMap;-><init>(Ljava/util/Comparator;)V

    .line 208
    .line 209
    .line 210
    iput-object p1, p0, Lp11/j;->i:Ljava/util/TreeMap;

    .line 211
    .line 212
    iget-object v1, p0, Lp11/j;->d:[Ljava/lang/String;

    .line 213
    .line 214
    invoke-static {p1, v1, v0}, Lp11/j;->a(Ljava/util/TreeMap;[Ljava/lang/String;[Ljava/lang/Integer;)V

    .line 215
    .line 216
    .line 217
    iget-object v1, p0, Lp11/j;->e:[Ljava/lang/String;

    .line 218
    .line 219
    invoke-static {p1, v1, v0}, Lp11/j;->a(Ljava/util/TreeMap;[Ljava/lang/String;[Ljava/lang/Integer;)V

    .line 220
    .line 221
    .line 222
    :goto_8
    const/16 v1, 0xc

    .line 223
    .line 224
    if-gt v4, v1, :cond_9

    .line 225
    .line 226
    invoke-static {v4}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 227
    .line 228
    .line 229
    move-result-object v1

    .line 230
    invoke-virtual {v1}, Ljava/lang/String;->intern()Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    aget-object v2, v0, v4

    .line 235
    .line 236
    invoke-virtual {p1, v1, v2}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    add-int/lit8 v4, v4, 0x1

    .line 240
    .line 241
    goto :goto_8

    .line 242
    :cond_9
    iget-object p1, p0, Lp11/j;->a:[Ljava/lang/String;

    .line 243
    .line 244
    invoke-static {p1}, Lp11/j;->c([Ljava/lang/String;)I

    .line 245
    .line 246
    .line 247
    move-result p1

    .line 248
    iput p1, p0, Lp11/j;->j:I

    .line 249
    .line 250
    iget-object p1, p0, Lp11/j;->b:[Ljava/lang/String;

    .line 251
    .line 252
    invoke-static {p1}, Lp11/j;->c([Ljava/lang/String;)I

    .line 253
    .line 254
    .line 255
    move-result p1

    .line 256
    iput p1, p0, Lp11/j;->k:I

    .line 257
    .line 258
    iget-object p1, p0, Lp11/j;->c:[Ljava/lang/String;

    .line 259
    .line 260
    invoke-static {p1}, Lp11/j;->c([Ljava/lang/String;)I

    .line 261
    .line 262
    .line 263
    iget-object p1, p0, Lp11/j;->d:[Ljava/lang/String;

    .line 264
    .line 265
    invoke-static {p1}, Lp11/j;->c([Ljava/lang/String;)I

    .line 266
    .line 267
    .line 268
    move-result p1

    .line 269
    iput p1, p0, Lp11/j;->l:I

    .line 270
    .line 271
    iget-object p1, p0, Lp11/j;->e:[Ljava/lang/String;

    .line 272
    .line 273
    invoke-static {p1}, Lp11/j;->c([Ljava/lang/String;)I

    .line 274
    .line 275
    .line 276
    iget-object p1, p0, Lp11/j;->f:[Ljava/lang/String;

    .line 277
    .line 278
    invoke-static {p1}, Lp11/j;->c([Ljava/lang/String;)I

    .line 279
    .line 280
    .line 281
    move-result p1

    .line 282
    iput p1, p0, Lp11/j;->m:I

    .line 283
    .line 284
    return-void
.end method

.method public static a(Ljava/util/TreeMap;[Ljava/lang/String;[Ljava/lang/Integer;)V
    .locals 3

    .line 1
    array-length v0, p1

    .line 2
    :cond_0
    :goto_0
    add-int/lit8 v0, v0, -0x1

    .line 3
    .line 4
    if-ltz v0, :cond_1

    .line 5
    .line 6
    aget-object v1, p1, v0

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    aget-object v2, p2, v0

    .line 11
    .line 12
    invoke-virtual {p0, v1, v2}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_1
    return-void
.end method

.method public static b(Ljava/util/Locale;)Lp11/j;
    .locals 2

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    :cond_0
    sget-object v0, Lp11/j;->n:Ljava/util/concurrent/ConcurrentHashMap;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    check-cast v1, Lp11/j;

    .line 14
    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    new-instance v1, Lp11/j;

    .line 18
    .line 19
    invoke-direct {v1, p0}, Lp11/j;-><init>(Ljava/util/Locale;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, p0, v1}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Lp11/j;

    .line 27
    .line 28
    if-eqz p0, :cond_1

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_1
    return-object v1
.end method

.method public static c([Ljava/lang/String;)I
    .locals 3

    .line 1
    array-length v0, p0

    .line 2
    const/4 v1, 0x0

    .line 3
    :cond_0
    :goto_0
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    if-ltz v0, :cond_1

    .line 6
    .line 7
    aget-object v2, p0, v0

    .line 8
    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-le v2, v1, :cond_0

    .line 16
    .line 17
    move v1, v2

    .line 18
    goto :goto_0

    .line 19
    :cond_1
    return v1
.end method
