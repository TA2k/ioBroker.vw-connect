.class public abstract Lk01/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lu01/i;

.field public static final b:[Ljava/lang/String;

.field public static final c:[Ljava/lang/String;

.field public static final d:[Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 13

    .line 1
    sget-object v0, Lu01/i;->g:Lu01/i;

    .line 2
    .line 3
    const-string v0, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    .line 4
    .line 5
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lk01/h;->a:Lu01/i;

    .line 10
    .line 11
    const-string v9, "WINDOW_UPDATE"

    .line 12
    .line 13
    const-string v10, "CONTINUATION"

    .line 14
    .line 15
    const-string v1, "DATA"

    .line 16
    .line 17
    const-string v2, "HEADERS"

    .line 18
    .line 19
    const-string v3, "PRIORITY"

    .line 20
    .line 21
    const-string v4, "RST_STREAM"

    .line 22
    .line 23
    const-string v5, "SETTINGS"

    .line 24
    .line 25
    const-string v6, "PUSH_PROMISE"

    .line 26
    .line 27
    const-string v7, "PING"

    .line 28
    .line 29
    const-string v8, "GOAWAY"

    .line 30
    .line 31
    filled-new-array/range {v1 .. v10}, [Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lk01/h;->b:[Ljava/lang/String;

    .line 36
    .line 37
    const/16 v0, 0x40

    .line 38
    .line 39
    new-array v0, v0, [Ljava/lang/String;

    .line 40
    .line 41
    sput-object v0, Lk01/h;->c:[Ljava/lang/String;

    .line 42
    .line 43
    const/16 v0, 0x100

    .line 44
    .line 45
    new-array v1, v0, [Ljava/lang/String;

    .line 46
    .line 47
    const/4 v2, 0x0

    .line 48
    move v3, v2

    .line 49
    :goto_0
    const/16 v4, 0x20

    .line 50
    .line 51
    if-ge v3, v0, :cond_0

    .line 52
    .line 53
    invoke-static {v3}, Ljava/lang/Integer;->toBinaryString(I)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v5

    .line 57
    const-string v6, "toBinaryString(...)"

    .line 58
    .line 59
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    const-string v6, "%8s"

    .line 67
    .line 68
    invoke-static {v6, v5}, Le01/g;->d(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    const/16 v6, 0x30

    .line 73
    .line 74
    invoke-static {v5, v4, v6}, Lly0/w;->u(Ljava/lang/String;CC)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    aput-object v4, v1, v3

    .line 79
    .line 80
    add-int/lit8 v3, v3, 0x1

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_0
    sput-object v1, Lk01/h;->d:[Ljava/lang/String;

    .line 84
    .line 85
    sget-object v0, Lk01/h;->c:[Ljava/lang/String;

    .line 86
    .line 87
    const-string v1, ""

    .line 88
    .line 89
    aput-object v1, v0, v2

    .line 90
    .line 91
    const-string v1, "END_STREAM"

    .line 92
    .line 93
    const/4 v3, 0x1

    .line 94
    aput-object v1, v0, v3

    .line 95
    .line 96
    filled-new-array {v3}, [I

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    const-string v3, "PADDED"

    .line 101
    .line 102
    const/16 v5, 0x8

    .line 103
    .line 104
    aput-object v3, v0, v5

    .line 105
    .line 106
    aget v3, v1, v2

    .line 107
    .line 108
    or-int/lit8 v6, v3, 0x8

    .line 109
    .line 110
    new-instance v7, Ljava/lang/StringBuilder;

    .line 111
    .line 112
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 113
    .line 114
    .line 115
    aget-object v3, v0, v3

    .line 116
    .line 117
    const-string v8, "|PADDED"

    .line 118
    .line 119
    invoke-static {v7, v3, v8}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v3

    .line 123
    aput-object v3, v0, v6

    .line 124
    .line 125
    const-string v3, "END_HEADERS"

    .line 126
    .line 127
    const/4 v6, 0x4

    .line 128
    aput-object v3, v0, v6

    .line 129
    .line 130
    const-string v3, "PRIORITY"

    .line 131
    .line 132
    aput-object v3, v0, v4

    .line 133
    .line 134
    const-string v3, "END_HEADERS|PRIORITY"

    .line 135
    .line 136
    const/16 v7, 0x24

    .line 137
    .line 138
    aput-object v3, v0, v7

    .line 139
    .line 140
    filled-new-array {v6, v4, v7}, [I

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    move v3, v2

    .line 145
    :goto_1
    const/4 v4, 0x3

    .line 146
    if-ge v3, v4, :cond_1

    .line 147
    .line 148
    aget v4, v0, v3

    .line 149
    .line 150
    aget v6, v1, v2

    .line 151
    .line 152
    sget-object v7, Lk01/h;->c:[Ljava/lang/String;

    .line 153
    .line 154
    or-int v9, v6, v4

    .line 155
    .line 156
    new-instance v10, Ljava/lang/StringBuilder;

    .line 157
    .line 158
    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    .line 159
    .line 160
    .line 161
    aget-object v11, v7, v6

    .line 162
    .line 163
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    const/16 v11, 0x7c

    .line 167
    .line 168
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    aget-object v12, v7, v4

    .line 172
    .line 173
    invoke-virtual {v10, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 174
    .line 175
    .line 176
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object v10

    .line 180
    aput-object v10, v7, v9

    .line 181
    .line 182
    or-int/2addr v9, v5

    .line 183
    new-instance v10, Ljava/lang/StringBuilder;

    .line 184
    .line 185
    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    .line 186
    .line 187
    .line 188
    aget-object v6, v7, v6

    .line 189
    .line 190
    invoke-virtual {v10, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    aget-object v4, v7, v4

    .line 197
    .line 198
    invoke-static {v10, v4, v8}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v4

    .line 202
    aput-object v4, v7, v9

    .line 203
    .line 204
    add-int/lit8 v3, v3, 0x1

    .line 205
    .line 206
    goto :goto_1

    .line 207
    :cond_1
    sget-object v0, Lk01/h;->c:[Ljava/lang/String;

    .line 208
    .line 209
    array-length v0, v0

    .line 210
    :goto_2
    if-ge v2, v0, :cond_3

    .line 211
    .line 212
    sget-object v1, Lk01/h;->c:[Ljava/lang/String;

    .line 213
    .line 214
    aget-object v3, v1, v2

    .line 215
    .line 216
    if-nez v3, :cond_2

    .line 217
    .line 218
    sget-object v3, Lk01/h;->d:[Ljava/lang/String;

    .line 219
    .line 220
    aget-object v3, v3, v2

    .line 221
    .line 222
    aput-object v3, v1, v2

    .line 223
    .line 224
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 225
    .line 226
    goto :goto_2

    .line 227
    :cond_3
    return-void
.end method

.method public static a(I)Ljava/lang/String;
    .locals 2

    .line 1
    sget-object v0, Lk01/h;->b:[Ljava/lang/String;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    if-ge p0, v1, :cond_0

    .line 5
    .line 6
    aget-object p0, v0, p0

    .line 7
    .line 8
    return-object p0

    .line 9
    :cond_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    const-string v0, "0x%02x"

    .line 18
    .line 19
    invoke-static {v0, p0}, Le01/g;->d(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public static b(IIIIZ)Ljava/lang/String;
    .locals 4

    .line 1
    invoke-static {p2}, Lk01/h;->a(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez p3, :cond_0

    .line 6
    .line 7
    const-string p2, ""

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_0
    const/4 v1, 0x2

    .line 11
    sget-object v2, Lk01/h;->d:[Ljava/lang/String;

    .line 12
    .line 13
    if-eq p2, v1, :cond_6

    .line 14
    .line 15
    const/4 v1, 0x3

    .line 16
    if-eq p2, v1, :cond_6

    .line 17
    .line 18
    const/4 v1, 0x4

    .line 19
    if-eq p2, v1, :cond_4

    .line 20
    .line 21
    const/4 v1, 0x6

    .line 22
    if-eq p2, v1, :cond_4

    .line 23
    .line 24
    const/4 v1, 0x7

    .line 25
    if-eq p2, v1, :cond_6

    .line 26
    .line 27
    const/16 v1, 0x8

    .line 28
    .line 29
    if-eq p2, v1, :cond_6

    .line 30
    .line 31
    sget-object v1, Lk01/h;->c:[Ljava/lang/String;

    .line 32
    .line 33
    array-length v3, v1

    .line 34
    if-ge p3, v3, :cond_1

    .line 35
    .line 36
    aget-object v1, v1, p3

    .line 37
    .line 38
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    aget-object v1, v2, p3

    .line 43
    .line 44
    :goto_0
    const/4 v2, 0x5

    .line 45
    const/4 v3, 0x0

    .line 46
    if-ne p2, v2, :cond_2

    .line 47
    .line 48
    and-int/lit8 v2, p3, 0x4

    .line 49
    .line 50
    if-eqz v2, :cond_2

    .line 51
    .line 52
    const-string p2, "HEADERS"

    .line 53
    .line 54
    const-string p3, "PUSH_PROMISE"

    .line 55
    .line 56
    invoke-static {v3, v1, p2, p3}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    goto :goto_1

    .line 61
    :cond_2
    if-nez p2, :cond_3

    .line 62
    .line 63
    and-int/lit8 p2, p3, 0x20

    .line 64
    .line 65
    if-eqz p2, :cond_3

    .line 66
    .line 67
    const-string p2, "PRIORITY"

    .line 68
    .line 69
    const-string p3, "COMPRESSED"

    .line 70
    .line 71
    invoke-static {v3, v1, p2, p3}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    goto :goto_1

    .line 76
    :cond_3
    move-object p2, v1

    .line 77
    goto :goto_1

    .line 78
    :cond_4
    const/4 p2, 0x1

    .line 79
    if-ne p3, p2, :cond_5

    .line 80
    .line 81
    const-string p2, "ACK"

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_5
    aget-object p2, v2, p3

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_6
    aget-object p2, v2, p3

    .line 88
    .line 89
    :goto_1
    if-eqz p4, :cond_7

    .line 90
    .line 91
    const-string p3, "<<"

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_7
    const-string p3, ">>"

    .line 95
    .line 96
    :goto_2
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    filled-new-array {p3, p0, p1, v0, p2}, [Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    const-string p1, "%s 0x%08x %5d %-13s %s"

    .line 109
    .line 110
    invoke-static {p1, p0}, Le01/g;->d(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0
.end method

.method public static c(JIIZ)Ljava/lang/String;
    .locals 1

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    invoke-static {v0}, Lk01/h;->a(I)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-eqz p4, :cond_0

    .line 8
    .line 9
    const-string p4, "<<"

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const-string p4, ">>"

    .line 13
    .line 14
    :goto_0
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object p3

    .line 22
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    filled-new-array {p4, p2, p3, v0, p0}, [Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    const-string p1, "%s 0x%08x %5d %-13s %d"

    .line 31
    .line 32
    invoke-static {p1, p0}, Le01/g;->d(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method
