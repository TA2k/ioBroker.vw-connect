.class public final synthetic Li2/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Li2/t;->d:I

    iput-object p2, p0, Li2/t;->e:Ljava/lang/Object;

    iput-object p3, p0, Li2/t;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio0/c;Ll2/t2;Landroidx/media3/exoplayer/ExoPlayer;)V
    .locals 0

    .line 2
    const/16 p1, 0x11

    iput p1, p0, Li2/t;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Li2/t;->e:Ljava/lang/Object;

    iput-object p3, p0, Li2/t;->f:Ljava/lang/Object;

    return-void
.end method

.method private final a()Ljava/lang/Object;
    .locals 15

    .line 1
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lc41/f;

    .line 4
    .line 5
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lk01/b0;

    .line 8
    .line 9
    new-instance v1, Lkotlin/jvm/internal/f0;

    .line 10
    .line 11
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iget-object v0, v0, Lc41/f;->f:Ljava/lang/Object;

    .line 15
    .line 16
    move-object v2, v0

    .line 17
    check-cast v2, Lk01/p;

    .line 18
    .line 19
    iget-object v3, v2, Lk01/p;->z:Lk01/y;

    .line 20
    .line 21
    monitor-enter v3

    .line 22
    :try_start_0
    monitor-enter v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 23
    :try_start_1
    iget-object v0, v2, Lk01/p;->u:Lk01/b0;

    .line 24
    .line 25
    new-instance v4, Lk01/b0;

    .line 26
    .line 27
    invoke-direct {v4}, Lk01/b0;-><init>()V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v4, v0}, Lk01/b0;->b(Lk01/b0;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v4, p0}, Lk01/b0;->b(Lk01/b0;)V

    .line 34
    .line 35
    .line 36
    iput-object v4, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 37
    .line 38
    invoke-virtual {v4}, Lk01/b0;->a()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    int-to-long v4, p0

    .line 43
    invoke-virtual {v0}, Lk01/b0;->a()I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    int-to-long v6, p0

    .line 48
    sub-long/2addr v4, v6

    .line 49
    const-wide/16 v6, 0x0

    .line 50
    .line 51
    cmp-long p0, v4, v6

    .line 52
    .line 53
    const/4 v6, 0x0

    .line 54
    if-eqz p0, :cond_1

    .line 55
    .line 56
    iget-object v0, v2, Lk01/p;->e:Ljava/util/LinkedHashMap;

    .line 57
    .line 58
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    if-eqz v0, :cond_0

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_0
    iget-object v0, v2, Lk01/p;->e:Ljava/util/LinkedHashMap;

    .line 66
    .line 67
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    new-array v7, v6, [Lk01/x;

    .line 72
    .line 73
    invoke-interface {v0, v7}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    check-cast v0, [Lk01/x;

    .line 78
    .line 79
    :goto_0
    move-object v7, v0

    .line 80
    goto :goto_2

    .line 81
    :catchall_0
    move-exception v0

    .line 82
    move-object p0, v0

    .line 83
    goto :goto_5

    .line 84
    :cond_1
    :goto_1
    const/4 v0, 0x0

    .line 85
    goto :goto_0

    .line 86
    :goto_2
    iget-object v0, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v0, Lk01/b0;

    .line 89
    .line 90
    const-string v8, "<set-?>"

    .line 91
    .line 92
    invoke-static {v0, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    iput-object v0, v2, Lk01/p;->u:Lk01/b0;

    .line 96
    .line 97
    iget-object v9, v2, Lk01/p;->m:Lg01/b;

    .line 98
    .line 99
    new-instance v0, Ljava/lang/StringBuilder;

    .line 100
    .line 101
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 102
    .line 103
    .line 104
    iget-object v8, v2, Lk01/p;->f:Ljava/lang/String;

    .line 105
    .line 106
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string v8, " onSettings"

    .line 110
    .line 111
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v10

    .line 118
    new-instance v13, Li2/t;

    .line 119
    .line 120
    const/16 v0, 0x16

    .line 121
    .line 122
    invoke-direct {v13, v0, v2, v1}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    const/4 v14, 0x6

    .line 126
    const-wide/16 v11, 0x0

    .line 127
    .line 128
    invoke-static/range {v9 .. v14}, Lg01/b;->c(Lg01/b;Ljava/lang/String;JLay0/a;I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 129
    .line 130
    .line 131
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 132
    :try_start_3
    iget-object v0, v2, Lk01/p;->z:Lk01/y;

    .line 133
    .line 134
    iget-object v1, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v1, Lk01/b0;

    .line 137
    .line 138
    invoke-virtual {v0, v1}, Lk01/y;->a(Lk01/b0;)V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 139
    .line 140
    .line 141
    goto :goto_3

    .line 142
    :catchall_1
    move-exception v0

    .line 143
    move-object p0, v0

    .line 144
    goto :goto_6

    .line 145
    :catch_0
    move-exception v0

    .line 146
    :try_start_4
    sget-object v1, Lk01/b;->g:Lk01/b;

    .line 147
    .line 148
    invoke-virtual {v2, v1, v1, v0}, Lk01/p;->a(Lk01/b;Lk01/b;Ljava/io/IOException;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 149
    .line 150
    .line 151
    :goto_3
    monitor-exit v3

    .line 152
    if-eqz v7, :cond_3

    .line 153
    .line 154
    array-length v0, v7

    .line 155
    :goto_4
    if-ge v6, v0, :cond_3

    .line 156
    .line 157
    aget-object v1, v7, v6

    .line 158
    .line 159
    monitor-enter v1

    .line 160
    :try_start_5
    iget-wide v2, v1, Lk01/x;->h:J

    .line 161
    .line 162
    add-long/2addr v2, v4

    .line 163
    iput-wide v2, v1, Lk01/x;->h:J

    .line 164
    .line 165
    if-lez p0, :cond_2

    .line 166
    .line 167
    invoke-virtual {v1}, Ljava/lang/Object;->notifyAll()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 168
    .line 169
    .line 170
    :cond_2
    monitor-exit v1

    .line 171
    add-int/lit8 v6, v6, 0x1

    .line 172
    .line 173
    goto :goto_4

    .line 174
    :catchall_2
    move-exception v0

    .line 175
    move-object p0, v0

    .line 176
    monitor-exit v1

    .line 177
    throw p0

    .line 178
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 179
    .line 180
    return-object p0

    .line 181
    :goto_5
    :try_start_6
    monitor-exit v2

    .line 182
    throw p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 183
    :goto_6
    monitor-exit v3

    .line 184
    throw p0
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Li2/t;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Landroidx/collection/r0;

    .line 11
    .line 12
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Ll2/a0;

    .line 15
    .line 16
    iget-object v1, v0, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 17
    .line 18
    iget-object v0, v0, Landroidx/collection/r0;->a:[J

    .line 19
    .line 20
    array-length v3, v0

    .line 21
    add-int/lit8 v3, v3, -0x2

    .line 22
    .line 23
    if-ltz v3, :cond_3

    .line 24
    .line 25
    move v4, v2

    .line 26
    :goto_0
    aget-wide v5, v0, v4

    .line 27
    .line 28
    not-long v7, v5

    .line 29
    const/4 v9, 0x7

    .line 30
    shl-long/2addr v7, v9

    .line 31
    and-long/2addr v7, v5

    .line 32
    const-wide v9, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    and-long/2addr v7, v9

    .line 38
    cmp-long v7, v7, v9

    .line 39
    .line 40
    if-eqz v7, :cond_2

    .line 41
    .line 42
    sub-int v7, v4, v3

    .line 43
    .line 44
    not-int v7, v7

    .line 45
    ushr-int/lit8 v7, v7, 0x1f

    .line 46
    .line 47
    const/16 v8, 0x8

    .line 48
    .line 49
    rsub-int/lit8 v7, v7, 0x8

    .line 50
    .line 51
    move v9, v2

    .line 52
    :goto_1
    if-ge v9, v7, :cond_1

    .line 53
    .line 54
    const-wide/16 v10, 0xff

    .line 55
    .line 56
    and-long/2addr v10, v5

    .line 57
    const-wide/16 v12, 0x80

    .line 58
    .line 59
    cmp-long v10, v10, v12

    .line 60
    .line 61
    if-gez v10, :cond_0

    .line 62
    .line 63
    shl-int/lit8 v10, v4, 0x3

    .line 64
    .line 65
    add-int/2addr v10, v9

    .line 66
    aget-object v10, v1, v10

    .line 67
    .line 68
    invoke-virtual {p0, v10}, Ll2/a0;->z(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    :cond_0
    shr-long/2addr v5, v8

    .line 72
    add-int/lit8 v9, v9, 0x1

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_1
    if-ne v7, v8, :cond_3

    .line 76
    .line 77
    :cond_2
    if-eq v4, v3, :cond_3

    .line 78
    .line 79
    add-int/lit8 v4, v4, 0x1

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    return-object p0

    .line 85
    :pswitch_0
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v0, Liv0/e;

    .line 88
    .line 89
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast p0, Lay0/k;

    .line 92
    .line 93
    instance-of v1, v0, Liv0/f;

    .line 94
    .line 95
    if-eqz v1, :cond_4

    .line 96
    .line 97
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 101
    .line 102
    return-object p0

    .line 103
    :pswitch_1
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v0, Lay0/k;

    .line 106
    .line 107
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast p0, Lmc/y;

    .line 110
    .line 111
    new-instance v1, Lmc/j;

    .line 112
    .line 113
    invoke-direct {v1, p0}, Lmc/j;-><init>(Lmc/y;)V

    .line 114
    .line 115
    .line 116
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 120
    .line 121
    return-object p0

    .line 122
    :pswitch_2
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v0, Lkj0/k;

    .line 125
    .line 126
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast p0, Lkj0/j;

    .line 129
    .line 130
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    invoke-interface {p0}, Lkj0/j;->getName()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    invoke-interface {p0}, Lkj0/j;->getValue()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    new-instance v2, Ljava/lang/StringBuilder;

    .line 143
    .line 144
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    const-string v0, ": name="

    .line 151
    .line 152
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    const-string v0, ", value="

    .line 159
    .line 160
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    return-object p0

    .line 171
    :pswitch_3
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 172
    .line 173
    check-cast v0, Lkj0/b;

    .line 174
    .line 175
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast p0, Landroid/os/Bundle;

    .line 178
    .line 179
    invoke-interface {v0}, Lkj0/b;->getName()Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    new-instance v1, Ljava/lang/StringBuilder;

    .line 184
    .line 185
    const-string v2, "name="

    .line 186
    .line 187
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    const-string v0, ", params="

    .line 194
    .line 195
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    return-object p0

    .line 206
    :pswitch_4
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast v0, Llc0/l;

    .line 209
    .line 210
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast p0, Ljava/net/URL;

    .line 213
    .line 214
    new-instance v1, Ljava/lang/StringBuilder;

    .line 215
    .line 216
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 217
    .line 218
    .line 219
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    const-string v0, " token auth url: "

    .line 223
    .line 224
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 225
    .line 226
    .line 227
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 228
    .line 229
    .line 230
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 231
    .line 232
    .line 233
    move-result-object p0

    .line 234
    return-object p0

    .line 235
    :pswitch_5
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast v0, Lk70/b0;

    .line 238
    .line 239
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 240
    .line 241
    check-cast p0, Ll70/h;

    .line 242
    .line 243
    iget-object v0, v0, Lk70/b0;->a:Lk70/v;

    .line 244
    .line 245
    check-cast v0, Li70/b;

    .line 246
    .line 247
    const-string v1, "fuelType"

    .line 248
    .line 249
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    invoke-virtual {v0, p0}, Li70/b;->b(Ll70/h;)Li70/a;

    .line 253
    .line 254
    .line 255
    move-result-object p0

    .line 256
    iget-object p0, p0, Li70/a;->e:Ljava/lang/Object;

    .line 257
    .line 258
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object p0

    .line 262
    check-cast p0, Lwe0/a;

    .line 263
    .line 264
    check-cast p0, Lwe0/c;

    .line 265
    .line 266
    invoke-virtual {p0}, Lwe0/c;->b()Z

    .line 267
    .line 268
    .line 269
    move-result p0

    .line 270
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 271
    .line 272
    .line 273
    move-result-object p0

    .line 274
    return-object p0

    .line 275
    :pswitch_6
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 276
    .line 277
    check-cast v0, Lk01/p;

    .line 278
    .line 279
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 280
    .line 281
    check-cast p0, Lkotlin/jvm/internal/f0;

    .line 282
    .line 283
    iget-object v1, v0, Lk01/p;->d:Lk01/n;

    .line 284
    .line 285
    iget-object p0, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 286
    .line 287
    check-cast p0, Lk01/b0;

    .line 288
    .line 289
    invoke-virtual {v1, v0, p0}, Lk01/n;->a(Lk01/p;Lk01/b0;)V

    .line 290
    .line 291
    .line 292
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 293
    .line 294
    return-object p0

    .line 295
    :pswitch_7
    invoke-direct {p0}, Li2/t;->a()Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object p0

    .line 299
    return-object p0

    .line 300
    :pswitch_8
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 301
    .line 302
    check-cast v0, Lk01/p;

    .line 303
    .line 304
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 305
    .line 306
    check-cast p0, Lk01/x;

    .line 307
    .line 308
    :try_start_0
    iget-object v1, v0, Lk01/p;->d:Lk01/n;

    .line 309
    .line 310
    invoke-virtual {v1, p0}, Lk01/n;->b(Lk01/x;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 311
    .line 312
    .line 313
    goto :goto_2

    .line 314
    :catch_0
    move-exception v1

    .line 315
    sget-object v2, Ln01/d;->a:Ln01/b;

    .line 316
    .line 317
    sget-object v2, Ln01/d;->a:Ln01/b;

    .line 318
    .line 319
    new-instance v3, Ljava/lang/StringBuilder;

    .line 320
    .line 321
    const-string v4, "Http2Connection.Listener failure for "

    .line 322
    .line 323
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    iget-object v0, v0, Lk01/p;->f:Ljava/lang/String;

    .line 327
    .line 328
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 329
    .line 330
    .line 331
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 332
    .line 333
    .line 334
    move-result-object v0

    .line 335
    const/4 v3, 0x4

    .line 336
    invoke-virtual {v2, v3, v0, v1}, Ln01/b;->c(ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 337
    .line 338
    .line 339
    :try_start_1
    sget-object v0, Lk01/b;->g:Lk01/b;

    .line 340
    .line 341
    invoke-virtual {p0, v0, v1}, Lk01/x;->d(Lk01/b;Ljava/io/IOException;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 342
    .line 343
    .line 344
    :catch_1
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 345
    .line 346
    return-object p0

    .line 347
    :pswitch_9
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 348
    .line 349
    check-cast v0, Lay0/k;

    .line 350
    .line 351
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 352
    .line 353
    check-cast p0, Lhe/a;

    .line 354
    .line 355
    new-instance v1, Lhe/e;

    .line 356
    .line 357
    iget-object p0, p0, Lhe/a;->c:Ljava/lang/String;

    .line 358
    .line 359
    invoke-direct {v1, p0}, Lhe/e;-><init>(Ljava/lang/String;)V

    .line 360
    .line 361
    .line 362
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 366
    .line 367
    return-object p0

    .line 368
    :pswitch_a
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 369
    .line 370
    check-cast v0, Ljb/b;

    .line 371
    .line 372
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 373
    .line 374
    check-cast p0, Ljb/a;

    .line 375
    .line 376
    iget-object v0, v0, Ljb/b;->a:Lh2/s;

    .line 377
    .line 378
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 379
    .line 380
    .line 381
    iget-object v1, v0, Lh2/s;->c:Ljava/lang/Object;

    .line 382
    .line 383
    monitor-enter v1

    .line 384
    :try_start_2
    iget-object v2, v0, Lh2/s;->d:Ljava/lang/Object;

    .line 385
    .line 386
    check-cast v2, Ljava/util/LinkedHashSet;

    .line 387
    .line 388
    invoke-virtual {v2, p0}, Ljava/util/AbstractCollection;->remove(Ljava/lang/Object;)Z

    .line 389
    .line 390
    .line 391
    move-result p0

    .line 392
    if-eqz p0, :cond_5

    .line 393
    .line 394
    iget-object p0, v0, Lh2/s;->d:Ljava/lang/Object;

    .line 395
    .line 396
    check-cast p0, Ljava/util/LinkedHashSet;

    .line 397
    .line 398
    invoke-virtual {p0}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 399
    .line 400
    .line 401
    move-result p0

    .line 402
    if-eqz p0, :cond_5

    .line 403
    .line 404
    invoke-virtual {v0}, Lh2/s;->e()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 405
    .line 406
    .line 407
    goto :goto_3

    .line 408
    :catchall_0
    move-exception p0

    .line 409
    goto :goto_4

    .line 410
    :cond_5
    :goto_3
    monitor-exit v1

    .line 411
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 412
    .line 413
    return-object p0

    .line 414
    :goto_4
    monitor-exit v1

    .line 415
    throw p0

    .line 416
    :pswitch_b
    sget-object v0, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 417
    .line 418
    iget-object v1, p0, Li2/t;->e:Ljava/lang/Object;

    .line 419
    .line 420
    check-cast v1, Ll2/t2;

    .line 421
    .line 422
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 423
    .line 424
    check-cast p0, Landroidx/media3/exoplayer/ExoPlayer;

    .line 425
    .line 426
    new-instance v2, Laa/a0;

    .line 427
    .line 428
    const/4 v3, 0x6

    .line 429
    invoke-direct {v2, v1, v3}, Laa/a0;-><init>(Ll2/t2;I)V

    .line 430
    .line 431
    .line 432
    invoke-static {v0, v2}, Llp/nd;->l(Ljava/lang/Object;Lay0/a;)V

    .line 433
    .line 434
    .line 435
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    move-result-object v0

    .line 439
    check-cast v0, Ljava/lang/Boolean;

    .line 440
    .line 441
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 442
    .line 443
    .line 444
    move-result v0

    .line 445
    if-eqz v0, :cond_6

    .line 446
    .line 447
    check-cast p0, Lap0/o;

    .line 448
    .line 449
    check-cast p0, La8/i0;

    .line 450
    .line 451
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 452
    .line 453
    .line 454
    const/4 v0, 0x1

    .line 455
    invoke-virtual {p0, v0, v0}, La8/i0;->I0(IZ)V

    .line 456
    .line 457
    .line 458
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 459
    .line 460
    return-object p0

    .line 461
    :pswitch_c
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 462
    .line 463
    check-cast v0, Lii/b;

    .line 464
    .line 465
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 466
    .line 467
    check-cast p0, Lii/a;

    .line 468
    .line 469
    iget-object v0, v0, Lii/b;->b:Lay0/k;

    .line 470
    .line 471
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 472
    .line 473
    .line 474
    move-result-object p0

    .line 475
    return-object p0

    .line 476
    :pswitch_d
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 477
    .line 478
    check-cast v0, Li40/j0;

    .line 479
    .line 480
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 481
    .line 482
    check-cast p0, Landroid/net/ConnectivityManager;

    .line 483
    .line 484
    sget-object v3, Lib/g;->b:Ljava/lang/Object;

    .line 485
    .line 486
    monitor-enter v3

    .line 487
    :try_start_3
    sget-object v4, Lib/g;->c:Ljava/util/LinkedHashMap;

    .line 488
    .line 489
    invoke-interface {v4, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 490
    .line 491
    .line 492
    invoke-interface {v4}, Ljava/util/Map;->isEmpty()Z

    .line 493
    .line 494
    .line 495
    move-result v0

    .line 496
    if-eqz v0, :cond_7

    .line 497
    .line 498
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 499
    .line 500
    .line 501
    move-result-object v0

    .line 502
    sget-object v4, Lib/j;->a:Ljava/lang/String;

    .line 503
    .line 504
    const-string v5, "NetworkRequestConstraintController unregister shared callback"

    .line 505
    .line 506
    invoke-virtual {v0, v4, v5}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 507
    .line 508
    .line 509
    sget-object v0, Lib/g;->a:Lib/g;

    .line 510
    .line 511
    invoke-virtual {p0, v0}, Landroid/net/ConnectivityManager;->unregisterNetworkCallback(Landroid/net/ConnectivityManager$NetworkCallback;)V

    .line 512
    .line 513
    .line 514
    sput-object v1, Lib/g;->d:Landroid/net/NetworkCapabilities;

    .line 515
    .line 516
    sput-boolean v2, Lib/g;->e:Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 517
    .line 518
    goto :goto_5

    .line 519
    :catchall_1
    move-exception p0

    .line 520
    goto :goto_6

    .line 521
    :cond_7
    :goto_5
    monitor-exit v3

    .line 522
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 523
    .line 524
    return-object p0

    .line 525
    :goto_6
    monitor-exit v3

    .line 526
    throw p0

    .line 527
    :pswitch_e
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 528
    .line 529
    check-cast v0, Li91/v3;

    .line 530
    .line 531
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 532
    .line 533
    check-cast p0, Lay0/a;

    .line 534
    .line 535
    if-eqz v0, :cond_8

    .line 536
    .line 537
    invoke-virtual {v0}, Li91/v3;->b()V

    .line 538
    .line 539
    .line 540
    :cond_8
    if-eqz p0, :cond_9

    .line 541
    .line 542
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 543
    .line 544
    .line 545
    :cond_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 546
    .line 547
    return-object p0

    .line 548
    :pswitch_f
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 549
    .line 550
    check-cast v0, Li91/v3;

    .line 551
    .line 552
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 553
    .line 554
    check-cast p0, Li91/v3;

    .line 555
    .line 556
    if-eqz v0, :cond_a

    .line 557
    .line 558
    invoke-virtual {v0}, Li91/v3;->b()V

    .line 559
    .line 560
    .line 561
    :cond_a
    if-eqz p0, :cond_b

    .line 562
    .line 563
    invoke-virtual {p0}, Li91/v3;->b()V

    .line 564
    .line 565
    .line 566
    :cond_b
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 567
    .line 568
    return-object p0

    .line 569
    :pswitch_10
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 570
    .line 571
    check-cast v0, Lay0/k;

    .line 572
    .line 573
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 574
    .line 575
    check-cast p0, Lh80/h;

    .line 576
    .line 577
    iget-object p0, p0, Lh80/h;->b:Ljava/lang/String;

    .line 578
    .line 579
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 580
    .line 581
    .line 582
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 583
    .line 584
    return-object p0

    .line 585
    :pswitch_11
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 586
    .line 587
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;

    .line 588
    .line 589
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 590
    .line 591
    check-cast p0, Lay0/a;

    .line 592
    .line 593
    invoke-static {v0, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->k(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;Lay0/a;)Llx0/b0;

    .line 594
    .line 595
    .line 596
    move-result-object p0

    .line 597
    return-object p0

    .line 598
    :pswitch_12
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 599
    .line 600
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;

    .line 601
    .line 602
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 603
    .line 604
    check-cast p0, Lay0/a;

    .line 605
    .line 606
    invoke-static {v0, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->b(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPAFragment;Lay0/a;)Llx0/b0;

    .line 607
    .line 608
    .line 609
    move-result-object p0

    .line 610
    return-object p0

    .line 611
    :pswitch_13
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 612
    .line 613
    check-cast v0, Ljava/lang/String;

    .line 614
    .line 615
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 616
    .line 617
    check-cast p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;

    .line 618
    .line 619
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAPluginImpl;->j:Ljava/util/concurrent/ConcurrentHashMap;

    .line 620
    .line 621
    new-instance v1, Ljava/lang/StringBuilder;

    .line 622
    .line 623
    const-string v2, "rpaStarterFor(): vin = "

    .line 624
    .line 625
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 626
    .line 627
    .line 628
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 629
    .line 630
    .line 631
    const-string v0, " (already requestedStarters = "

    .line 632
    .line 633
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 634
    .line 635
    .line 636
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 637
    .line 638
    .line 639
    const-string p0, ")"

    .line 640
    .line 641
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 642
    .line 643
    .line 644
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 645
    .line 646
    .line 647
    move-result-object p0

    .line 648
    return-object p0

    .line 649
    :pswitch_14
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 650
    .line 651
    check-cast v0, Lay0/k;

    .line 652
    .line 653
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 654
    .line 655
    check-cast p0, Lh50/u;

    .line 656
    .line 657
    iget-object p0, p0, Lh50/u;->p:Lqp0/e;

    .line 658
    .line 659
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 660
    .line 661
    .line 662
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 663
    .line 664
    return-object p0

    .line 665
    :pswitch_15
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 666
    .line 667
    check-cast v0, Lay0/k;

    .line 668
    .line 669
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 670
    .line 671
    check-cast p0, Ll2/f1;

    .line 672
    .line 673
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 674
    .line 675
    .line 676
    move-result p0

    .line 677
    float-to-int p0, p0

    .line 678
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 679
    .line 680
    .line 681
    move-result-object p0

    .line 682
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 683
    .line 684
    .line 685
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 686
    .line 687
    return-object p0

    .line 688
    :pswitch_16
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 689
    .line 690
    check-cast v0, Lay0/k;

    .line 691
    .line 692
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 693
    .line 694
    check-cast p0, Lh40/a4;

    .line 695
    .line 696
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 697
    .line 698
    .line 699
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 700
    .line 701
    return-object p0

    .line 702
    :pswitch_17
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 703
    .line 704
    check-cast v0, Lay0/k;

    .line 705
    .line 706
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 707
    .line 708
    check-cast p0, Lh40/b4;

    .line 709
    .line 710
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 711
    .line 712
    .line 713
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 714
    .line 715
    return-object p0

    .line 716
    :pswitch_18
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 717
    .line 718
    check-cast v0, Lay0/k;

    .line 719
    .line 720
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 721
    .line 722
    check-cast p0, Lh40/y;

    .line 723
    .line 724
    iget-object p0, p0, Lh40/y;->c:Ljava/lang/String;

    .line 725
    .line 726
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 727
    .line 728
    .line 729
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 730
    .line 731
    return-object p0

    .line 732
    :pswitch_19
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 733
    .line 734
    check-cast v0, Lay0/k;

    .line 735
    .line 736
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 737
    .line 738
    check-cast p0, Lh40/x;

    .line 739
    .line 740
    iget-object p0, p0, Lh40/x;->c:Ljava/lang/String;

    .line 741
    .line 742
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 743
    .line 744
    .line 745
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 746
    .line 747
    return-object p0

    .line 748
    :pswitch_1a
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 749
    .line 750
    check-cast v0, Lay0/k;

    .line 751
    .line 752
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 753
    .line 754
    check-cast p0, Lh40/l3;

    .line 755
    .line 756
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 757
    .line 758
    .line 759
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 760
    .line 761
    return-object p0

    .line 762
    :pswitch_1b
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 763
    .line 764
    check-cast v0, Lay0/k;

    .line 765
    .line 766
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 767
    .line 768
    check-cast p0, Lh40/b;

    .line 769
    .line 770
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 771
    .line 772
    .line 773
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 774
    .line 775
    return-object p0

    .line 776
    :pswitch_1c
    iget-object v0, p0, Li2/t;->e:Ljava/lang/Object;

    .line 777
    .line 778
    check-cast v0, Lvy0/b0;

    .line 779
    .line 780
    iget-object p0, p0, Li2/t;->f:Ljava/lang/Object;

    .line 781
    .line 782
    check-cast p0, Lh2/yb;

    .line 783
    .line 784
    new-instance v3, Li2/u;

    .line 785
    .line 786
    invoke-direct {v3, p0, v1, v2}, Li2/u;-><init>(Lh2/yb;Lkotlin/coroutines/Continuation;I)V

    .line 787
    .line 788
    .line 789
    const/4 p0, 0x3

    .line 790
    invoke-static {v0, v1, v1, v3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 791
    .line 792
    .line 793
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 794
    .line 795
    return-object p0

    .line 796
    nop

    .line 797
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
