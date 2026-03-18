.class public final Lvp/j2;
.super Lvp/b0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Lro/f;

.field public g:Lcom/google/firebase/messaging/k;

.field public h:Lc2/k;

.field public final i:Ljava/util/concurrent/CopyOnWriteArraySet;

.field public j:Z

.field public final k:Ljava/util/concurrent/atomic/AtomicReference;

.field public final l:Ljava/lang/Object;

.field public m:Z

.field public n:I

.field public o:Lvp/x1;

.field public p:Lvp/x1;

.field public q:Ljava/util/PriorityQueue;

.field public r:Z

.field public s:Lvp/s1;

.field public final t:Ljava/util/concurrent/atomic/AtomicLong;

.field public u:J

.field public final v:Lro/f;

.field public w:Z

.field public x:Lvp/x1;

.field public y:Lvp/i2;

.field public z:Lvp/x1;


# direct methods
.method public constructor <init>(Lvp/g1;)V
    .locals 3

    .line 1
    invoke-direct {p0, p1}, Lvp/b0;-><init>(Lvp/g1;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lvp/j2;->i:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lvp/j2;->l:Ljava/lang/Object;

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    iput-boolean v0, p0, Lvp/j2;->m:Z

    .line 20
    .line 21
    const/4 v0, 0x1

    .line 22
    iput v0, p0, Lvp/j2;->n:I

    .line 23
    .line 24
    iput-boolean v0, p0, Lvp/j2;->w:Z

    .line 25
    .line 26
    new-instance v0, Lro/f;

    .line 27
    .line 28
    const/16 v1, 0x9

    .line 29
    .line 30
    invoke-direct {v0, p0, v1}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 31
    .line 32
    .line 33
    iput-object v0, p0, Lvp/j2;->A:Lro/f;

    .line 34
    .line 35
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 36
    .line 37
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 38
    .line 39
    .line 40
    iput-object v0, p0, Lvp/j2;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 41
    .line 42
    sget-object v0, Lvp/s1;->c:Lvp/s1;

    .line 43
    .line 44
    iput-object v0, p0, Lvp/j2;->s:Lvp/s1;

    .line 45
    .line 46
    const-wide/16 v0, -0x1

    .line 47
    .line 48
    iput-wide v0, p0, Lvp/j2;->u:J

    .line 49
    .line 50
    new-instance v0, Ljava/util/concurrent/atomic/AtomicLong;

    .line 51
    .line 52
    const-wide/16 v1, 0x0

    .line 53
    .line 54
    invoke-direct {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicLong;-><init>(J)V

    .line 55
    .line 56
    .line 57
    iput-object v0, p0, Lvp/j2;->t:Ljava/util/concurrent/atomic/AtomicLong;

    .line 58
    .line 59
    new-instance v0, Lro/f;

    .line 60
    .line 61
    const/16 v1, 0xb

    .line 62
    .line 63
    invoke-direct {v0, p1, v1}, Lro/f;-><init>(Ljava/lang/Object;I)V

    .line 64
    .line 65
    .line 66
    iput-object v0, p0, Lvp/j2;->v:Lro/f;

    .line 67
    .line 68
    return-void
.end method


# virtual methods
.method public final d0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final e0(Lvp/s1;)V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lvp/r1;->f:Lvp/r1;

    .line 5
    .line 6
    invoke-virtual {p1, v0}, Lvp/s1;->i(Lvp/r1;)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x0

    .line 11
    const/4 v2, 0x1

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    sget-object v0, Lvp/r1;->e:Lvp/r1;

    .line 15
    .line 16
    invoke-virtual {p1, v0}, Lvp/s1;->i(Lvp/r1;)Z

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    if-nez p1, :cond_0

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_0
    :goto_0
    move p1, v2

    .line 24
    goto :goto_2

    .line 25
    :cond_1
    :goto_1
    iget-object p1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p1, Lvp/g1;

    .line 28
    .line 29
    invoke-virtual {p1}, Lvp/g1;->o()Lvp/d3;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p1}, Lvp/d3;->j0()Z

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    if-eqz p1, :cond_2

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    move p1, v1

    .line 41
    :goto_2
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Lvp/g1;

    .line 44
    .line 45
    iget-object v3, v0, Lvp/g1;->j:Lvp/e1;

    .line 46
    .line 47
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v3}, Lvp/e1;->a0()V

    .line 51
    .line 52
    .line 53
    iget-boolean v3, v0, Lvp/g1;->C:Z

    .line 54
    .line 55
    if-eq p1, v3, :cond_5

    .line 56
    .line 57
    iget-object v3, v0, Lvp/g1;->j:Lvp/e1;

    .line 58
    .line 59
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v3}, Lvp/e1;->a0()V

    .line 63
    .line 64
    .line 65
    iput-boolean p1, v0, Lvp/g1;->C:Z

    .line 66
    .line 67
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v0, Lvp/g1;

    .line 70
    .line 71
    iget-object v0, v0, Lvp/g1;->h:Lvp/w0;

    .line 72
    .line 73
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    const-string v4, "measurement_enabled_from_api"

    .line 84
    .line 85
    invoke-interface {v3, v4}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    if-eqz v3, :cond_3

    .line 90
    .line 91
    invoke-virtual {v0}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    invoke-interface {v0, v4, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    goto :goto_3

    .line 104
    :cond_3
    const/4 v0, 0x0

    .line 105
    :goto_3
    if-eqz p1, :cond_4

    .line 106
    .line 107
    if-eqz v0, :cond_4

    .line 108
    .line 109
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    if-eqz v0, :cond_5

    .line 114
    .line 115
    :cond_4
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    invoke-virtual {p0, p1, v1}, Lvp/j2;->r0(Ljava/lang/Boolean;Z)V

    .line 120
    .line 121
    .line 122
    :cond_5
    return-void
.end method

.method public final f0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;ZZJ)V
    .locals 12

    .line 1
    if-nez p3, :cond_0

    .line 2
    .line 3
    new-instance v0, Landroid/os/Bundle;

    .line 4
    .line 5
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move-object v0, p3

    .line 10
    :goto_0
    const-string v1, "screen_view"

    .line 11
    .line 12
    invoke-static {p2, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/4 v2, 0x0

    .line 17
    if-eqz v1, :cond_c

    .line 18
    .line 19
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Lvp/g1;

    .line 22
    .line 23
    iget-object p1, p0, Lvp/g1;->o:Lvp/u2;

    .line 24
    .line 25
    invoke-static {p1}, Lvp/g1;->i(Lvp/b0;)V

    .line 26
    .line 27
    .line 28
    iget-object v1, p1, Lvp/u2;->p:Ljava/lang/Object;

    .line 29
    .line 30
    monitor-enter v1

    .line 31
    :try_start_0
    iget-boolean p0, p1, Lvp/u2;->o:Z

    .line 32
    .line 33
    if-nez p0, :cond_1

    .line 34
    .line 35
    iget-object p0, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Lvp/g1;

    .line 38
    .line 39
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 40
    .line 41
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 45
    .line 46
    const-string p1, "Cannot log screen view event when the app is in the background."

    .line 47
    .line 48
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    monitor-exit v1

    .line 52
    return-void

    .line 53
    :catchall_0
    move-exception v0

    .line 54
    move-object p0, v0

    .line 55
    goto/16 :goto_6

    .line 56
    .line 57
    :cond_1
    const-string p0, "screen_name"

    .line 58
    .line 59
    invoke-virtual {v0, p0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    const/16 p0, 0x1f4

    .line 64
    .line 65
    if-eqz v4, :cond_3

    .line 66
    .line 67
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 68
    .line 69
    .line 70
    move-result p2

    .line 71
    if-lez p2, :cond_2

    .line 72
    .line 73
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 74
    .line 75
    .line 76
    move-result p2

    .line 77
    iget-object v3, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v3, Lvp/g1;

    .line 80
    .line 81
    iget-object v3, v3, Lvp/g1;->g:Lvp/h;

    .line 82
    .line 83
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    if-le p2, p0, :cond_3

    .line 87
    .line 88
    :cond_2
    iget-object p0, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast p0, Lvp/g1;

    .line 91
    .line 92
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 93
    .line 94
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 95
    .line 96
    .line 97
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 98
    .line 99
    const-string p1, "Invalid screen name length for screen view. Length"

    .line 100
    .line 101
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 102
    .line 103
    .line 104
    move-result p2

    .line 105
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 106
    .line 107
    .line 108
    move-result-object p2

    .line 109
    invoke-virtual {p0, p2, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    monitor-exit v1

    .line 113
    return-void

    .line 114
    :cond_3
    const-string p2, "screen_class"

    .line 115
    .line 116
    invoke-virtual {v0, p2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p2

    .line 120
    if-eqz p2, :cond_5

    .line 121
    .line 122
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    if-lez v3, :cond_4

    .line 127
    .line 128
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 129
    .line 130
    .line 131
    move-result v3

    .line 132
    iget-object v5, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v5, Lvp/g1;

    .line 135
    .line 136
    iget-object v5, v5, Lvp/g1;->g:Lvp/h;

    .line 137
    .line 138
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 139
    .line 140
    .line 141
    if-le v3, p0, :cond_5

    .line 142
    .line 143
    :cond_4
    iget-object p0, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast p0, Lvp/g1;

    .line 146
    .line 147
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 148
    .line 149
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 150
    .line 151
    .line 152
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 153
    .line 154
    const-string p1, "Invalid screen class length for screen view. Length"

    .line 155
    .line 156
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 157
    .line 158
    .line 159
    move-result p2

    .line 160
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 161
    .line 162
    .line 163
    move-result-object p2

    .line 164
    invoke-virtual {p0, p2, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    monitor-exit v1

    .line 168
    return-void

    .line 169
    :cond_5
    if-nez p2, :cond_6

    .line 170
    .line 171
    iget-object p0, p1, Lvp/u2;->k:Lcom/google/android/gms/internal/measurement/w0;

    .line 172
    .line 173
    if-eqz p0, :cond_7

    .line 174
    .line 175
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/w0;->e:Ljava/lang/String;

    .line 176
    .line 177
    invoke-virtual {p1, p0}, Lvp/u2;->h0(Ljava/lang/String;)Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object p2

    .line 181
    :cond_6
    :goto_1
    move-object v5, p2

    .line 182
    goto :goto_2

    .line 183
    :cond_7
    const-string p2, "Activity"

    .line 184
    .line 185
    goto :goto_1

    .line 186
    :goto_2
    iget-object p0, p1, Lvp/u2;->g:Lvp/r2;

    .line 187
    .line 188
    iget-boolean p2, p1, Lvp/u2;->l:Z

    .line 189
    .line 190
    if-eqz p2, :cond_8

    .line 191
    .line 192
    if-eqz p0, :cond_8

    .line 193
    .line 194
    iput-boolean v2, p1, Lvp/u2;->l:Z

    .line 195
    .line 196
    iget-object p2, p0, Lvp/r2;->b:Ljava/lang/String;

    .line 197
    .line 198
    invoke-static {p2, v5}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result p2

    .line 202
    iget-object p0, p0, Lvp/r2;->a:Ljava/lang/String;

    .line 203
    .line 204
    invoke-static {p0, v4}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result p0

    .line 208
    if-eqz p2, :cond_8

    .line 209
    .line 210
    if-eqz p0, :cond_8

    .line 211
    .line 212
    iget-object p0, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 213
    .line 214
    check-cast p0, Lvp/g1;

    .line 215
    .line 216
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 217
    .line 218
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 219
    .line 220
    .line 221
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 222
    .line 223
    const-string p1, "Ignoring call to log screen view event with duplicate parameters."

    .line 224
    .line 225
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    monitor-exit v1

    .line 229
    return-void

    .line 230
    :cond_8
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 231
    iget-object p0, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 232
    .line 233
    check-cast p0, Lvp/g1;

    .line 234
    .line 235
    iget-object p2, p0, Lvp/g1;->i:Lvp/p0;

    .line 236
    .line 237
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 238
    .line 239
    .line 240
    iget-object p2, p2, Lvp/p0;->r:Lvp/n0;

    .line 241
    .line 242
    if-nez v4, :cond_9

    .line 243
    .line 244
    const-string v1, "null"

    .line 245
    .line 246
    goto :goto_3

    .line 247
    :cond_9
    move-object v1, v4

    .line 248
    :goto_3
    if-nez v5, :cond_a

    .line 249
    .line 250
    const-string v2, "null"

    .line 251
    .line 252
    goto :goto_4

    .line 253
    :cond_a
    move-object v2, v5

    .line 254
    :goto_4
    const-string v3, "Logging screen view with name, class"

    .line 255
    .line 256
    invoke-virtual {p2, v1, v2, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 257
    .line 258
    .line 259
    iget-object p2, p1, Lvp/u2;->g:Lvp/r2;

    .line 260
    .line 261
    if-nez p2, :cond_b

    .line 262
    .line 263
    iget-object p2, p1, Lvp/u2;->h:Lvp/r2;

    .line 264
    .line 265
    goto :goto_5

    .line 266
    :cond_b
    iget-object p2, p1, Lvp/u2;->g:Lvp/r2;

    .line 267
    .line 268
    :goto_5
    new-instance v3, Lvp/r2;

    .line 269
    .line 270
    iget-object v1, p0, Lvp/g1;->l:Lvp/d4;

    .line 271
    .line 272
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 273
    .line 274
    .line 275
    invoke-virtual {v1}, Lvp/d4;->W0()J

    .line 276
    .line 277
    .line 278
    move-result-wide v6

    .line 279
    const/4 v8, 0x1

    .line 280
    move-wide/from16 v9, p6

    .line 281
    .line 282
    invoke-direct/range {v3 .. v10}, Lvp/r2;-><init>(Ljava/lang/String;Ljava/lang/String;JZJ)V

    .line 283
    .line 284
    .line 285
    iput-object v3, p1, Lvp/u2;->g:Lvp/r2;

    .line 286
    .line 287
    iput-object p2, p1, Lvp/u2;->h:Lvp/r2;

    .line 288
    .line 289
    iput-object v3, p1, Lvp/u2;->m:Lvp/r2;

    .line 290
    .line 291
    iget-object v1, p0, Lvp/g1;->n:Lto/a;

    .line 292
    .line 293
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 294
    .line 295
    .line 296
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 297
    .line 298
    .line 299
    move-result-wide v1

    .line 300
    iget-object v4, p0, Lvp/g1;->j:Lvp/e1;

    .line 301
    .line 302
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 303
    .line 304
    .line 305
    new-instance p0, Lvp/j1;

    .line 306
    .line 307
    move-object/from16 p4, p2

    .line 308
    .line 309
    move-object p2, v0

    .line 310
    move-wide/from16 p5, v1

    .line 311
    .line 312
    move-object p3, v3

    .line 313
    invoke-direct/range {p0 .. p6}, Lvp/j1;-><init>(Lvp/u2;Landroid/os/Bundle;Lvp/r2;Lvp/r2;J)V

    .line 314
    .line 315
    .line 316
    invoke-virtual {v4, p0}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 317
    .line 318
    .line 319
    return-void

    .line 320
    :goto_6
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 321
    throw p0

    .line 322
    :cond_c
    const/4 v1, 0x1

    .line 323
    if-eqz p5, :cond_d

    .line 324
    .line 325
    iget-object v3, p0, Lvp/j2;->h:Lc2/k;

    .line 326
    .line 327
    if-eqz v3, :cond_d

    .line 328
    .line 329
    invoke-static {p2}, Lvp/d4;->y0(Ljava/lang/String;)Z

    .line 330
    .line 331
    .line 332
    move-result v3

    .line 333
    if-eqz v3, :cond_e

    .line 334
    .line 335
    :cond_d
    move v10, v1

    .line 336
    goto :goto_7

    .line 337
    :cond_e
    move v10, v2

    .line 338
    :goto_7
    if-nez p1, :cond_f

    .line 339
    .line 340
    const-string p1, "app"

    .line 341
    .line 342
    :cond_f
    move-object v4, p1

    .line 343
    new-instance v8, Landroid/os/Bundle;

    .line 344
    .line 345
    invoke-direct {v8, v0}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 346
    .line 347
    .line 348
    invoke-virtual {v8}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 349
    .line 350
    .line 351
    move-result-object p1

    .line 352
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 353
    .line 354
    .line 355
    move-result-object p1

    .line 356
    :cond_10
    :goto_8
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 357
    .line 358
    .line 359
    move-result v0

    .line 360
    if-eqz v0, :cond_15

    .line 361
    .line 362
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 363
    .line 364
    .line 365
    move-result-object v0

    .line 366
    check-cast v0, Ljava/lang/String;

    .line 367
    .line 368
    invoke-virtual {v8, v0}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v1

    .line 372
    instance-of v3, v1, Landroid/os/Bundle;

    .line 373
    .line 374
    if-eqz v3, :cond_11

    .line 375
    .line 376
    new-instance v3, Landroid/os/Bundle;

    .line 377
    .line 378
    check-cast v1, Landroid/os/Bundle;

    .line 379
    .line 380
    invoke-direct {v3, v1}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 381
    .line 382
    .line 383
    invoke-virtual {v8, v0, v3}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 384
    .line 385
    .line 386
    goto :goto_8

    .line 387
    :cond_11
    instance-of v0, v1, [Landroid/os/Parcelable;

    .line 388
    .line 389
    if-eqz v0, :cond_13

    .line 390
    .line 391
    check-cast v1, [Landroid/os/Parcelable;

    .line 392
    .line 393
    move v0, v2

    .line 394
    :goto_9
    array-length v3, v1

    .line 395
    if-ge v0, v3, :cond_10

    .line 396
    .line 397
    aget-object v3, v1, v0

    .line 398
    .line 399
    instance-of v5, v3, Landroid/os/Bundle;

    .line 400
    .line 401
    if-eqz v5, :cond_12

    .line 402
    .line 403
    new-instance v5, Landroid/os/Bundle;

    .line 404
    .line 405
    check-cast v3, Landroid/os/Bundle;

    .line 406
    .line 407
    invoke-direct {v5, v3}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 408
    .line 409
    .line 410
    aput-object v5, v1, v0

    .line 411
    .line 412
    :cond_12
    add-int/lit8 v0, v0, 0x1

    .line 413
    .line 414
    goto :goto_9

    .line 415
    :cond_13
    instance-of v0, v1, Ljava/util/List;

    .line 416
    .line 417
    if-eqz v0, :cond_10

    .line 418
    .line 419
    check-cast v1, Ljava/util/List;

    .line 420
    .line 421
    move v0, v2

    .line 422
    :goto_a
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 423
    .line 424
    .line 425
    move-result v3

    .line 426
    if-ge v0, v3, :cond_10

    .line 427
    .line 428
    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v3

    .line 432
    instance-of v5, v3, Landroid/os/Bundle;

    .line 433
    .line 434
    if-eqz v5, :cond_14

    .line 435
    .line 436
    new-instance v5, Landroid/os/Bundle;

    .line 437
    .line 438
    check-cast v3, Landroid/os/Bundle;

    .line 439
    .line 440
    invoke-direct {v5, v3}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 441
    .line 442
    .line 443
    invoke-interface {v1, v0, v5}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 444
    .line 445
    .line 446
    :cond_14
    add-int/lit8 v0, v0, 0x1

    .line 447
    .line 448
    goto :goto_a

    .line 449
    :cond_15
    iget-object p1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 450
    .line 451
    check-cast p1, Lvp/g1;

    .line 452
    .line 453
    iget-object p1, p1, Lvp/g1;->j:Lvp/e1;

    .line 454
    .line 455
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 456
    .line 457
    .line 458
    new-instance v2, Lvp/c2;

    .line 459
    .line 460
    move-object v3, p0

    .line 461
    move-object v5, p2

    .line 462
    move/from16 v11, p4

    .line 463
    .line 464
    move/from16 v9, p5

    .line 465
    .line 466
    move-wide/from16 v6, p6

    .line 467
    .line 468
    invoke-direct/range {v2 .. v11}, Lvp/c2;-><init>(Lvp/j2;Ljava/lang/String;Ljava/lang/String;JLandroid/os/Bundle;ZZZ)V

    .line 469
    .line 470
    .line 471
    invoke-virtual {p1, v2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 472
    .line 473
    .line 474
    return-void
.end method

.method public final g0()V
    .locals 55

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 4
    .line 5
    .line 6
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Lvp/g1;

    .line 9
    .line 10
    iget-object v2, v1, Lvp/g1;->i:Lvp/p0;

    .line 11
    .line 12
    iget-object v3, v1, Lvp/g1;->n:Lto/a;

    .line 13
    .line 14
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 15
    .line 16
    .line 17
    iget-object v4, v2, Lvp/p0;->q:Lvp/n0;

    .line 18
    .line 19
    const-string v5, "Handle tcf update."

    .line 20
    .line 21
    invoke-virtual {v4, v5}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-object v4, v1, Lvp/g1;->h:Lvp/w0;

    .line 25
    .line 26
    invoke-static {v4}, Lvp/g1;->g(Lap0/o;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v4}, Lvp/w0;->f0()Landroid/content/SharedPreferences;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    new-instance v6, Ljava/util/HashMap;

    .line 34
    .line 35
    invoke-direct {v6}, Ljava/util/HashMap;-><init>()V

    .line 36
    .line 37
    .line 38
    sget-object v7, Lvp/z;->Z0:Lvp/y;

    .line 39
    .line 40
    const/4 v8, 0x0

    .line 41
    invoke-virtual {v7, v8}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v9

    .line 45
    check-cast v9, Ljava/lang/Boolean;

    .line 46
    .line 47
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 48
    .line 49
    .line 50
    move-result v9

    .line 51
    const-string v10, "CmpSdkID"

    .line 52
    .line 53
    const-string v11, "PolicyVersion"

    .line 54
    .line 55
    const-string v12, "EnableAdvertiserConsentMode"

    .line 56
    .line 57
    const-string v13, "gdprApplies"

    .line 58
    .line 59
    const-string v14, "Version"

    .line 60
    .line 61
    const-string v15, "0"

    .line 62
    .line 63
    const-string v16, "1"

    .line 64
    .line 65
    const-string v8, "IABTCF_VendorConsents"

    .line 66
    .line 67
    move-object/from16 v17, v3

    .line 68
    .line 69
    const-string v3, "IABTCF_PurposeConsents"

    .line 70
    .line 71
    move/from16 v18, v9

    .line 72
    .line 73
    const/16 v19, 0x2

    .line 74
    .line 75
    const-string v9, "IABTCF_EnableAdvertiserConsentMode"

    .line 76
    .line 77
    move-object/from16 v20, v15

    .line 78
    .line 79
    const-string v15, "IABTCF_gdprApplies"

    .line 80
    .line 81
    const-string v0, "IABTCF_PolicyVersion"

    .line 82
    .line 83
    move-object/from16 v21, v4

    .line 84
    .line 85
    const-string v4, "IABTCF_CmpSdkID"

    .line 86
    .line 87
    move-object/from16 v22, v7

    .line 88
    .line 89
    const-string v7, ""

    .line 90
    .line 91
    move-object/from16 v23, v1

    .line 92
    .line 93
    const/16 v25, 0x0

    .line 94
    .line 95
    const/16 v26, 0x1

    .line 96
    .line 97
    if-eqz v18, :cond_18

    .line 98
    .line 99
    sget-object v6, Lvp/n3;->a:Lhr/x0;

    .line 100
    .line 101
    new-instance v6, Ljava/util/AbstractMap$SimpleImmutableEntry;

    .line 102
    .line 103
    sget-object v1, Lcom/google/android/gms/internal/measurement/r4;->e:Lcom/google/android/gms/internal/measurement/r4;

    .line 104
    .line 105
    move-object/from16 v40, v2

    .line 106
    .line 107
    sget-object v2, Lvp/m3;->d:Lvp/m3;

    .line 108
    .line 109
    invoke-direct {v6, v1, v2}, Ljava/util/AbstractMap$SimpleImmutableEntry;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    move-object/from16 v27, v6

    .line 113
    .line 114
    new-instance v6, Ljava/util/AbstractMap$SimpleImmutableEntry;

    .line 115
    .line 116
    move-object/from16 v41, v7

    .line 117
    .line 118
    sget-object v7, Lcom/google/android/gms/internal/measurement/r4;->f:Lcom/google/android/gms/internal/measurement/r4;

    .line 119
    .line 120
    move-object/from16 v28, v10

    .line 121
    .line 122
    sget-object v10, Lvp/m3;->e:Lvp/m3;

    .line 123
    .line 124
    invoke-direct {v6, v7, v10}, Ljava/util/AbstractMap$SimpleImmutableEntry;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    new-instance v7, Ljava/util/AbstractMap$SimpleImmutableEntry;

    .line 128
    .line 129
    move-object/from16 v29, v6

    .line 130
    .line 131
    sget-object v6, Lcom/google/android/gms/internal/measurement/r4;->g:Lcom/google/android/gms/internal/measurement/r4;

    .line 132
    .line 133
    invoke-direct {v7, v6, v2}, Ljava/util/AbstractMap$SimpleImmutableEntry;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    move-object/from16 v30, v7

    .line 137
    .line 138
    new-instance v7, Ljava/util/AbstractMap$SimpleImmutableEntry;

    .line 139
    .line 140
    move-object/from16 v31, v11

    .line 141
    .line 142
    sget-object v11, Lcom/google/android/gms/internal/measurement/r4;->h:Lcom/google/android/gms/internal/measurement/r4;

    .line 143
    .line 144
    invoke-direct {v7, v11, v2}, Ljava/util/AbstractMap$SimpleImmutableEntry;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    new-instance v2, Ljava/util/AbstractMap$SimpleImmutableEntry;

    .line 148
    .line 149
    move-object/from16 v32, v7

    .line 150
    .line 151
    sget-object v7, Lcom/google/android/gms/internal/measurement/r4;->i:Lcom/google/android/gms/internal/measurement/r4;

    .line 152
    .line 153
    invoke-direct {v2, v7, v10}, Ljava/util/AbstractMap$SimpleImmutableEntry;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    move-object/from16 v33, v2

    .line 157
    .line 158
    new-instance v2, Ljava/util/AbstractMap$SimpleImmutableEntry;

    .line 159
    .line 160
    move-object/from16 v34, v12

    .line 161
    .line 162
    sget-object v12, Lcom/google/android/gms/internal/measurement/r4;->j:Lcom/google/android/gms/internal/measurement/r4;

    .line 163
    .line 164
    invoke-direct {v2, v12, v10}, Ljava/util/AbstractMap$SimpleImmutableEntry;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    new-instance v12, Ljava/util/AbstractMap$SimpleImmutableEntry;

    .line 168
    .line 169
    move-object/from16 v35, v2

    .line 170
    .line 171
    sget-object v2, Lcom/google/android/gms/internal/measurement/r4;->k:Lcom/google/android/gms/internal/measurement/r4;

    .line 172
    .line 173
    invoke-direct {v12, v2, v10}, Ljava/util/AbstractMap$SimpleImmutableEntry;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    const/4 v2, 0x7

    .line 177
    new-array v2, v2, [Ljava/util/Map$Entry;

    .line 178
    .line 179
    aput-object v27, v2, v25

    .line 180
    .line 181
    aput-object v29, v2, v26

    .line 182
    .line 183
    aput-object v30, v2, v19

    .line 184
    .line 185
    const/4 v10, 0x3

    .line 186
    aput-object v32, v2, v10

    .line 187
    .line 188
    const/4 v10, 0x4

    .line 189
    aput-object v33, v2, v10

    .line 190
    .line 191
    const/4 v10, 0x5

    .line 192
    aput-object v35, v2, v10

    .line 193
    .line 194
    const/16 v29, 0x6

    .line 195
    .line 196
    aput-object v12, v2, v29

    .line 197
    .line 198
    invoke-static {v2}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 199
    .line 200
    .line 201
    move-result-object v2

    .line 202
    check-cast v2, Ljava/util/Collection;

    .line 203
    .line 204
    instance-of v12, v2, Ljava/util/Collection;

    .line 205
    .line 206
    if-eqz v12, :cond_0

    .line 207
    .line 208
    move-object v12, v2

    .line 209
    check-cast v12, Ljava/util/Collection;

    .line 210
    .line 211
    invoke-interface {v12}, Ljava/util/Collection;->size()I

    .line 212
    .line 213
    .line 214
    move-result v12

    .line 215
    goto :goto_0

    .line 216
    :cond_0
    const/4 v12, 0x4

    .line 217
    :goto_0
    new-instance v10, Lbb/g0;

    .line 218
    .line 219
    invoke-direct {v10, v12}, Lbb/g0;-><init>(I)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v10, v2}, Lbb/g0;->r(Ljava/lang/Iterable;)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v10}, Lbb/g0;->e()Lhr/c1;

    .line 226
    .line 227
    .line 228
    move-result-object v43

    .line 229
    sget v2, Lhr/k0;->f:I

    .line 230
    .line 231
    new-instance v2, Lhr/j1;

    .line 232
    .line 233
    const-string v10, "CH"

    .line 234
    .line 235
    invoke-direct {v2, v10}, Lhr/j1;-><init>(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    const/4 v10, 0x5

    .line 239
    new-array v12, v10, [C

    .line 240
    .line 241
    const-string v10, "IABTCF_TCString"

    .line 242
    .line 243
    invoke-interface {v5, v10}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    .line 244
    .line 245
    .line 246
    move-result v10

    .line 247
    move-object/from16 v30, v2

    .line 248
    .line 249
    const/4 v2, -0x1

    .line 250
    :try_start_0
    invoke-interface {v5, v4, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 251
    .line 252
    .line 253
    move-result v18
    :try_end_0
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_0

    .line 254
    move/from16 v4, v18

    .line 255
    .line 256
    goto :goto_1

    .line 257
    :catch_0
    move v4, v2

    .line 258
    :goto_1
    :try_start_1
    invoke-interface {v5, v0, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 259
    .line 260
    .line 261
    move-result v18
    :try_end_1
    .catch Ljava/lang/ClassCastException; {:try_start_1 .. :try_end_1} :catch_1

    .line 262
    move/from16 v0, v18

    .line 263
    .line 264
    goto :goto_2

    .line 265
    :catch_1
    move v0, v2

    .line 266
    :goto_2
    :try_start_2
    invoke-interface {v5, v15, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 267
    .line 268
    .line 269
    move-result v18
    :try_end_2
    .catch Ljava/lang/ClassCastException; {:try_start_2 .. :try_end_2} :catch_2

    .line 270
    move/from16 v15, v18

    .line 271
    .line 272
    :goto_3
    move/from16 v29, v0

    .line 273
    .line 274
    goto :goto_4

    .line 275
    :catch_2
    move v15, v2

    .line 276
    goto :goto_3

    .line 277
    :goto_4
    const-string v0, "IABTCF_PurposeOneTreatment"

    .line 278
    .line 279
    :try_start_3
    invoke-interface {v5, v0, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 280
    .line 281
    .line 282
    move-result v18
    :try_end_3
    .catch Ljava/lang/ClassCastException; {:try_start_3 .. :try_end_3} :catch_3

    .line 283
    move/from16 v0, v18

    .line 284
    .line 285
    goto :goto_5

    .line 286
    :catch_3
    move v0, v2

    .line 287
    :goto_5
    :try_start_4
    invoke-interface {v5, v9, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 288
    .line 289
    .line 290
    move-result v2
    :try_end_4
    .catch Ljava/lang/ClassCastException; {:try_start_4 .. :try_end_4} :catch_4

    .line 291
    goto :goto_6

    .line 292
    :catch_4
    const/4 v2, -0x1

    .line 293
    :goto_6
    const-string v9, "IABTCF_PublisherCC"

    .line 294
    .line 295
    invoke-static {v5, v9}, Lvp/n3;->a(Landroid/content/SharedPreferences;Ljava/lang/String;)Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v9

    .line 299
    move/from16 v32, v4

    .line 300
    .line 301
    new-instance v4, Lbb/g0;

    .line 302
    .line 303
    move/from16 v33, v10

    .line 304
    .line 305
    const/4 v10, 0x4

    .line 306
    invoke-direct {v4, v10}, Lbb/g0;-><init>(I)V

    .line 307
    .line 308
    .line 309
    invoke-virtual/range {v43 .. v43}, Lhr/c1;->c()Lhr/k0;

    .line 310
    .line 311
    .line 312
    move-result-object v10

    .line 313
    invoke-virtual {v10}, Lhr/k0;->s()Lhr/l1;

    .line 314
    .line 315
    .line 316
    move-result-object v10

    .line 317
    :goto_7
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 318
    .line 319
    .line 320
    move-result v18

    .line 321
    sget-object v35, Lcom/google/android/gms/internal/measurement/s4;->h:Lcom/google/android/gms/internal/measurement/s4;

    .line 322
    .line 323
    move-object/from16 v36, v10

    .line 324
    .line 325
    if-eqz v18, :cond_7

    .line 326
    .line 327
    invoke-interface/range {v36 .. v36}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v18

    .line 331
    move-object/from16 v10, v18

    .line 332
    .line 333
    check-cast v10, Lcom/google/android/gms/internal/measurement/r4;

    .line 334
    .line 335
    move-object/from16 v46, v12

    .line 336
    .line 337
    invoke-virtual {v10}, Lcom/google/android/gms/internal/measurement/r4;->h()I

    .line 338
    .line 339
    .line 340
    move-result v12

    .line 341
    invoke-static {v12}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 342
    .line 343
    .line 344
    move-result-object v18

    .line 345
    invoke-virtual/range {v18 .. v18}, Ljava/lang/String;->length()I

    .line 346
    .line 347
    .line 348
    move-result v18

    .line 349
    move-object/from16 v50, v9

    .line 350
    .line 351
    new-instance v9, Ljava/lang/StringBuilder;

    .line 352
    .line 353
    move/from16 v49, v0

    .line 354
    .line 355
    add-int/lit8 v0, v18, 0x1c

    .line 356
    .line 357
    invoke-direct {v9, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 358
    .line 359
    .line 360
    const-string v0, "IABTCF_PublisherRestrictions"

    .line 361
    .line 362
    invoke-virtual {v9, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 363
    .line 364
    .line 365
    invoke-virtual {v9, v12}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 366
    .line 367
    .line 368
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 369
    .line 370
    .line 371
    move-result-object v0

    .line 372
    invoke-static {v5, v0}, Lvp/n3;->a(Landroid/content/SharedPreferences;Ljava/lang/String;)Ljava/lang/String;

    .line 373
    .line 374
    .line 375
    move-result-object v0

    .line 376
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 377
    .line 378
    .line 379
    move-result v9

    .line 380
    if-nez v9, :cond_3

    .line 381
    .line 382
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 383
    .line 384
    .line 385
    move-result v9

    .line 386
    const/16 v12, 0x2f3

    .line 387
    .line 388
    if-ge v9, v12, :cond_1

    .line 389
    .line 390
    goto :goto_8

    .line 391
    :cond_1
    const/16 v9, 0x2f2

    .line 392
    .line 393
    invoke-virtual {v0, v9}, Ljava/lang/String;->charAt(I)C

    .line 394
    .line 395
    .line 396
    move-result v0

    .line 397
    const/16 v9, 0xa

    .line 398
    .line 399
    invoke-static {v0, v9}, Ljava/lang/Character;->digit(CI)I

    .line 400
    .line 401
    .line 402
    move-result v0

    .line 403
    sget-object v9, Lcom/google/android/gms/internal/measurement/s4;->e:Lcom/google/android/gms/internal/measurement/s4;

    .line 404
    .line 405
    if-ltz v0, :cond_6

    .line 406
    .line 407
    invoke-static {}, Lcom/google/android/gms/internal/measurement/s4;->values()[Lcom/google/android/gms/internal/measurement/s4;

    .line 408
    .line 409
    .line 410
    move-result-object v12

    .line 411
    array-length v12, v12

    .line 412
    if-le v0, v12, :cond_2

    .line 413
    .line 414
    goto :goto_9

    .line 415
    :cond_2
    if-eqz v0, :cond_6

    .line 416
    .line 417
    move/from16 v12, v26

    .line 418
    .line 419
    if-eq v0, v12, :cond_5

    .line 420
    .line 421
    move/from16 v9, v19

    .line 422
    .line 423
    if-eq v0, v9, :cond_4

    .line 424
    .line 425
    :cond_3
    :goto_8
    move-object/from16 v9, v35

    .line 426
    .line 427
    goto :goto_9

    .line 428
    :cond_4
    sget-object v35, Lcom/google/android/gms/internal/measurement/s4;->g:Lcom/google/android/gms/internal/measurement/s4;

    .line 429
    .line 430
    goto :goto_8

    .line 431
    :cond_5
    sget-object v35, Lcom/google/android/gms/internal/measurement/s4;->f:Lcom/google/android/gms/internal/measurement/s4;

    .line 432
    .line 433
    goto :goto_8

    .line 434
    :cond_6
    :goto_9
    invoke-virtual {v4, v10, v9}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 435
    .line 436
    .line 437
    move-object/from16 v10, v36

    .line 438
    .line 439
    move-object/from16 v12, v46

    .line 440
    .line 441
    move/from16 v0, v49

    .line 442
    .line 443
    move-object/from16 v9, v50

    .line 444
    .line 445
    const/16 v19, 0x2

    .line 446
    .line 447
    const/16 v26, 0x1

    .line 448
    .line 449
    goto/16 :goto_7

    .line 450
    .line 451
    :cond_7
    move/from16 v49, v0

    .line 452
    .line 453
    move-object/from16 v50, v9

    .line 454
    .line 455
    move-object/from16 v46, v12

    .line 456
    .line 457
    invoke-virtual {v4}, Lbb/g0;->e()Lhr/c1;

    .line 458
    .line 459
    .line 460
    move-result-object v0

    .line 461
    invoke-static {v5, v3}, Lvp/n3;->a(Landroid/content/SharedPreferences;Ljava/lang/String;)Ljava/lang/String;

    .line 462
    .line 463
    .line 464
    move-result-object v3

    .line 465
    invoke-static {v5, v8}, Lvp/n3;->a(Landroid/content/SharedPreferences;Ljava/lang/String;)Ljava/lang/String;

    .line 466
    .line 467
    .line 468
    move-result-object v4

    .line 469
    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 470
    .line 471
    .line 472
    move-result v8

    .line 473
    const/16 v9, 0x31

    .line 474
    .line 475
    if-nez v8, :cond_8

    .line 476
    .line 477
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 478
    .line 479
    .line 480
    move-result v8

    .line 481
    const/16 v12, 0x2f3

    .line 482
    .line 483
    if-lt v8, v12, :cond_8

    .line 484
    .line 485
    const/16 v8, 0x2f2

    .line 486
    .line 487
    invoke-virtual {v4, v8}, Ljava/lang/String;->charAt(I)C

    .line 488
    .line 489
    .line 490
    move-result v4

    .line 491
    if-ne v4, v9, :cond_8

    .line 492
    .line 493
    const/4 v4, 0x1

    .line 494
    goto :goto_a

    .line 495
    :cond_8
    move/from16 v4, v25

    .line 496
    .line 497
    :goto_a
    const-string v8, "IABTCF_PurposeLegitimateInterests"

    .line 498
    .line 499
    invoke-static {v5, v8}, Lvp/n3;->a(Landroid/content/SharedPreferences;Ljava/lang/String;)Ljava/lang/String;

    .line 500
    .line 501
    .line 502
    move-result-object v8

    .line 503
    const-string v10, "IABTCF_VendorLegitimateInterests"

    .line 504
    .line 505
    invoke-static {v5, v10}, Lvp/n3;->a(Landroid/content/SharedPreferences;Ljava/lang/String;)Ljava/lang/String;

    .line 506
    .line 507
    .line 508
    move-result-object v5

    .line 509
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 510
    .line 511
    .line 512
    move-result v10

    .line 513
    if-nez v10, :cond_9

    .line 514
    .line 515
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 516
    .line 517
    .line 518
    move-result v10

    .line 519
    const/16 v12, 0x2f3

    .line 520
    .line 521
    if-lt v10, v12, :cond_9

    .line 522
    .line 523
    const/16 v10, 0x2f2

    .line 524
    .line 525
    invoke-virtual {v5, v10}, Ljava/lang/String;->charAt(I)C

    .line 526
    .line 527
    .line 528
    move-result v5

    .line 529
    if-ne v5, v9, :cond_9

    .line 530
    .line 531
    const/4 v5, 0x1

    .line 532
    goto :goto_b

    .line 533
    :cond_9
    move/from16 v5, v25

    .line 534
    .line 535
    :goto_b
    const/16 v9, 0x32

    .line 536
    .line 537
    aput-char v9, v46, v25

    .line 538
    .line 539
    new-instance v9, Lvp/l3;

    .line 540
    .line 541
    if-nez v33, :cond_a

    .line 542
    .line 543
    sget-object v0, Lhr/c1;->j:Lhr/c1;

    .line 544
    .line 545
    goto/16 :goto_1f

    .line 546
    .line 547
    :cond_a
    invoke-virtual {v0, v1}, Lhr/c1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 548
    .line 549
    .line 550
    move-result-object v10

    .line 551
    check-cast v10, Lcom/google/android/gms/internal/measurement/s4;

    .line 552
    .line 553
    invoke-virtual {v0, v6}, Lhr/c1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 554
    .line 555
    .line 556
    move-result-object v12

    .line 557
    check-cast v12, Lcom/google/android/gms/internal/measurement/s4;

    .line 558
    .line 559
    invoke-virtual {v0, v11}, Lhr/c1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 560
    .line 561
    .line 562
    move-result-object v18

    .line 563
    check-cast v18, Lcom/google/android/gms/internal/measurement/s4;

    .line 564
    .line 565
    invoke-virtual {v0, v7}, Lhr/c1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 566
    .line 567
    .line 568
    move-result-object v24

    .line 569
    check-cast v24, Lcom/google/android/gms/internal/measurement/s4;

    .line 570
    .line 571
    move-object/from16 v44, v0

    .line 572
    .line 573
    new-instance v0, Lbb/g0;

    .line 574
    .line 575
    move-object/from16 v33, v10

    .line 576
    .line 577
    const/4 v10, 0x4

    .line 578
    invoke-direct {v0, v10}, Lbb/g0;-><init>(I)V

    .line 579
    .line 580
    .line 581
    const-string v10, "2"

    .line 582
    .line 583
    invoke-virtual {v0, v14, v10}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 584
    .line 585
    .line 586
    const/4 v10, 0x1

    .line 587
    if-eq v10, v4, :cond_b

    .line 588
    .line 589
    move-object/from16 v10, v20

    .line 590
    .line 591
    :goto_c
    move/from16 v38, v4

    .line 592
    .line 593
    goto :goto_d

    .line 594
    :cond_b
    move-object/from16 v10, v16

    .line 595
    .line 596
    goto :goto_c

    .line 597
    :goto_d
    const-string v4, "VendorConsent"

    .line 598
    .line 599
    invoke-virtual {v0, v4, v10}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 600
    .line 601
    .line 602
    const/4 v10, 0x1

    .line 603
    if-eq v10, v5, :cond_c

    .line 604
    .line 605
    move-object/from16 v4, v20

    .line 606
    .line 607
    :goto_e
    move/from16 v39, v5

    .line 608
    .line 609
    goto :goto_f

    .line 610
    :cond_c
    move-object/from16 v4, v16

    .line 611
    .line 612
    goto :goto_e

    .line 613
    :goto_f
    const-string v5, "VendorLegitimateInterest"

    .line 614
    .line 615
    invoke-virtual {v0, v5, v4}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 616
    .line 617
    .line 618
    if-eq v15, v10, :cond_d

    .line 619
    .line 620
    move-object/from16 v4, v20

    .line 621
    .line 622
    goto :goto_10

    .line 623
    :cond_d
    move-object/from16 v4, v16

    .line 624
    .line 625
    :goto_10
    invoke-virtual {v0, v13, v4}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 626
    .line 627
    .line 628
    if-eq v2, v10, :cond_e

    .line 629
    .line 630
    move-object/from16 v4, v20

    .line 631
    .line 632
    :goto_11
    move-object/from16 v5, v34

    .line 633
    .line 634
    goto :goto_12

    .line 635
    :cond_e
    move-object/from16 v4, v16

    .line 636
    .line 637
    goto :goto_11

    .line 638
    :goto_12
    invoke-virtual {v0, v5, v4}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 639
    .line 640
    .line 641
    invoke-static/range {v29 .. v29}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 642
    .line 643
    .line 644
    move-result-object v4

    .line 645
    move-object/from16 v5, v31

    .line 646
    .line 647
    invoke-virtual {v0, v5, v4}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 648
    .line 649
    .line 650
    invoke-static/range {v32 .. v32}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 651
    .line 652
    .line 653
    move-result-object v4

    .line 654
    move-object/from16 v5, v28

    .line 655
    .line 656
    invoke-virtual {v0, v5, v4}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 657
    .line 658
    .line 659
    move/from16 v4, v49

    .line 660
    .line 661
    if-eq v4, v10, :cond_f

    .line 662
    .line 663
    move-object/from16 v5, v20

    .line 664
    .line 665
    goto :goto_13

    .line 666
    :cond_f
    move-object/from16 v5, v16

    .line 667
    .line 668
    :goto_13
    const-string v10, "PurposeOneTreatment"

    .line 669
    .line 670
    invoke-virtual {v0, v10, v5}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 671
    .line 672
    .line 673
    const-string v5, "PublisherCC"

    .line 674
    .line 675
    move-object/from16 v10, v50

    .line 676
    .line 677
    invoke-virtual {v0, v5, v10}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 678
    .line 679
    .line 680
    if-eqz v33, :cond_10

    .line 681
    .line 682
    invoke-virtual/range {v33 .. v33}, Lcom/google/android/gms/internal/measurement/s4;->h()I

    .line 683
    .line 684
    .line 685
    move-result v5

    .line 686
    goto :goto_14

    .line 687
    :cond_10
    invoke-virtual/range {v35 .. v35}, Lcom/google/android/gms/internal/measurement/s4;->h()I

    .line 688
    .line 689
    .line 690
    move-result v5

    .line 691
    :goto_14
    const-string v13, "PublisherRestrictions1"

    .line 692
    .line 693
    invoke-static {v5}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 694
    .line 695
    .line 696
    move-result-object v5

    .line 697
    invoke-virtual {v0, v13, v5}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 698
    .line 699
    .line 700
    if-eqz v12, :cond_11

    .line 701
    .line 702
    invoke-virtual {v12}, Lcom/google/android/gms/internal/measurement/s4;->h()I

    .line 703
    .line 704
    .line 705
    move-result v5

    .line 706
    goto :goto_15

    .line 707
    :cond_11
    invoke-virtual/range {v35 .. v35}, Lcom/google/android/gms/internal/measurement/s4;->h()I

    .line 708
    .line 709
    .line 710
    move-result v5

    .line 711
    :goto_15
    const-string v12, "PublisherRestrictions3"

    .line 712
    .line 713
    invoke-static {v5}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 714
    .line 715
    .line 716
    move-result-object v5

    .line 717
    invoke-virtual {v0, v12, v5}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 718
    .line 719
    .line 720
    if-eqz v18, :cond_12

    .line 721
    .line 722
    invoke-virtual/range {v18 .. v18}, Lcom/google/android/gms/internal/measurement/s4;->h()I

    .line 723
    .line 724
    .line 725
    move-result v5

    .line 726
    goto :goto_16

    .line 727
    :cond_12
    invoke-virtual/range {v35 .. v35}, Lcom/google/android/gms/internal/measurement/s4;->h()I

    .line 728
    .line 729
    .line 730
    move-result v5

    .line 731
    :goto_16
    const-string v12, "PublisherRestrictions4"

    .line 732
    .line 733
    invoke-static {v5}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 734
    .line 735
    .line 736
    move-result-object v5

    .line 737
    invoke-virtual {v0, v12, v5}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 738
    .line 739
    .line 740
    if-eqz v24, :cond_13

    .line 741
    .line 742
    invoke-virtual/range {v24 .. v24}, Lcom/google/android/gms/internal/measurement/s4;->h()I

    .line 743
    .line 744
    .line 745
    move-result v5

    .line 746
    goto :goto_17

    .line 747
    :cond_13
    invoke-virtual/range {v35 .. v35}, Lcom/google/android/gms/internal/measurement/s4;->h()I

    .line 748
    .line 749
    .line 750
    move-result v5

    .line 751
    :goto_17
    const-string v12, "PublisherRestrictions7"

    .line 752
    .line 753
    invoke-static {v5}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 754
    .line 755
    .line 756
    move-result-object v5

    .line 757
    invoke-virtual {v0, v12, v5}, Lbb/g0;->q(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 758
    .line 759
    .line 760
    invoke-static {v1, v3, v8}, Lvp/n3;->d(Lcom/google/android/gms/internal/measurement/r4;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 761
    .line 762
    .line 763
    move-result-object v5

    .line 764
    invoke-static {v6, v3, v8}, Lvp/n3;->d(Lcom/google/android/gms/internal/measurement/r4;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 765
    .line 766
    .line 767
    move-result-object v12

    .line 768
    invoke-static {v11, v3, v8}, Lvp/n3;->d(Lcom/google/android/gms/internal/measurement/r4;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 769
    .line 770
    .line 771
    move-result-object v13

    .line 772
    move-object/from16 v24, v1

    .line 773
    .line 774
    invoke-static {v7, v3, v8}, Lvp/n3;->d(Lcom/google/android/gms/internal/measurement/r4;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 775
    .line 776
    .line 777
    move-result-object v1

    .line 778
    move/from16 v32, v2

    .line 779
    .line 780
    const-string v2, "Purpose1"

    .line 781
    .line 782
    invoke-static {v2, v5}, Lhr/q;->b(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 783
    .line 784
    .line 785
    move-object/from16 v47, v2

    .line 786
    .line 787
    const-string v2, "Purpose3"

    .line 788
    .line 789
    invoke-static {v2, v12}, Lhr/q;->b(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 790
    .line 791
    .line 792
    move-object/from16 v49, v2

    .line 793
    .line 794
    const-string v2, "Purpose4"

    .line 795
    .line 796
    invoke-static {v2, v13}, Lhr/q;->b(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 797
    .line 798
    .line 799
    move-object/from16 v51, v2

    .line 800
    .line 801
    const-string v2, "Purpose7"

    .line 802
    .line 803
    invoke-static {v2, v1}, Lhr/q;->b(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 804
    .line 805
    .line 806
    move-object/from16 v54, v1

    .line 807
    .line 808
    move-object/from16 v53, v2

    .line 809
    .line 810
    move-object/from16 v48, v5

    .line 811
    .line 812
    move-object/from16 v50, v12

    .line 813
    .line 814
    move-object/from16 v52, v13

    .line 815
    .line 816
    filled-new-array/range {v47 .. v54}, [Ljava/lang/Object;

    .line 817
    .line 818
    .line 819
    move-result-object v1

    .line 820
    const/4 v2, 0x4

    .line 821
    const/4 v5, 0x0

    .line 822
    invoke-static {v2, v1, v5}, Lhr/c1;->a(I[Ljava/lang/Object;Lbb/g0;)Lhr/c1;

    .line 823
    .line 824
    .line 825
    move-result-object v1

    .line 826
    invoke-virtual {v1}, Lhr/c1;->b()Lhr/k0;

    .line 827
    .line 828
    .line 829
    move-result-object v1

    .line 830
    invoke-virtual {v0, v1}, Lbb/g0;->r(Ljava/lang/Iterable;)V

    .line 831
    .line 832
    .line 833
    move-object/from16 v36, v3

    .line 834
    .line 835
    move/from16 v34, v4

    .line 836
    .line 837
    move-object/from16 v37, v8

    .line 838
    .line 839
    move-object/from16 v35, v10

    .line 840
    .line 841
    move/from16 v33, v15

    .line 842
    .line 843
    move-object/from16 v27, v24

    .line 844
    .line 845
    move-object/from16 v28, v43

    .line 846
    .line 847
    move-object/from16 v29, v44

    .line 848
    .line 849
    move-object/from16 v31, v46

    .line 850
    .line 851
    invoke-static/range {v27 .. v39}, Lvp/n3;->b(Lcom/google/android/gms/internal/measurement/r4;Lhr/c1;Lhr/c1;Lhr/j1;[CIIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Z

    .line 852
    .line 853
    .line 854
    move-result v1

    .line 855
    move-object/from16 v45, v30

    .line 856
    .line 857
    move/from16 v47, v32

    .line 858
    .line 859
    move/from16 v48, v33

    .line 860
    .line 861
    move/from16 v49, v34

    .line 862
    .line 863
    move-object/from16 v50, v35

    .line 864
    .line 865
    move-object/from16 v51, v36

    .line 866
    .line 867
    move-object/from16 v52, v37

    .line 868
    .line 869
    move/from16 v53, v38

    .line 870
    .line 871
    move/from16 v54, v39

    .line 872
    .line 873
    const/4 v10, 0x1

    .line 874
    if-eq v10, v1, :cond_14

    .line 875
    .line 876
    move-object/from16 v28, v20

    .line 877
    .line 878
    :goto_18
    move-object/from16 v42, v6

    .line 879
    .line 880
    goto :goto_19

    .line 881
    :cond_14
    move-object/from16 v28, v16

    .line 882
    .line 883
    goto :goto_18

    .line 884
    :goto_19
    invoke-static/range {v42 .. v54}, Lvp/n3;->b(Lcom/google/android/gms/internal/measurement/r4;Lhr/c1;Lhr/c1;Lhr/j1;[CIIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Z

    .line 885
    .line 886
    .line 887
    move-result v1

    .line 888
    if-eq v10, v1, :cond_15

    .line 889
    .line 890
    move-object/from16 v30, v20

    .line 891
    .line 892
    :goto_1a
    move-object/from16 v42, v11

    .line 893
    .line 894
    goto :goto_1b

    .line 895
    :cond_15
    move-object/from16 v30, v16

    .line 896
    .line 897
    goto :goto_1a

    .line 898
    :goto_1b
    invoke-static/range {v42 .. v54}, Lvp/n3;->b(Lcom/google/android/gms/internal/measurement/r4;Lhr/c1;Lhr/c1;Lhr/j1;[CIIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Z

    .line 899
    .line 900
    .line 901
    move-result v1

    .line 902
    if-eq v10, v1, :cond_16

    .line 903
    .line 904
    move-object/from16 v32, v20

    .line 905
    .line 906
    :goto_1c
    move-object/from16 v42, v7

    .line 907
    .line 908
    goto :goto_1d

    .line 909
    :cond_16
    move-object/from16 v32, v16

    .line 910
    .line 911
    goto :goto_1c

    .line 912
    :goto_1d
    invoke-static/range {v42 .. v54}, Lvp/n3;->b(Lcom/google/android/gms/internal/measurement/r4;Lhr/c1;Lhr/c1;Lhr/j1;[CIIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Z

    .line 913
    .line 914
    .line 915
    move-result v1

    .line 916
    move-object/from16 v2, v46

    .line 917
    .line 918
    if-eq v10, v1, :cond_17

    .line 919
    .line 920
    move-object/from16 v34, v20

    .line 921
    .line 922
    goto :goto_1e

    .line 923
    :cond_17
    move-object/from16 v34, v16

    .line 924
    .line 925
    :goto_1e
    new-instance v1, Ljava/lang/String;

    .line 926
    .line 927
    invoke-direct {v1, v2}, Ljava/lang/String;-><init>([C)V

    .line 928
    .line 929
    .line 930
    const-string v29, "AuthorizePurpose3"

    .line 931
    .line 932
    const-string v27, "AuthorizePurpose1"

    .line 933
    .line 934
    const-string v31, "AuthorizePurpose4"

    .line 935
    .line 936
    const-string v33, "AuthorizePurpose7"

    .line 937
    .line 938
    const-string v35, "PurposeDiagnostics"

    .line 939
    .line 940
    move-object/from16 v36, v1

    .line 941
    .line 942
    filled-new-array/range {v27 .. v36}, [Ljava/lang/Object;

    .line 943
    .line 944
    .line 945
    move-result-object v1

    .line 946
    const/4 v5, 0x0

    .line 947
    const/4 v10, 0x5

    .line 948
    invoke-static {v10, v1, v5}, Lhr/c1;->a(I[Ljava/lang/Object;Lbb/g0;)Lhr/c1;

    .line 949
    .line 950
    .line 951
    move-result-object v1

    .line 952
    invoke-virtual {v1}, Lhr/c1;->b()Lhr/k0;

    .line 953
    .line 954
    .line 955
    move-result-object v1

    .line 956
    invoke-virtual {v0, v1}, Lbb/g0;->r(Ljava/lang/Iterable;)V

    .line 957
    .line 958
    .line 959
    invoke-virtual {v0}, Lbb/g0;->e()Lhr/c1;

    .line 960
    .line 961
    .line 962
    move-result-object v0

    .line 963
    :goto_1f
    invoke-direct {v9, v0}, Lvp/l3;-><init>(Ljava/util/Map;)V

    .line 964
    .line 965
    .line 966
    move-object/from16 v10, v41

    .line 967
    .line 968
    goto/16 :goto_24

    .line 969
    .line 970
    :cond_18
    move-object/from16 v40, v2

    .line 971
    .line 972
    move-object/from16 v41, v7

    .line 973
    .line 974
    move-object v1, v10

    .line 975
    move-object v2, v11

    .line 976
    move-object v7, v12

    .line 977
    invoke-static {v5, v8}, Lvp/n3;->a(Landroid/content/SharedPreferences;Ljava/lang/String;)Ljava/lang/String;

    .line 978
    .line 979
    .line 980
    move-result-object v8

    .line 981
    move-object/from16 v10, v41

    .line 982
    .line 983
    invoke-virtual {v10, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 984
    .line 985
    .line 986
    move-result v11

    .line 987
    if-nez v11, :cond_19

    .line 988
    .line 989
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 990
    .line 991
    .line 992
    move-result v11

    .line 993
    const/16 v12, 0x2f2

    .line 994
    .line 995
    if-le v11, v12, :cond_19

    .line 996
    .line 997
    invoke-virtual {v8, v12}, Ljava/lang/String;->charAt(I)C

    .line 998
    .line 999
    .line 1000
    move-result v8

    .line 1001
    invoke-static {v8}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 1002
    .line 1003
    .line 1004
    move-result-object v8

    .line 1005
    const-string v11, "GoogleConsent"

    .line 1006
    .line 1007
    invoke-virtual {v6, v11, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1008
    .line 1009
    .line 1010
    :cond_19
    const/4 v8, -0x1

    .line 1011
    :try_start_5
    invoke-interface {v5, v15, v8}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 1012
    .line 1013
    .line 1014
    move-result v18
    :try_end_5
    .catch Ljava/lang/ClassCastException; {:try_start_5 .. :try_end_5} :catch_5

    .line 1015
    move/from16 v11, v18

    .line 1016
    .line 1017
    goto :goto_20

    .line 1018
    :catch_5
    move v11, v8

    .line 1019
    :goto_20
    if-eq v11, v8, :cond_1a

    .line 1020
    .line 1021
    invoke-static {v11}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 1022
    .line 1023
    .line 1024
    move-result-object v11

    .line 1025
    invoke-virtual {v6, v13, v11}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1026
    .line 1027
    .line 1028
    :cond_1a
    :try_start_6
    invoke-interface {v5, v9, v8}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 1029
    .line 1030
    .line 1031
    move-result v18
    :try_end_6
    .catch Ljava/lang/ClassCastException; {:try_start_6 .. :try_end_6} :catch_6

    .line 1032
    move/from16 v9, v18

    .line 1033
    .line 1034
    goto :goto_21

    .line 1035
    :catch_6
    move v9, v8

    .line 1036
    :goto_21
    if-eq v9, v8, :cond_1b

    .line 1037
    .line 1038
    invoke-static {v9}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 1039
    .line 1040
    .line 1041
    move-result-object v9

    .line 1042
    invoke-virtual {v6, v7, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1043
    .line 1044
    .line 1045
    :cond_1b
    :try_start_7
    invoke-interface {v5, v0, v8}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 1046
    .line 1047
    .line 1048
    move-result v18
    :try_end_7
    .catch Ljava/lang/ClassCastException; {:try_start_7 .. :try_end_7} :catch_7

    .line 1049
    move/from16 v0, v18

    .line 1050
    .line 1051
    goto :goto_22

    .line 1052
    :catch_7
    move v0, v8

    .line 1053
    :goto_22
    if-eq v0, v8, :cond_1c

    .line 1054
    .line 1055
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 1056
    .line 1057
    .line 1058
    move-result-object v0

    .line 1059
    invoke-virtual {v6, v2, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1060
    .line 1061
    .line 1062
    :cond_1c
    invoke-static {v5, v3}, Lvp/n3;->a(Landroid/content/SharedPreferences;Ljava/lang/String;)Ljava/lang/String;

    .line 1063
    .line 1064
    .line 1065
    move-result-object v0

    .line 1066
    invoke-virtual {v10, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1067
    .line 1068
    .line 1069
    move-result v2

    .line 1070
    if-nez v2, :cond_1d

    .line 1071
    .line 1072
    const-string v2, "PurposeConsents"

    .line 1073
    .line 1074
    invoke-virtual {v6, v2, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1075
    .line 1076
    .line 1077
    :cond_1d
    const/4 v2, -0x1

    .line 1078
    :try_start_8
    invoke-interface {v5, v4, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 1079
    .line 1080
    .line 1081
    move-result v0
    :try_end_8
    .catch Ljava/lang/ClassCastException; {:try_start_8 .. :try_end_8} :catch_8

    .line 1082
    goto :goto_23

    .line 1083
    :catch_8
    move v0, v2

    .line 1084
    :goto_23
    if-eq v0, v2, :cond_1e

    .line 1085
    .line 1086
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 1087
    .line 1088
    .line 1089
    move-result-object v0

    .line 1090
    invoke-virtual {v6, v1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1091
    .line 1092
    .line 1093
    :cond_1e
    new-instance v9, Lvp/l3;

    .line 1094
    .line 1095
    invoke-direct {v9, v6}, Lvp/l3;-><init>(Ljava/util/Map;)V

    .line 1096
    .line 1097
    .line 1098
    :goto_24
    invoke-static/range {v40 .. v40}, Lvp/g1;->k(Lvp/n1;)V

    .line 1099
    .line 1100
    .line 1101
    move-object/from16 v0, v40

    .line 1102
    .line 1103
    iget-object v1, v0, Lvp/p0;->r:Lvp/n0;

    .line 1104
    .line 1105
    const-string v2, "Tcf preferences read"

    .line 1106
    .line 1107
    invoke-virtual {v1, v9, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1108
    .line 1109
    .line 1110
    move-object/from16 v2, v23

    .line 1111
    .line 1112
    iget-object v2, v2, Lvp/g1;->g:Lvp/h;

    .line 1113
    .line 1114
    move-object/from16 v3, v22

    .line 1115
    .line 1116
    const/4 v5, 0x0

    .line 1117
    invoke-virtual {v2, v5, v3}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 1118
    .line 1119
    .line 1120
    move-result v2

    .line 1121
    const-string v3, "_tcf"

    .line 1122
    .line 1123
    const-string v4, "auto"

    .line 1124
    .line 1125
    const-string v5, "_tcfd"

    .line 1126
    .line 1127
    const/16 v6, -0x1e

    .line 1128
    .line 1129
    const-string v7, "Consent generated from Tcf"

    .line 1130
    .line 1131
    if-eqz v2, :cond_29

    .line 1132
    .line 1133
    invoke-virtual/range {v21 .. v21}, Lap0/o;->a0()V

    .line 1134
    .line 1135
    .line 1136
    invoke-virtual/range {v21 .. v21}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 1137
    .line 1138
    .line 1139
    move-result-object v2

    .line 1140
    const-string v8, "stored_tcf_param"

    .line 1141
    .line 1142
    invoke-interface {v2, v8, v10}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1143
    .line 1144
    .line 1145
    move-result-object v2

    .line 1146
    new-instance v8, Ljava/util/HashMap;

    .line 1147
    .line 1148
    invoke-direct {v8}, Ljava/util/HashMap;-><init>()V

    .line 1149
    .line 1150
    .line 1151
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1152
    .line 1153
    .line 1154
    move-result v10

    .line 1155
    if-eqz v10, :cond_1f

    .line 1156
    .line 1157
    new-instance v2, Lvp/l3;

    .line 1158
    .line 1159
    invoke-direct {v2, v8}, Lvp/l3;-><init>(Ljava/util/Map;)V

    .line 1160
    .line 1161
    .line 1162
    :goto_25
    move-object/from16 v8, v21

    .line 1163
    .line 1164
    goto :goto_28

    .line 1165
    :cond_1f
    const-string v10, ";"

    .line 1166
    .line 1167
    invoke-virtual {v2, v10}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 1168
    .line 1169
    .line 1170
    move-result-object v2

    .line 1171
    array-length v10, v2

    .line 1172
    move/from16 v11, v25

    .line 1173
    .line 1174
    :goto_26
    if-ge v11, v10, :cond_21

    .line 1175
    .line 1176
    aget-object v12, v2, v11

    .line 1177
    .line 1178
    const-string v13, "="

    .line 1179
    .line 1180
    invoke-virtual {v12, v13}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 1181
    .line 1182
    .line 1183
    move-result-object v12

    .line 1184
    array-length v13, v12

    .line 1185
    const/4 v15, 0x2

    .line 1186
    if-lt v13, v15, :cond_20

    .line 1187
    .line 1188
    sget-object v13, Lvp/n3;->a:Lhr/x0;

    .line 1189
    .line 1190
    aget-object v15, v12, v25

    .line 1191
    .line 1192
    invoke-virtual {v13, v15}, Lhr/h0;->contains(Ljava/lang/Object;)Z

    .line 1193
    .line 1194
    .line 1195
    move-result v13

    .line 1196
    if-eqz v13, :cond_20

    .line 1197
    .line 1198
    aget-object v13, v12, v25

    .line 1199
    .line 1200
    const/16 v26, 0x1

    .line 1201
    .line 1202
    aget-object v12, v12, v26

    .line 1203
    .line 1204
    invoke-virtual {v8, v13, v12}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1205
    .line 1206
    .line 1207
    goto :goto_27

    .line 1208
    :cond_20
    const/16 v26, 0x1

    .line 1209
    .line 1210
    :goto_27
    add-int/lit8 v11, v11, 0x1

    .line 1211
    .line 1212
    goto :goto_26

    .line 1213
    :cond_21
    new-instance v2, Lvp/l3;

    .line 1214
    .line 1215
    invoke-direct {v2, v8}, Lvp/l3;-><init>(Ljava/util/Map;)V

    .line 1216
    .line 1217
    .line 1218
    goto :goto_25

    .line 1219
    :goto_28
    invoke-virtual {v8, v9}, Lvp/w0;->i0(Lvp/l3;)Z

    .line 1220
    .line 1221
    .line 1222
    move-result v8

    .line 1223
    if-eqz v8, :cond_2b

    .line 1224
    .line 1225
    invoke-virtual {v9}, Lvp/l3;->b()Landroid/os/Bundle;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v8

    .line 1229
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 1230
    .line 1231
    .line 1232
    invoke-virtual {v1, v8, v7}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1233
    .line 1234
    .line 1235
    sget-object v0, Landroid/os/Bundle;->EMPTY:Landroid/os/Bundle;

    .line 1236
    .line 1237
    if-eq v8, v0, :cond_22

    .line 1238
    .line 1239
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1240
    .line 1241
    .line 1242
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 1243
    .line 1244
    .line 1245
    move-result-wide v0

    .line 1246
    move-object/from16 v10, p0

    .line 1247
    .line 1248
    invoke-virtual {v10, v8, v6, v0, v1}, Lvp/j2;->u0(Landroid/os/Bundle;IJ)V

    .line 1249
    .line 1250
    .line 1251
    goto :goto_29

    .line 1252
    :cond_22
    move-object/from16 v10, p0

    .line 1253
    .line 1254
    :goto_29
    new-instance v0, Landroid/os/Bundle;

    .line 1255
    .line 1256
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 1257
    .line 1258
    .line 1259
    iget-object v1, v2, Lvp/l3;->a:Ljava/util/HashMap;

    .line 1260
    .line 1261
    invoke-virtual {v1}, Ljava/util/HashMap;->isEmpty()Z

    .line 1262
    .line 1263
    .line 1264
    move-result v6

    .line 1265
    if-nez v6, :cond_23

    .line 1266
    .line 1267
    invoke-virtual {v1, v14}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1268
    .line 1269
    .line 1270
    move-result-object v1

    .line 1271
    check-cast v1, Ljava/lang/String;

    .line 1272
    .line 1273
    if-nez v1, :cond_23

    .line 1274
    .line 1275
    move-object/from16 v1, v16

    .line 1276
    .line 1277
    goto :goto_2a

    .line 1278
    :cond_23
    move-object/from16 v1, v20

    .line 1279
    .line 1280
    :goto_2a
    invoke-virtual {v9}, Lvp/l3;->b()Landroid/os/Bundle;

    .line 1281
    .line 1282
    .line 1283
    move-result-object v6

    .line 1284
    invoke-virtual {v2}, Lvp/l3;->b()Landroid/os/Bundle;

    .line 1285
    .line 1286
    .line 1287
    move-result-object v2

    .line 1288
    invoke-virtual {v6}, Landroid/os/BaseBundle;->size()I

    .line 1289
    .line 1290
    .line 1291
    move-result v7

    .line 1292
    invoke-virtual {v2}, Landroid/os/BaseBundle;->size()I

    .line 1293
    .line 1294
    .line 1295
    move-result v8

    .line 1296
    if-eq v7, v8, :cond_24

    .line 1297
    .line 1298
    goto :goto_2b

    .line 1299
    :cond_24
    const-string v7, "ad_storage"

    .line 1300
    .line 1301
    invoke-virtual {v6, v7}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 1302
    .line 1303
    .line 1304
    move-result-object v8

    .line 1305
    invoke-virtual {v2, v7}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 1306
    .line 1307
    .line 1308
    move-result-object v7

    .line 1309
    invoke-static {v8, v7}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1310
    .line 1311
    .line 1312
    move-result v7

    .line 1313
    if-nez v7, :cond_25

    .line 1314
    .line 1315
    goto :goto_2b

    .line 1316
    :cond_25
    const-string v7, "ad_personalization"

    .line 1317
    .line 1318
    invoke-virtual {v6, v7}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 1319
    .line 1320
    .line 1321
    move-result-object v8

    .line 1322
    invoke-virtual {v2, v7}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 1323
    .line 1324
    .line 1325
    move-result-object v7

    .line 1326
    invoke-static {v8, v7}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1327
    .line 1328
    .line 1329
    move-result v7

    .line 1330
    if-nez v7, :cond_26

    .line 1331
    .line 1332
    goto :goto_2b

    .line 1333
    :cond_26
    const-string v7, "ad_user_data"

    .line 1334
    .line 1335
    invoke-virtual {v6, v7}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 1336
    .line 1337
    .line 1338
    move-result-object v6

    .line 1339
    invoke-virtual {v2, v7}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 1340
    .line 1341
    .line 1342
    move-result-object v2

    .line 1343
    invoke-static {v6, v2}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1344
    .line 1345
    .line 1346
    move-result v2

    .line 1347
    if-nez v2, :cond_27

    .line 1348
    .line 1349
    :goto_2b
    move-object/from16 v15, v16

    .line 1350
    .line 1351
    goto :goto_2c

    .line 1352
    :cond_27
    move-object/from16 v15, v20

    .line 1353
    .line 1354
    :goto_2c
    invoke-virtual {v1, v15}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 1355
    .line 1356
    .line 1357
    move-result-object v1

    .line 1358
    const-string v2, "_tcfm"

    .line 1359
    .line 1360
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1361
    .line 1362
    .line 1363
    iget-object v1, v9, Lvp/l3;->a:Ljava/util/HashMap;

    .line 1364
    .line 1365
    const-string v2, "PurposeDiagnostics"

    .line 1366
    .line 1367
    invoke-virtual {v1, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1368
    .line 1369
    .line 1370
    move-result-object v1

    .line 1371
    check-cast v1, Ljava/lang/String;

    .line 1372
    .line 1373
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 1374
    .line 1375
    .line 1376
    move-result v2

    .line 1377
    if-eqz v2, :cond_28

    .line 1378
    .line 1379
    const-string v1, "200000"

    .line 1380
    .line 1381
    :cond_28
    const-string v2, "_tcfd2"

    .line 1382
    .line 1383
    invoke-virtual {v0, v2, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1384
    .line 1385
    .line 1386
    invoke-virtual {v9}, Lvp/l3;->c()Ljava/lang/String;

    .line 1387
    .line 1388
    .line 1389
    move-result-object v1

    .line 1390
    invoke-virtual {v0, v5, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1391
    .line 1392
    .line 1393
    invoke-virtual {v10, v4, v3, v0}, Lvp/j2;->h0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1394
    .line 1395
    .line 1396
    return-void

    .line 1397
    :cond_29
    move-object/from16 v10, p0

    .line 1398
    .line 1399
    move-object/from16 v8, v21

    .line 1400
    .line 1401
    invoke-virtual {v8, v9}, Lvp/w0;->i0(Lvp/l3;)Z

    .line 1402
    .line 1403
    .line 1404
    move-result v2

    .line 1405
    if-eqz v2, :cond_2b

    .line 1406
    .line 1407
    invoke-virtual {v9}, Lvp/l3;->b()Landroid/os/Bundle;

    .line 1408
    .line 1409
    .line 1410
    move-result-object v2

    .line 1411
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 1412
    .line 1413
    .line 1414
    invoke-virtual {v1, v2, v7}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1415
    .line 1416
    .line 1417
    sget-object v0, Landroid/os/Bundle;->EMPTY:Landroid/os/Bundle;

    .line 1418
    .line 1419
    if-eq v2, v0, :cond_2a

    .line 1420
    .line 1421
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1422
    .line 1423
    .line 1424
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 1425
    .line 1426
    .line 1427
    move-result-wide v0

    .line 1428
    invoke-virtual {v10, v2, v6, v0, v1}, Lvp/j2;->u0(Landroid/os/Bundle;IJ)V

    .line 1429
    .line 1430
    .line 1431
    :cond_2a
    new-instance v0, Landroid/os/Bundle;

    .line 1432
    .line 1433
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 1434
    .line 1435
    .line 1436
    invoke-virtual {v9}, Lvp/l3;->c()Ljava/lang/String;

    .line 1437
    .line 1438
    .line 1439
    move-result-object v1

    .line 1440
    invoke-virtual {v0, v5, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1441
    .line 1442
    .line 1443
    invoke-virtual {v10, v4, v3, v0}, Lvp/j2;->h0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 1444
    .line 1445
    .line 1446
    :cond_2b
    return-void
.end method

.method public final h0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 7

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Lvp/g1;

    .line 7
    .line 8
    iget-object v0, v0, Lvp/g1;->n:Lto/a;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 14
    .line 15
    .line 16
    move-result-wide v2

    .line 17
    move-object v1, p0

    .line 18
    move-object v5, p1

    .line 19
    move-object v6, p2

    .line 20
    move-object v4, p3

    .line 21
    invoke-virtual/range {v1 .. v6}, Lvp/j2;->i0(JLandroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final i0(JLandroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;)V
    .locals 9

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    iget-object v1, p0, Lvp/j2;->h:Lc2/k;

    .line 5
    .line 6
    const/4 v2, 0x1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-static {p5}, Lvp/d4;->y0(Ljava/lang/String;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    :cond_0
    :goto_0
    move v7, v2

    .line 16
    goto :goto_1

    .line 17
    :cond_1
    const/4 v2, 0x0

    .line 18
    goto :goto_0

    .line 19
    :goto_1
    const/4 v6, 0x1

    .line 20
    const/4 v8, 0x1

    .line 21
    move-object v0, p0

    .line 22
    move-wide v3, p1

    .line 23
    move-object v5, p3

    .line 24
    move-object v1, p4

    .line 25
    move-object v2, p5

    .line 26
    invoke-virtual/range {v0 .. v8}, Lvp/j2;->j0(Ljava/lang/String;Ljava/lang/String;JLandroid/os/Bundle;ZZZ)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public final j0(Ljava/lang/String;Ljava/lang/String;JLandroid/os/Bundle;ZZZ)V
    .locals 28

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v7, p1

    .line 4
    .line 5
    move-object/from16 v8, p2

    .line 6
    .line 7
    move-object/from16 v9, p5

    .line 8
    .line 9
    move/from16 v10, p8

    .line 10
    .line 11
    invoke-static {v7}, Lno/c0;->e(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-static {v9}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1}, Lvp/x;->a0()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1}, Lvp/b0;->b0()V

    .line 21
    .line 22
    .line 23
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v11, v0

    .line 26
    check-cast v11, Lvp/g1;

    .line 27
    .line 28
    invoke-virtual {v11}, Lvp/g1;->a()Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    iget-object v12, v11, Lvp/g1;->k:Lvp/k3;

    .line 33
    .line 34
    iget-object v13, v11, Lvp/g1;->g:Lvp/h;

    .line 35
    .line 36
    iget-object v2, v11, Lvp/g1;->d:Landroid/content/Context;

    .line 37
    .line 38
    iget-object v14, v11, Lvp/g1;->l:Lvp/d4;

    .line 39
    .line 40
    iget-object v15, v11, Lvp/g1;->i:Lvp/p0;

    .line 41
    .line 42
    if-eqz v0, :cond_29

    .line 43
    .line 44
    invoke-virtual {v11}, Lvp/g1;->q()Lvp/h0;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    iget-object v0, v0, Lvp/h0;->o:Ljava/util/List;

    .line 49
    .line 50
    if-eqz v0, :cond_1

    .line 51
    .line 52
    invoke-interface {v0, v8}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-eqz v0, :cond_0

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    invoke-static {v15}, Lvp/g1;->k(Lvp/n1;)V

    .line 60
    .line 61
    .line 62
    iget-object v0, v15, Lvp/p0;->q:Lvp/n0;

    .line 63
    .line 64
    const-string v1, "Dropping non-safelisted event. event name, origin"

    .line 65
    .line 66
    invoke-virtual {v0, v8, v7, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    :cond_1
    :goto_0
    iget-boolean v0, v1, Lvp/j2;->j:Z

    .line 71
    .line 72
    const/4 v3, 0x0

    .line 73
    const/4 v4, 0x1

    .line 74
    if-nez v0, :cond_3

    .line 75
    .line 76
    iput-boolean v4, v1, Lvp/j2;->j:Z

    .line 77
    .line 78
    :try_start_0
    iget-boolean v0, v11, Lvp/g1;->e:Z
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_1

    .line 79
    .line 80
    const-string v5, "com.google.android.gms.tagmanager.TagManagerService"

    .line 81
    .line 82
    if-nez v0, :cond_2

    .line 83
    .line 84
    :try_start_1
    invoke-virtual {v2}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    invoke-static {v5, v4, v0}, Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    goto :goto_1

    .line 93
    :cond_2
    invoke-static {v5}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    move-result-object v0
    :try_end_1
    .catch Ljava/lang/ClassNotFoundException; {:try_start_1 .. :try_end_1} :catch_1

    .line 97
    :goto_1
    :try_start_2
    const-string v5, "initialize"

    .line 98
    .line 99
    const-class v6, Landroid/content/Context;

    .line 100
    .line 101
    filled-new-array {v6}, [Ljava/lang/Class;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    invoke-virtual {v0, v5, v6}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v2

    .line 113
    invoke-virtual {v0, v3, v2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 114
    .line 115
    .line 116
    goto :goto_2

    .line 117
    :catch_0
    move-exception v0

    .line 118
    :try_start_3
    invoke-static {v15}, Lvp/g1;->k(Lvp/n1;)V

    .line 119
    .line 120
    .line 121
    iget-object v2, v15, Lvp/p0;->m:Lvp/n0;

    .line 122
    .line 123
    const-string v5, "Failed to invoke Tag Manager\'s initialize() method"

    .line 124
    .line 125
    invoke-virtual {v2, v0, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_3
    .catch Ljava/lang/ClassNotFoundException; {:try_start_3 .. :try_end_3} :catch_1

    .line 126
    .line 127
    .line 128
    goto :goto_2

    .line 129
    :catch_1
    invoke-static {v15}, Lvp/g1;->k(Lvp/n1;)V

    .line 130
    .line 131
    .line 132
    iget-object v0, v15, Lvp/p0;->p:Lvp/n0;

    .line 133
    .line 134
    const-string v2, "Tag Manager is not found and thus will not be used"

    .line 135
    .line 136
    invoke-virtual {v0, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    :cond_3
    :goto_2
    iget-object v0, v11, Lvp/g1;->m:Lvp/k0;

    .line 140
    .line 141
    iget-object v2, v11, Lvp/g1;->h:Lvp/w0;

    .line 142
    .line 143
    iget-object v5, v11, Lvp/g1;->n:Lto/a;

    .line 144
    .line 145
    sget-object v6, Lvp/z;->f1:Lvp/y;

    .line 146
    .line 147
    invoke-virtual {v13, v3, v6}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 148
    .line 149
    .line 150
    move-result v6

    .line 151
    if-nez v6, :cond_4

    .line 152
    .line 153
    const-string v6, "_cmp"

    .line 154
    .line 155
    invoke-virtual {v6, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v6

    .line 159
    if-eqz v6, :cond_4

    .line 160
    .line 161
    const-string v6, "gclid"

    .line 162
    .line 163
    invoke-virtual {v9, v6}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 164
    .line 165
    .line 166
    move-result v16

    .line 167
    if-eqz v16, :cond_4

    .line 168
    .line 169
    invoke-virtual {v9, v6}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v6

    .line 173
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 174
    .line 175
    .line 176
    move-object/from16 v16, v2

    .line 177
    .line 178
    move-object/from16 v17, v3

    .line 179
    .line 180
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 181
    .line 182
    .line 183
    move-result-wide v2

    .line 184
    move-object/from16 v18, v5

    .line 185
    .line 186
    const-string v5, "auto"

    .line 187
    .line 188
    move/from16 v19, v4

    .line 189
    .line 190
    move-object v4, v6

    .line 191
    const-string v6, "_lgclid"

    .line 192
    .line 193
    move-object/from16 v17, v16

    .line 194
    .line 195
    move-object/from16 v16, v13

    .line 196
    .line 197
    move/from16 v13, v19

    .line 198
    .line 199
    invoke-virtual/range {v1 .. v6}, Lvp/j2;->l0(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    goto :goto_3

    .line 203
    :cond_4
    move-object/from16 v17, v2

    .line 204
    .line 205
    move-object/from16 v18, v5

    .line 206
    .line 207
    move-object/from16 v16, v13

    .line 208
    .line 209
    move v13, v4

    .line 210
    :goto_3
    const/4 v2, 0x0

    .line 211
    if-eqz p6, :cond_5

    .line 212
    .line 213
    sget-object v3, Lvp/d4;->n:[Ljava/lang/String;

    .line 214
    .line 215
    aget-object v3, v3, v2

    .line 216
    .line 217
    invoke-virtual {v3, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v3

    .line 221
    if-nez v3, :cond_5

    .line 222
    .line 223
    invoke-static {v14}, Lvp/g1;->g(Lap0/o;)V

    .line 224
    .line 225
    .line 226
    invoke-static/range {v17 .. v17}, Lvp/g1;->g(Lap0/o;)V

    .line 227
    .line 228
    .line 229
    move-object/from16 v3, v17

    .line 230
    .line 231
    iget-object v4, v3, Lvp/w0;->C:Lun/a;

    .line 232
    .line 233
    invoke-virtual {v4}, Lun/a;->b()Landroid/os/Bundle;

    .line 234
    .line 235
    .line 236
    move-result-object v4

    .line 237
    invoke-virtual {v14, v9, v4}, Lvp/d4;->l0(Landroid/os/Bundle;Landroid/os/Bundle;)V

    .line 238
    .line 239
    .line 240
    goto :goto_4

    .line 241
    :cond_5
    move-object/from16 v3, v17

    .line 242
    .line 243
    :goto_4
    iget-object v4, v1, Lvp/j2;->A:Lro/f;

    .line 244
    .line 245
    const/16 v5, 0x28

    .line 246
    .line 247
    if-nez v10, :cond_a

    .line 248
    .line 249
    const-string v6, "_iap"

    .line 250
    .line 251
    invoke-virtual {v6, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 252
    .line 253
    .line 254
    move-result v6

    .line 255
    if-nez v6, :cond_a

    .line 256
    .line 257
    invoke-static {v14}, Lvp/g1;->g(Lap0/o;)V

    .line 258
    .line 259
    .line 260
    const-string v6, "event"

    .line 261
    .line 262
    invoke-virtual {v14, v6, v8}, Lvp/d4;->a1(Ljava/lang/String;Ljava/lang/String;)Z

    .line 263
    .line 264
    .line 265
    move-result v17

    .line 266
    const/16 v19, 0x2

    .line 267
    .line 268
    if-nez v17, :cond_6

    .line 269
    .line 270
    goto :goto_5

    .line 271
    :cond_6
    sget-object v2, Lvp/t1;->a:[Ljava/lang/String;

    .line 272
    .line 273
    sget-object v13, Lvp/t1;->b:[Ljava/lang/String;

    .line 274
    .line 275
    invoke-virtual {v14, v6, v2, v8, v13}, Lvp/d4;->c1(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Z

    .line 276
    .line 277
    .line 278
    move-result v2

    .line 279
    if-nez v2, :cond_7

    .line 280
    .line 281
    const/16 v19, 0xd

    .line 282
    .line 283
    goto :goto_5

    .line 284
    :cond_7
    iget-object v2, v14, Lap0/o;->e:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast v2, Lvp/g1;

    .line 287
    .line 288
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 289
    .line 290
    .line 291
    invoke-virtual {v14, v6, v5, v8}, Lvp/d4;->d1(Ljava/lang/String;ILjava/lang/String;)Z

    .line 292
    .line 293
    .line 294
    move-result v2

    .line 295
    if-nez v2, :cond_8

    .line 296
    .line 297
    goto :goto_5

    .line 298
    :cond_8
    const/16 v19, 0x0

    .line 299
    .line 300
    :goto_5
    if-eqz v19, :cond_a

    .line 301
    .line 302
    invoke-static {v15}, Lvp/g1;->k(Lvp/n1;)V

    .line 303
    .line 304
    .line 305
    iget-object v1, v15, Lvp/p0;->l:Lvp/n0;

    .line 306
    .line 307
    invoke-virtual {v0, v8}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 308
    .line 309
    .line 310
    move-result-object v0

    .line 311
    const-string v2, "Invalid public event name. Event will not be logged (FE)"

    .line 312
    .line 313
    invoke-virtual {v1, v0, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 314
    .line 315
    .line 316
    invoke-static {v14}, Lvp/g1;->g(Lap0/o;)V

    .line 317
    .line 318
    .line 319
    const/4 v13, 0x1

    .line 320
    invoke-static {v8, v5, v13}, Lvp/d4;->f0(Ljava/lang/String;IZ)Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object v0

    .line 324
    if-eqz v8, :cond_9

    .line 325
    .line 326
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 327
    .line 328
    .line 329
    move-result v2

    .line 330
    goto :goto_6

    .line 331
    :cond_9
    const/4 v2, 0x0

    .line 332
    :goto_6
    const/4 v1, 0x0

    .line 333
    const-string v3, "_ev"

    .line 334
    .line 335
    move-object/from16 p4, v0

    .line 336
    .line 337
    move-object/from16 p1, v1

    .line 338
    .line 339
    move/from16 p5, v2

    .line 340
    .line 341
    move-object/from16 p3, v3

    .line 342
    .line 343
    move-object/from16 p0, v4

    .line 344
    .line 345
    move/from16 p2, v19

    .line 346
    .line 347
    invoke-static/range {p0 .. p5}, Lvp/d4;->q0(Lro/f;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;I)V

    .line 348
    .line 349
    .line 350
    return-void

    .line 351
    :cond_a
    move-object v2, v4

    .line 352
    iget-object v13, v11, Lvp/g1;->o:Lvp/u2;

    .line 353
    .line 354
    invoke-static {v13}, Lvp/g1;->i(Lvp/b0;)V

    .line 355
    .line 356
    .line 357
    const/4 v4, 0x0

    .line 358
    invoke-virtual {v13, v4}, Lvp/u2;->g0(Z)Lvp/r2;

    .line 359
    .line 360
    .line 361
    move-result-object v6

    .line 362
    const-string v4, "_sc"

    .line 363
    .line 364
    if-eqz v6, :cond_b

    .line 365
    .line 366
    invoke-virtual {v9, v4}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 367
    .line 368
    .line 369
    move-result v19

    .line 370
    if-nez v19, :cond_b

    .line 371
    .line 372
    const/4 v5, 0x1

    .line 373
    iput-boolean v5, v6, Lvp/r2;->d:Z

    .line 374
    .line 375
    :cond_b
    if-eqz p6, :cond_c

    .line 376
    .line 377
    if-nez v10, :cond_c

    .line 378
    .line 379
    const/4 v5, 0x1

    .line 380
    goto :goto_7

    .line 381
    :cond_c
    const/4 v5, 0x0

    .line 382
    :goto_7
    invoke-static {v6, v9, v5}, Lvp/d4;->R0(Lvp/r2;Landroid/os/Bundle;Z)V

    .line 383
    .line 384
    .line 385
    const-string v5, "am"

    .line 386
    .line 387
    invoke-virtual {v5, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 388
    .line 389
    .line 390
    move-result v5

    .line 391
    invoke-static {v8}, Lvp/d4;->y0(Ljava/lang/String;)Z

    .line 392
    .line 393
    .line 394
    move-result v6

    .line 395
    if-eqz p6, :cond_f

    .line 396
    .line 397
    move-object/from16 v20, v2

    .line 398
    .line 399
    iget-object v2, v1, Lvp/j2;->h:Lc2/k;

    .line 400
    .line 401
    if-eqz v2, :cond_e

    .line 402
    .line 403
    if-nez v6, :cond_e

    .line 404
    .line 405
    if-eqz v5, :cond_d

    .line 406
    .line 407
    move-wide/from16 v1, p3

    .line 408
    .line 409
    const/16 v21, 0x1

    .line 410
    .line 411
    goto :goto_a

    .line 412
    :cond_d
    invoke-static {v15}, Lvp/g1;->k(Lvp/n1;)V

    .line 413
    .line 414
    .line 415
    iget-object v2, v15, Lvp/p0;->q:Lvp/n0;

    .line 416
    .line 417
    invoke-virtual {v0, v8}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 418
    .line 419
    .line 420
    move-result-object v3

    .line 421
    invoke-virtual {v0, v9}, Lvp/k0;->e(Landroid/os/Bundle;)Ljava/lang/String;

    .line 422
    .line 423
    .line 424
    move-result-object v0

    .line 425
    const-string v4, "Passing event to registered event handler (FE)"

    .line 426
    .line 427
    invoke-virtual {v2, v3, v0, v4}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 428
    .line 429
    .line 430
    iget-object v0, v1, Lvp/j2;->h:Lc2/k;

    .line 431
    .line 432
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 433
    .line 434
    .line 435
    iget-object v6, v1, Lvp/j2;->h:Lc2/k;

    .line 436
    .line 437
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 438
    .line 439
    .line 440
    :try_start_4
    iget-object v0, v6, Lc2/k;->e:Ljava/lang/Object;

    .line 441
    .line 442
    check-cast v0, Lcom/google/android/gms/internal/measurement/r0;

    .line 443
    .line 444
    move-wide/from16 v1, p3

    .line 445
    .line 446
    move-object v4, v7

    .line 447
    move-object v5, v8

    .line 448
    move-object v3, v9

    .line 449
    invoke-interface/range {v0 .. v5}, Lcom/google/android/gms/internal/measurement/r0;->x(JLandroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_4
    .catch Landroid/os/RemoteException; {:try_start_4 .. :try_end_4} :catch_2

    .line 450
    .line 451
    .line 452
    goto/16 :goto_1b

    .line 453
    .line 454
    :catch_2
    move-exception v0

    .line 455
    iget-object v1, v6, Lc2/k;->f:Ljava/lang/Object;

    .line 456
    .line 457
    check-cast v1, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;

    .line 458
    .line 459
    iget-object v1, v1, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 460
    .line 461
    if-eqz v1, :cond_28

    .line 462
    .line 463
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 464
    .line 465
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 466
    .line 467
    .line 468
    iget-object v1, v1, Lvp/p0;->m:Lvp/n0;

    .line 469
    .line 470
    const-string v2, "Event interceptor threw exception"

    .line 471
    .line 472
    invoke-virtual {v1, v0, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 473
    .line 474
    .line 475
    goto/16 :goto_1b

    .line 476
    .line 477
    :cond_e
    :goto_8
    move-wide/from16 v1, p3

    .line 478
    .line 479
    goto :goto_9

    .line 480
    :cond_f
    move-object/from16 v20, v2

    .line 481
    .line 482
    goto :goto_8

    .line 483
    :goto_9
    move/from16 v21, v5

    .line 484
    .line 485
    :goto_a
    invoke-virtual {v11}, Lvp/g1;->c()Z

    .line 486
    .line 487
    .line 488
    move-result v5

    .line 489
    if-nez v5, :cond_10

    .line 490
    .line 491
    goto/16 :goto_1b

    .line 492
    .line 493
    :cond_10
    invoke-static {v14}, Lvp/g1;->g(Lap0/o;)V

    .line 494
    .line 495
    .line 496
    iget-object v5, v14, Lap0/o;->e:Ljava/lang/Object;

    .line 497
    .line 498
    check-cast v5, Lvp/g1;

    .line 499
    .line 500
    invoke-virtual {v14, v8}, Lvp/d4;->e1(Ljava/lang/String;)I

    .line 501
    .line 502
    .line 503
    move-result v6

    .line 504
    if-eqz v6, :cond_12

    .line 505
    .line 506
    invoke-static {v15}, Lvp/g1;->k(Lvp/n1;)V

    .line 507
    .line 508
    .line 509
    iget-object v1, v15, Lvp/p0;->l:Lvp/n0;

    .line 510
    .line 511
    invoke-virtual {v0, v8}, Lvp/k0;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 512
    .line 513
    .line 514
    move-result-object v0

    .line 515
    const-string v2, "Invalid event name. Event will not be logged (FE)"

    .line 516
    .line 517
    invoke-virtual {v1, v0, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 518
    .line 519
    .line 520
    const/16 v0, 0x28

    .line 521
    .line 522
    const/4 v13, 0x1

    .line 523
    invoke-static {v8, v0, v13}, Lvp/d4;->f0(Ljava/lang/String;IZ)Ljava/lang/String;

    .line 524
    .line 525
    .line 526
    move-result-object v0

    .line 527
    if-eqz v8, :cond_11

    .line 528
    .line 529
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 530
    .line 531
    .line 532
    move-result v2

    .line 533
    goto :goto_b

    .line 534
    :cond_11
    const/4 v2, 0x0

    .line 535
    :goto_b
    invoke-static {v14}, Lvp/g1;->g(Lap0/o;)V

    .line 536
    .line 537
    .line 538
    const-string v1, "_ev"

    .line 539
    .line 540
    const/4 v3, 0x0

    .line 541
    move-object/from16 p4, v0

    .line 542
    .line 543
    move-object/from16 p3, v1

    .line 544
    .line 545
    move/from16 p5, v2

    .line 546
    .line 547
    move-object/from16 p1, v3

    .line 548
    .line 549
    move/from16 p2, v6

    .line 550
    .line 551
    move-object/from16 p0, v20

    .line 552
    .line 553
    invoke-static/range {p0 .. p5}, Lvp/d4;->q0(Lro/f;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;I)V

    .line 554
    .line 555
    .line 556
    return-void

    .line 557
    :cond_12
    const-string v0, "_sn"

    .line 558
    .line 559
    const-string v6, "_si"

    .line 560
    .line 561
    move-object/from16 v19, v11

    .line 562
    .line 563
    const-string v11, "_o"

    .line 564
    .line 565
    filled-new-array {v11, v0, v4, v6}, [Ljava/lang/String;

    .line 566
    .line 567
    .line 568
    move-result-object v0

    .line 569
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 570
    .line 571
    .line 572
    move-result-object v0

    .line 573
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 574
    .line 575
    .line 576
    move-result-object v0

    .line 577
    invoke-virtual {v14, v8, v9, v0, v10}, Lvp/d4;->i0(Ljava/lang/String;Landroid/os/Bundle;Ljava/util/List;Z)Landroid/os/Bundle;

    .line 578
    .line 579
    .line 580
    move-result-object v0

    .line 581
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 582
    .line 583
    .line 584
    invoke-static {v13}, Lvp/g1;->i(Lvp/b0;)V

    .line 585
    .line 586
    .line 587
    const/4 v4, 0x0

    .line 588
    invoke-virtual {v13, v4}, Lvp/u2;->g0(Z)Lvp/r2;

    .line 589
    .line 590
    .line 591
    move-result-object v6

    .line 592
    const-string v9, "_ae"

    .line 593
    .line 594
    move-object/from16 p6, v5

    .line 595
    .line 596
    if-eqz v6, :cond_13

    .line 597
    .line 598
    invoke-virtual {v9, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 599
    .line 600
    .line 601
    move-result v6

    .line 602
    if-eqz v6, :cond_13

    .line 603
    .line 604
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 605
    .line 606
    .line 607
    iget-object v6, v12, Lvp/k3;->j:Lc1/i2;

    .line 608
    .line 609
    iget-object v10, v6, Lc1/i2;->g:Ljava/lang/Object;

    .line 610
    .line 611
    check-cast v10, Lvp/k3;

    .line 612
    .line 613
    iget-object v10, v10, Lap0/o;->e:Ljava/lang/Object;

    .line 614
    .line 615
    check-cast v10, Lvp/g1;

    .line 616
    .line 617
    iget-object v10, v10, Lvp/g1;->n:Lto/a;

    .line 618
    .line 619
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 620
    .line 621
    .line 622
    const-wide/16 v22, 0x0

    .line 623
    .line 624
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 625
    .line 626
    .line 627
    move-result-wide v4

    .line 628
    move-object/from16 v20, v11

    .line 629
    .line 630
    iget-wide v10, v6, Lc1/i2;->e:J

    .line 631
    .line 632
    sub-long v10, v4, v10

    .line 633
    .line 634
    iput-wide v4, v6, Lc1/i2;->e:J

    .line 635
    .line 636
    cmp-long v4, v10, v22

    .line 637
    .line 638
    if-lez v4, :cond_14

    .line 639
    .line 640
    invoke-virtual {v14, v0, v10, v11}, Lvp/d4;->H0(Landroid/os/Bundle;J)V

    .line 641
    .line 642
    .line 643
    goto :goto_c

    .line 644
    :cond_13
    move-object/from16 v20, v11

    .line 645
    .line 646
    const-wide/16 v22, 0x0

    .line 647
    .line 648
    :cond_14
    :goto_c
    const-string v4, "auto"

    .line 649
    .line 650
    invoke-virtual {v4, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 651
    .line 652
    .line 653
    move-result v4

    .line 654
    const-string v5, "_ffr"

    .line 655
    .line 656
    if-nez v4, :cond_19

    .line 657
    .line 658
    const-string v4, "_ssr"

    .line 659
    .line 660
    invoke-virtual {v4, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 661
    .line 662
    .line 663
    move-result v4

    .line 664
    if-eqz v4, :cond_19

    .line 665
    .line 666
    invoke-virtual {v0, v5}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 667
    .line 668
    .line 669
    move-result-object v4

    .line 670
    sget v5, Lto/c;->a:I

    .line 671
    .line 672
    if-eqz v4, :cond_17

    .line 673
    .line 674
    invoke-virtual {v4}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 675
    .line 676
    .line 677
    move-result-object v5

    .line 678
    invoke-virtual {v5}, Ljava/lang/String;->isEmpty()Z

    .line 679
    .line 680
    .line 681
    move-result v5

    .line 682
    if-eqz v5, :cond_15

    .line 683
    .line 684
    goto :goto_d

    .line 685
    :cond_15
    if-eqz v4, :cond_16

    .line 686
    .line 687
    invoke-virtual {v4}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 688
    .line 689
    .line 690
    move-result-object v4

    .line 691
    :cond_16
    move-object/from16 v6, p6

    .line 692
    .line 693
    goto :goto_e

    .line 694
    :cond_17
    :goto_d
    move-object/from16 v6, p6

    .line 695
    .line 696
    const/4 v4, 0x0

    .line 697
    :goto_e
    iget-object v5, v6, Lvp/g1;->h:Lvp/w0;

    .line 698
    .line 699
    invoke-static {v5}, Lvp/g1;->g(Lap0/o;)V

    .line 700
    .line 701
    .line 702
    iget-object v5, v5, Lvp/w0;->z:La8/b;

    .line 703
    .line 704
    invoke-virtual {v5}, La8/b;->t()Ljava/lang/String;

    .line 705
    .line 706
    .line 707
    move-result-object v5

    .line 708
    invoke-static {v4, v5}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 709
    .line 710
    .line 711
    move-result v5

    .line 712
    if-nez v5, :cond_18

    .line 713
    .line 714
    iget-object v5, v6, Lvp/g1;->h:Lvp/w0;

    .line 715
    .line 716
    invoke-static {v5}, Lvp/g1;->g(Lap0/o;)V

    .line 717
    .line 718
    .line 719
    iget-object v5, v5, Lvp/w0;->z:La8/b;

    .line 720
    .line 721
    invoke-virtual {v5, v4}, La8/b;->u(Ljava/lang/String;)V

    .line 722
    .line 723
    .line 724
    goto :goto_f

    .line 725
    :cond_18
    iget-object v0, v6, Lvp/g1;->i:Lvp/p0;

    .line 726
    .line 727
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 728
    .line 729
    .line 730
    iget-object v0, v0, Lvp/p0;->q:Lvp/n0;

    .line 731
    .line 732
    const-string v1, "Not logging duplicate session_start_with_rollout event"

    .line 733
    .line 734
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 735
    .line 736
    .line 737
    return-void

    .line 738
    :cond_19
    move-object/from16 v6, p6

    .line 739
    .line 740
    invoke-virtual {v9, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 741
    .line 742
    .line 743
    move-result v4

    .line 744
    if-eqz v4, :cond_1a

    .line 745
    .line 746
    iget-object v4, v6, Lvp/g1;->h:Lvp/w0;

    .line 747
    .line 748
    invoke-static {v4}, Lvp/g1;->g(Lap0/o;)V

    .line 749
    .line 750
    .line 751
    iget-object v4, v4, Lvp/w0;->z:La8/b;

    .line 752
    .line 753
    invoke-virtual {v4}, La8/b;->t()Ljava/lang/String;

    .line 754
    .line 755
    .line 756
    move-result-object v4

    .line 757
    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 758
    .line 759
    .line 760
    move-result v6

    .line 761
    if-nez v6, :cond_1a

    .line 762
    .line 763
    invoke-virtual {v0, v5, v4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 764
    .line 765
    .line 766
    :cond_1a
    :goto_f
    new-instance v10, Ljava/util/ArrayList;

    .line 767
    .line 768
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 769
    .line 770
    .line 771
    invoke-virtual {v10, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 772
    .line 773
    .line 774
    sget-object v4, Lvp/z;->U0:Lvp/y;

    .line 775
    .line 776
    move-object/from16 v5, v16

    .line 777
    .line 778
    const/4 v11, 0x0

    .line 779
    invoke-virtual {v5, v11, v4}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 780
    .line 781
    .line 782
    move-result v4

    .line 783
    if-eqz v4, :cond_1b

    .line 784
    .line 785
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 786
    .line 787
    .line 788
    invoke-virtual {v12}, Lvp/x;->a0()V

    .line 789
    .line 790
    .line 791
    iget-boolean v4, v12, Lvp/k3;->h:Z

    .line 792
    .line 793
    goto :goto_10

    .line 794
    :cond_1b
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 795
    .line 796
    .line 797
    iget-object v4, v3, Lvp/w0;->w:Lvp/v0;

    .line 798
    .line 799
    invoke-virtual {v4}, Lvp/v0;->a()Z

    .line 800
    .line 801
    .line 802
    move-result v4

    .line 803
    :goto_10
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 804
    .line 805
    .line 806
    iget-object v5, v3, Lvp/w0;->t:La8/s1;

    .line 807
    .line 808
    invoke-virtual {v5}, La8/s1;->g()J

    .line 809
    .line 810
    .line 811
    move-result-wide v5

    .line 812
    cmp-long v5, v5, v22

    .line 813
    .line 814
    if-lez v5, :cond_1c

    .line 815
    .line 816
    invoke-virtual {v3, v1, v2}, Lvp/w0;->k0(J)Z

    .line 817
    .line 818
    .line 819
    move-result v5

    .line 820
    if-eqz v5, :cond_1c

    .line 821
    .line 822
    if-eqz v4, :cond_1c

    .line 823
    .line 824
    invoke-static {v15}, Lvp/g1;->k(Lvp/n1;)V

    .line 825
    .line 826
    .line 827
    iget-object v4, v15, Lvp/p0;->r:Lvp/n0;

    .line 828
    .line 829
    const-string v5, "Current session is expired, remove the session number, ID, and engagement time"

    .line 830
    .line 831
    invoke-virtual {v4, v5}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 832
    .line 833
    .line 834
    invoke-virtual/range {v18 .. v18}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 835
    .line 836
    .line 837
    move-object/from16 v16, v3

    .line 838
    .line 839
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 840
    .line 841
    .line 842
    move-result-wide v2

    .line 843
    const-string v6, "_sid"

    .line 844
    .line 845
    const/4 v4, 0x0

    .line 846
    const-string v5, "auto"

    .line 847
    .line 848
    const/16 v17, 0x0

    .line 849
    .line 850
    move-object/from16 v1, p0

    .line 851
    .line 852
    move-object/from16 p5, v9

    .line 853
    .line 854
    move-object/from16 v11, v16

    .line 855
    .line 856
    move-wide/from16 v8, v22

    .line 857
    .line 858
    invoke-virtual/range {v1 .. v6}, Lvp/j2;->l0(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 859
    .line 860
    .line 861
    invoke-virtual/range {v18 .. v18}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 862
    .line 863
    .line 864
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 865
    .line 866
    .line 867
    move-result-wide v2

    .line 868
    const-string v6, "_sno"

    .line 869
    .line 870
    const-string v5, "auto"

    .line 871
    .line 872
    invoke-virtual/range {v1 .. v6}, Lvp/j2;->l0(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 873
    .line 874
    .line 875
    invoke-virtual/range {v18 .. v18}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 876
    .line 877
    .line 878
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 879
    .line 880
    .line 881
    move-result-wide v2

    .line 882
    const-string v6, "_se"

    .line 883
    .line 884
    const-string v5, "auto"

    .line 885
    .line 886
    invoke-virtual/range {v1 .. v6}, Lvp/j2;->l0(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 887
    .line 888
    .line 889
    move-object v6, v1

    .line 890
    iget-object v1, v11, Lvp/w0;->u:La8/s1;

    .line 891
    .line 892
    invoke-virtual {v1, v8, v9}, La8/s1;->h(J)V

    .line 893
    .line 894
    .line 895
    goto :goto_11

    .line 896
    :cond_1c
    move-object/from16 v6, p0

    .line 897
    .line 898
    move-object/from16 p5, v9

    .line 899
    .line 900
    move-wide/from16 v8, v22

    .line 901
    .line 902
    const/16 v17, 0x0

    .line 903
    .line 904
    :goto_11
    const-string v1, "extend_session"

    .line 905
    .line 906
    invoke-virtual {v0, v1, v8, v9}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;J)J

    .line 907
    .line 908
    .line 909
    move-result-wide v1

    .line 910
    const-wide/16 v3, 0x1

    .line 911
    .line 912
    cmp-long v1, v1, v3

    .line 913
    .line 914
    if-nez v1, :cond_1d

    .line 915
    .line 916
    invoke-static {v15}, Lvp/g1;->k(Lvp/n1;)V

    .line 917
    .line 918
    .line 919
    iget-object v1, v15, Lvp/p0;->r:Lvp/n0;

    .line 920
    .line 921
    const-string v2, "EXTEND_SESSION param attached: initiate a new session or extend the current active session"

    .line 922
    .line 923
    invoke-virtual {v1, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 924
    .line 925
    .line 926
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 927
    .line 928
    .line 929
    iget-object v1, v12, Lvp/k3;->i:Lt1/j0;

    .line 930
    .line 931
    move-wide/from16 v4, p3

    .line 932
    .line 933
    invoke-virtual {v1, v4, v5}, Lt1/j0;->q(J)V

    .line 934
    .line 935
    .line 936
    goto :goto_12

    .line 937
    :cond_1d
    move-wide/from16 v4, p3

    .line 938
    .line 939
    :goto_12
    new-instance v1, Ljava/util/ArrayList;

    .line 940
    .line 941
    invoke-virtual {v0}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 942
    .line 943
    .line 944
    move-result-object v2

    .line 945
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 946
    .line 947
    .line 948
    invoke-static {v1}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    .line 949
    .line 950
    .line 951
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 952
    .line 953
    .line 954
    move-result v2

    .line 955
    move/from16 v3, v17

    .line 956
    .line 957
    :goto_13
    if-ge v3, v2, :cond_22

    .line 958
    .line 959
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 960
    .line 961
    .line 962
    move-result-object v8

    .line 963
    check-cast v8, Ljava/lang/String;

    .line 964
    .line 965
    if-eqz v8, :cond_21

    .line 966
    .line 967
    invoke-static {v14}, Lvp/g1;->g(Lap0/o;)V

    .line 968
    .line 969
    .line 970
    invoke-virtual {v0, v8}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 971
    .line 972
    .line 973
    move-result-object v9

    .line 974
    instance-of v11, v9, Landroid/os/Bundle;

    .line 975
    .line 976
    if-eqz v11, :cond_1e

    .line 977
    .line 978
    const/4 v11, 0x1

    .line 979
    new-array v15, v11, [Landroid/os/Bundle;

    .line 980
    .line 981
    check-cast v9, Landroid/os/Bundle;

    .line 982
    .line 983
    aput-object v9, v15, v17

    .line 984
    .line 985
    move-object v9, v15

    .line 986
    goto :goto_14

    .line 987
    :cond_1e
    instance-of v11, v9, [Landroid/os/Parcelable;

    .line 988
    .line 989
    if-eqz v11, :cond_1f

    .line 990
    .line 991
    check-cast v9, [Landroid/os/Parcelable;

    .line 992
    .line 993
    array-length v11, v9

    .line 994
    const-class v15, [Landroid/os/Bundle;

    .line 995
    .line 996
    invoke-static {v9, v11, v15}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;ILjava/lang/Class;)[Ljava/lang/Object;

    .line 997
    .line 998
    .line 999
    move-result-object v9

    .line 1000
    check-cast v9, [Landroid/os/Bundle;

    .line 1001
    .line 1002
    goto :goto_14

    .line 1003
    :cond_1f
    instance-of v11, v9, Ljava/util/ArrayList;

    .line 1004
    .line 1005
    if-eqz v11, :cond_20

    .line 1006
    .line 1007
    check-cast v9, Ljava/util/ArrayList;

    .line 1008
    .line 1009
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 1010
    .line 1011
    .line 1012
    move-result v11

    .line 1013
    new-array v11, v11, [Landroid/os/Bundle;

    .line 1014
    .line 1015
    invoke-virtual {v9, v11}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 1016
    .line 1017
    .line 1018
    move-result-object v9

    .line 1019
    check-cast v9, [Landroid/os/Bundle;

    .line 1020
    .line 1021
    goto :goto_14

    .line 1022
    :cond_20
    const/4 v9, 0x0

    .line 1023
    :goto_14
    if-eqz v9, :cond_21

    .line 1024
    .line 1025
    invoke-virtual {v0, v8, v9}, Landroid/os/Bundle;->putParcelableArray(Ljava/lang/String;[Landroid/os/Parcelable;)V

    .line 1026
    .line 1027
    .line 1028
    :cond_21
    add-int/lit8 v3, v3, 0x1

    .line 1029
    .line 1030
    goto :goto_13

    .line 1031
    :cond_22
    move/from16 v8, v17

    .line 1032
    .line 1033
    :goto_15
    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    .line 1034
    .line 1035
    .line 1036
    move-result v0

    .line 1037
    if-ge v8, v0, :cond_27

    .line 1038
    .line 1039
    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1040
    .line 1041
    .line 1042
    move-result-object v0

    .line 1043
    check-cast v0, Landroid/os/Bundle;

    .line 1044
    .line 1045
    if-eqz v8, :cond_23

    .line 1046
    .line 1047
    const-string v1, "_ep"

    .line 1048
    .line 1049
    :goto_16
    move-object/from16 v9, v20

    .line 1050
    .line 1051
    goto :goto_17

    .line 1052
    :cond_23
    move-object/from16 v1, p2

    .line 1053
    .line 1054
    goto :goto_16

    .line 1055
    :goto_17
    invoke-virtual {v0, v9, v7}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 1056
    .line 1057
    .line 1058
    if-eqz p7, :cond_24

    .line 1059
    .line 1060
    invoke-virtual {v14, v0}, Lvp/d4;->B0(Landroid/os/Bundle;)Landroid/os/Bundle;

    .line 1061
    .line 1062
    .line 1063
    move-result-object v0

    .line 1064
    :cond_24
    move-object v11, v0

    .line 1065
    new-instance v26, Lvp/t;

    .line 1066
    .line 1067
    new-instance v2, Lvp/s;

    .line 1068
    .line 1069
    invoke-direct {v2, v11}, Lvp/s;-><init>(Landroid/os/Bundle;)V

    .line 1070
    .line 1071
    .line 1072
    move-object v3, v7

    .line 1073
    move-object/from16 v0, v26

    .line 1074
    .line 1075
    invoke-direct/range {v0 .. v5}, Lvp/t;-><init>(Ljava/lang/String;Lvp/s;Ljava/lang/String;J)V

    .line 1076
    .line 1077
    .line 1078
    invoke-virtual/range {v19 .. v19}, Lvp/g1;->o()Lvp/d3;

    .line 1079
    .line 1080
    .line 1081
    move-result-object v1

    .line 1082
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1083
    .line 1084
    .line 1085
    invoke-virtual {v1}, Lvp/x;->a0()V

    .line 1086
    .line 1087
    .line 1088
    invoke-virtual {v1}, Lvp/b0;->b0()V

    .line 1089
    .line 1090
    .line 1091
    invoke-virtual {v1}, Lvp/d3;->m0()V

    .line 1092
    .line 1093
    .line 1094
    iget-object v2, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 1095
    .line 1096
    check-cast v2, Lvp/g1;

    .line 1097
    .line 1098
    invoke-virtual {v2}, Lvp/g1;->n()Lvp/j0;

    .line 1099
    .line 1100
    .line 1101
    move-result-object v2

    .line 1102
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1103
    .line 1104
    .line 1105
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 1106
    .line 1107
    .line 1108
    move-result-object v3

    .line 1109
    move/from16 v4, v17

    .line 1110
    .line 1111
    invoke-static {v0, v3, v4}, Ltt/f;->a(Lvp/t;Landroid/os/Parcel;I)V

    .line 1112
    .line 1113
    .line 1114
    invoke-virtual {v3}, Landroid/os/Parcel;->marshall()[B

    .line 1115
    .line 1116
    .line 1117
    move-result-object v4

    .line 1118
    invoke-virtual {v3}, Landroid/os/Parcel;->recycle()V

    .line 1119
    .line 1120
    .line 1121
    array-length v3, v4

    .line 1122
    const/high16 v5, 0x20000

    .line 1123
    .line 1124
    if-le v3, v5, :cond_25

    .line 1125
    .line 1126
    iget-object v2, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 1127
    .line 1128
    check-cast v2, Lvp/g1;

    .line 1129
    .line 1130
    iget-object v2, v2, Lvp/g1;->i:Lvp/p0;

    .line 1131
    .line 1132
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 1133
    .line 1134
    .line 1135
    iget-object v2, v2, Lvp/p0;->k:Lvp/n0;

    .line 1136
    .line 1137
    const-string v3, "Event is too long for local database. Sending event directly to service"

    .line 1138
    .line 1139
    invoke-virtual {v2, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1140
    .line 1141
    .line 1142
    const/16 v25, 0x0

    .line 1143
    .line 1144
    :goto_18
    const/4 v5, 0x1

    .line 1145
    goto :goto_19

    .line 1146
    :cond_25
    const/4 v3, 0x0

    .line 1147
    invoke-virtual {v2, v3, v4}, Lvp/j0;->h0(I[B)Z

    .line 1148
    .line 1149
    .line 1150
    move-result v2

    .line 1151
    move/from16 v25, v2

    .line 1152
    .line 1153
    goto :goto_18

    .line 1154
    :goto_19
    invoke-virtual {v1, v5}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 1155
    .line 1156
    .line 1157
    move-result-object v24

    .line 1158
    new-instance v22, Lio/j;

    .line 1159
    .line 1160
    const/16 v27, 0x2

    .line 1161
    .line 1162
    move-object/from16 v26, v0

    .line 1163
    .line 1164
    move-object/from16 v23, v1

    .line 1165
    .line 1166
    invoke-direct/range {v22 .. v27}, Lio/j;-><init>(Lvp/d3;Lvp/f4;ZLoo/a;I)V

    .line 1167
    .line 1168
    .line 1169
    move-object/from16 v1, v22

    .line 1170
    .line 1171
    move-object/from16 v0, v23

    .line 1172
    .line 1173
    invoke-virtual {v0, v1}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 1174
    .line 1175
    .line 1176
    if-nez v21, :cond_26

    .line 1177
    .line 1178
    iget-object v0, v6, Lvp/j2;->i:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 1179
    .line 1180
    invoke-virtual {v0}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 1181
    .line 1182
    .line 1183
    move-result-object v7

    .line 1184
    :goto_1a
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 1185
    .line 1186
    .line 1187
    move-result v0

    .line 1188
    if-eqz v0, :cond_26

    .line 1189
    .line 1190
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1191
    .line 1192
    .line 1193
    move-result-object v0

    .line 1194
    check-cast v0, Lvp/u1;

    .line 1195
    .line 1196
    new-instance v3, Landroid/os/Bundle;

    .line 1197
    .line 1198
    invoke-direct {v3, v11}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 1199
    .line 1200
    .line 1201
    move-object/from16 v4, p1

    .line 1202
    .line 1203
    move-object/from16 v5, p2

    .line 1204
    .line 1205
    move-wide/from16 v1, p3

    .line 1206
    .line 1207
    invoke-interface/range {v0 .. v5}, Lvp/u1;->a(JLandroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;)V

    .line 1208
    .line 1209
    .line 1210
    goto :goto_1a

    .line 1211
    :cond_26
    move-object/from16 v5, p2

    .line 1212
    .line 1213
    add-int/lit8 v8, v8, 0x1

    .line 1214
    .line 1215
    move-object/from16 v7, p1

    .line 1216
    .line 1217
    move-wide/from16 v4, p3

    .line 1218
    .line 1219
    move-object/from16 v20, v9

    .line 1220
    .line 1221
    const/16 v17, 0x0

    .line 1222
    .line 1223
    goto/16 :goto_15

    .line 1224
    .line 1225
    :cond_27
    move-object/from16 v5, p2

    .line 1226
    .line 1227
    invoke-static {v13}, Lvp/g1;->i(Lvp/b0;)V

    .line 1228
    .line 1229
    .line 1230
    const/4 v4, 0x0

    .line 1231
    invoke-virtual {v13, v4}, Lvp/u2;->g0(Z)Lvp/r2;

    .line 1232
    .line 1233
    .line 1234
    move-result-object v0

    .line 1235
    if-eqz v0, :cond_28

    .line 1236
    .line 1237
    move-object/from16 v0, p5

    .line 1238
    .line 1239
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1240
    .line 1241
    .line 1242
    move-result v0

    .line 1243
    if-eqz v0, :cond_28

    .line 1244
    .line 1245
    invoke-static {v12}, Lvp/g1;->i(Lvp/b0;)V

    .line 1246
    .line 1247
    .line 1248
    invoke-virtual/range {v18 .. v18}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1249
    .line 1250
    .line 1251
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 1252
    .line 1253
    .line 1254
    move-result-wide v0

    .line 1255
    iget-object v2, v12, Lvp/k3;->j:Lc1/i2;

    .line 1256
    .line 1257
    const/4 v13, 0x1

    .line 1258
    invoke-virtual {v2, v0, v1, v13, v13}, Lc1/i2;->i(JZZ)Z

    .line 1259
    .line 1260
    .line 1261
    :cond_28
    :goto_1b
    return-void

    .line 1262
    :cond_29
    invoke-static {v15}, Lvp/g1;->k(Lvp/n1;)V

    .line 1263
    .line 1264
    .line 1265
    iget-object v0, v15, Lvp/p0;->q:Lvp/n0;

    .line 1266
    .line 1267
    const-string v1, "Event not sent since app measurement is disabled"

    .line 1268
    .line 1269
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 1270
    .line 1271
    .line 1272
    return-void
.end method

.method public final k0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;ZJ)V
    .locals 11

    .line 1
    iget-object v2, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v2, Lvp/g1;

    .line 4
    .line 5
    const/4 v4, 0x0

    .line 6
    const/16 v5, 0x18

    .line 7
    .line 8
    if-eqz p4, :cond_0

    .line 9
    .line 10
    iget-object v6, v2, Lvp/g1;->l:Lvp/d4;

    .line 11
    .line 12
    invoke-static {v6}, Lvp/g1;->g(Lap0/o;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v6, p2}, Lvp/d4;->f1(Ljava/lang/String;)I

    .line 16
    .line 17
    .line 18
    move-result v6

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    iget-object v6, v2, Lvp/g1;->l:Lvp/d4;

    .line 21
    .line 22
    invoke-static {v6}, Lvp/g1;->g(Lap0/o;)V

    .line 23
    .line 24
    .line 25
    const-string v7, "user property"

    .line 26
    .line 27
    invoke-virtual {v6, v7, p2}, Lvp/d4;->a1(Ljava/lang/String;Ljava/lang/String;)Z

    .line 28
    .line 29
    .line 30
    move-result v8

    .line 31
    const/4 v9, 0x6

    .line 32
    if-nez v8, :cond_1

    .line 33
    .line 34
    :goto_0
    move v6, v9

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    sget-object v8, Lvp/t1;->i:[Ljava/lang/String;

    .line 37
    .line 38
    const/4 v10, 0x0

    .line 39
    invoke-virtual {v6, v7, v8, p2, v10}, Lvp/d4;->c1(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Z

    .line 40
    .line 41
    .line 42
    move-result v8

    .line 43
    if-nez v8, :cond_2

    .line 44
    .line 45
    const/16 v6, 0xf

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    iget-object v8, v6, Lap0/o;->e:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v8, Lvp/g1;

    .line 51
    .line 52
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v6, v7, v5, p2}, Lvp/d4;->d1(Ljava/lang/String;ILjava/lang/String;)Z

    .line 56
    .line 57
    .line 58
    move-result v6

    .line 59
    if-nez v6, :cond_3

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_3
    move v6, v4

    .line 63
    :goto_1
    iget-object v7, p0, Lvp/j2;->A:Lro/f;

    .line 64
    .line 65
    const/4 v8, 0x1

    .line 66
    if-eqz v6, :cond_5

    .line 67
    .line 68
    iget-object v0, v2, Lvp/g1;->l:Lvp/d4;

    .line 69
    .line 70
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 71
    .line 72
    .line 73
    invoke-static {p2, v5, v8}, Lvp/d4;->f0(Ljava/lang/String;IZ)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    if-eqz p2, :cond_4

    .line 78
    .line 79
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 80
    .line 81
    .line 82
    move-result v4

    .line 83
    :cond_4
    iget-object v1, v2, Lvp/g1;->l:Lvp/d4;

    .line 84
    .line 85
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 86
    .line 87
    .line 88
    const/4 v1, 0x0

    .line 89
    const-string v2, "_ev"

    .line 90
    .line 91
    move-object p4, v0

    .line 92
    move-object p1, v1

    .line 93
    move-object p3, v2

    .line 94
    move/from16 p5, v4

    .line 95
    .line 96
    move p2, v6

    .line 97
    move-object p0, v7

    .line 98
    invoke-static/range {p0 .. p5}, Lvp/d4;->q0(Lro/f;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;I)V

    .line 99
    .line 100
    .line 101
    return-void

    .line 102
    :cond_5
    move-object v6, v7

    .line 103
    if-nez p1, :cond_6

    .line 104
    .line 105
    const-string v7, "app"

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_6
    move-object v7, p1

    .line 109
    :goto_2
    if-eqz p3, :cond_b

    .line 110
    .line 111
    iget-object v9, v2, Lvp/g1;->l:Lvp/d4;

    .line 112
    .line 113
    invoke-static {v9}, Lvp/g1;->g(Lap0/o;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v9, p3, p2}, Lvp/d4;->n0(Ljava/lang/Object;Ljava/lang/String;)I

    .line 117
    .line 118
    .line 119
    move-result v10

    .line 120
    if-eqz v10, :cond_9

    .line 121
    .line 122
    invoke-static {v9}, Lvp/g1;->g(Lap0/o;)V

    .line 123
    .line 124
    .line 125
    invoke-static {p2, v5, v8}, Lvp/d4;->f0(Ljava/lang/String;IZ)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    instance-of v3, p3, Ljava/lang/String;

    .line 130
    .line 131
    if-nez v3, :cond_7

    .line 132
    .line 133
    instance-of v3, p3, Ljava/lang/CharSequence;

    .line 134
    .line 135
    if-eqz v3, :cond_8

    .line 136
    .line 137
    :cond_7
    invoke-virtual {p3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 142
    .line 143
    .line 144
    move-result v4

    .line 145
    :cond_8
    iget-object v0, v2, Lvp/g1;->l:Lvp/d4;

    .line 146
    .line 147
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 148
    .line 149
    .line 150
    const/4 v0, 0x0

    .line 151
    const-string v2, "_ev"

    .line 152
    .line 153
    move-object p1, v0

    .line 154
    move-object p4, v1

    .line 155
    move-object p3, v2

    .line 156
    move/from16 p5, v4

    .line 157
    .line 158
    move-object p0, v6

    .line 159
    move p2, v10

    .line 160
    invoke-static/range {p0 .. p5}, Lvp/d4;->q0(Lro/f;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;I)V

    .line 161
    .line 162
    .line 163
    return-void

    .line 164
    :cond_9
    invoke-static {v9}, Lvp/g1;->g(Lap0/o;)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v9, p3, p2}, Lvp/d4;->o0(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v4

    .line 171
    if-eqz v4, :cond_a

    .line 172
    .line 173
    iget-object v8, v2, Lvp/g1;->j:Lvp/e1;

    .line 174
    .line 175
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 176
    .line 177
    .line 178
    new-instance v0, Lvp/j1;

    .line 179
    .line 180
    move-object v2, v7

    .line 181
    const/4 v7, 0x1

    .line 182
    move-object v1, p0

    .line 183
    move-object v3, p2

    .line 184
    move-wide/from16 v5, p5

    .line 185
    .line 186
    invoke-direct/range {v0 .. v7}, Lvp/j1;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;JI)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v8, v0}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 190
    .line 191
    .line 192
    :cond_a
    return-void

    .line 193
    :cond_b
    iget-object v8, v2, Lvp/g1;->j:Lvp/e1;

    .line 194
    .line 195
    invoke-static {v8}, Lvp/g1;->k(Lvp/n1;)V

    .line 196
    .line 197
    .line 198
    new-instance v0, Lvp/j1;

    .line 199
    .line 200
    move-object v2, v7

    .line 201
    const/4 v7, 0x1

    .line 202
    const/4 v4, 0x0

    .line 203
    move-object v1, p0

    .line 204
    move-object v3, p2

    .line 205
    move-wide/from16 v5, p5

    .line 206
    .line 207
    invoke-direct/range {v0 .. v7}, Lvp/j1;-><init>(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;JI)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {v8, v0}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 211
    .line 212
    .line 213
    return-void
.end method

.method public final l0(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V
    .locals 13

    .line 1
    move-object/from16 v0, p3

    .line 2
    .line 3
    iget-object v2, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v2, Lvp/g1;

    .line 6
    .line 7
    invoke-static/range {p4 .. p4}, Lno/c0;->e(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-static/range {p5 .. p5}, Lno/c0;->e(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 17
    .line 18
    .line 19
    const-string v1, "allow_personalized_ads"

    .line 20
    .line 21
    move-object/from16 v3, p5

    .line 22
    .line 23
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    const/4 v4, 0x1

    .line 28
    if-eqz v1, :cond_4

    .line 29
    .line 30
    instance-of v1, v0, Ljava/lang/String;

    .line 31
    .line 32
    const-string v5, "_npa"

    .line 33
    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    move-object v1, v0

    .line 37
    check-cast v1, Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 40
    .line 41
    .line 42
    move-result v6

    .line 43
    if-nez v6, :cond_2

    .line 44
    .line 45
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 46
    .line 47
    invoke-virtual {v1, v0}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    const-string v1, "false"

    .line 52
    .line 53
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    const-wide/16 v6, 0x1

    .line 58
    .line 59
    if-eq v4, v0, :cond_0

    .line 60
    .line 61
    const-wide/16 v8, 0x0

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_0
    move-wide v8, v6

    .line 65
    :goto_0
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    iget-object v3, v2, Lvp/g1;->h:Lvp/w0;

    .line 70
    .line 71
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 72
    .line 73
    .line 74
    iget-object v3, v3, Lvp/w0;->q:La8/b;

    .line 75
    .line 76
    cmp-long v6, v8, v6

    .line 77
    .line 78
    if-nez v6, :cond_1

    .line 79
    .line 80
    const-string v1, "true"

    .line 81
    .line 82
    :cond_1
    invoke-virtual {v3, v1}, La8/b;->u(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_2
    if-nez v0, :cond_3

    .line 87
    .line 88
    iget-object v1, v2, Lvp/g1;->h:Lvp/w0;

    .line 89
    .line 90
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 91
    .line 92
    .line 93
    iget-object v1, v1, Lvp/w0;->q:La8/b;

    .line 94
    .line 95
    const-string v3, "unset"

    .line 96
    .line 97
    invoke-virtual {v1, v3}, La8/b;->u(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_3
    move-object v5, v3

    .line 102
    :goto_1
    iget-object v1, v2, Lvp/g1;->i:Lvp/p0;

    .line 103
    .line 104
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 105
    .line 106
    .line 107
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 108
    .line 109
    const-string v3, "Setting user property(FE)"

    .line 110
    .line 111
    const-string v6, "non_personalized_ads(_npa)"

    .line 112
    .line 113
    invoke-virtual {v1, v6, v0, v3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    move-object v11, v5

    .line 117
    :goto_2
    move-object v10, v0

    .line 118
    goto :goto_3

    .line 119
    :cond_4
    move-object v11, v3

    .line 120
    goto :goto_2

    .line 121
    :goto_3
    invoke-virtual {v2}, Lvp/g1;->a()Z

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    if-nez v0, :cond_5

    .line 126
    .line 127
    iget-object v0, v2, Lvp/g1;->i:Lvp/p0;

    .line 128
    .line 129
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 130
    .line 131
    .line 132
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 133
    .line 134
    const-string v1, "User property not set since app measurement is disabled"

    .line 135
    .line 136
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    return-void

    .line 140
    :cond_5
    invoke-virtual {v2}, Lvp/g1;->c()Z

    .line 141
    .line 142
    .line 143
    move-result v0

    .line 144
    if-nez v0, :cond_6

    .line 145
    .line 146
    return-void

    .line 147
    :cond_6
    new-instance v7, Lvp/b4;

    .line 148
    .line 149
    move-wide v8, p1

    .line 150
    move-object/from16 v12, p4

    .line 151
    .line 152
    invoke-direct/range {v7 .. v12}, Lvp/b4;-><init>(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v2}, Lvp/g1;->o()Lvp/d3;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v0}, Lvp/b0;->b0()V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v0}, Lvp/d3;->m0()V

    .line 166
    .line 167
    .line 168
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v1, Lvp/g1;

    .line 171
    .line 172
    invoke-virtual {v1}, Lvp/g1;->n()Lvp/j0;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 177
    .line 178
    .line 179
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 180
    .line 181
    .line 182
    move-result-object v2

    .line 183
    invoke-static {v7, v2}, Ltt/f;->b(Lvp/b4;Landroid/os/Parcel;)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v2}, Landroid/os/Parcel;->marshall()[B

    .line 187
    .line 188
    .line 189
    move-result-object v3

    .line 190
    invoke-virtual {v2}, Landroid/os/Parcel;->recycle()V

    .line 191
    .line 192
    .line 193
    array-length v2, v3

    .line 194
    const/high16 v5, 0x20000

    .line 195
    .line 196
    if-le v2, v5, :cond_7

    .line 197
    .line 198
    iget-object v1, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v1, Lvp/g1;

    .line 201
    .line 202
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 203
    .line 204
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 205
    .line 206
    .line 207
    iget-object v1, v1, Lvp/p0;->k:Lvp/n0;

    .line 208
    .line 209
    const-string v2, "User property too long for local database. Sending directly to service"

    .line 210
    .line 211
    invoke-virtual {v1, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    const/4 v1, 0x0

    .line 215
    goto :goto_4

    .line 216
    :cond_7
    invoke-virtual {v1, v4, v3}, Lvp/j0;->h0(I[B)Z

    .line 217
    .line 218
    .line 219
    move-result v1

    .line 220
    :goto_4
    invoke-virtual {v0, v4}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 221
    .line 222
    .line 223
    move-result-object v2

    .line 224
    new-instance v3, Lio/j;

    .line 225
    .line 226
    const/4 v4, 0x1

    .line 227
    move-object p1, v0

    .line 228
    move/from16 p3, v1

    .line 229
    .line 230
    move-object p2, v2

    .line 231
    move-object p0, v3

    .line 232
    move/from16 p5, v4

    .line 233
    .line 234
    move-object/from16 p4, v7

    .line 235
    .line 236
    invoke-direct/range {p0 .. p5}, Lio/j;-><init>(Lvp/d3;Lvp/f4;ZLoo/a;I)V

    .line 237
    .line 238
    .line 239
    move-object v1, p0

    .line 240
    invoke-virtual {v0, v1}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 241
    .line 242
    .line 243
    return-void
.end method

.method public final m0()V
    .locals 8

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lvp/g1;

    .line 10
    .line 11
    invoke-virtual {v0}, Lvp/g1;->c()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    goto/16 :goto_0

    .line 18
    .line 19
    :cond_0
    iget-object v1, v0, Lvp/g1;->g:Lvp/h;

    .line 20
    .line 21
    iget-object v2, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v2, Lvp/g1;

    .line 24
    .line 25
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    const-string v2, "google_analytics_deferred_deep_link_enabled"

    .line 29
    .line 30
    invoke-virtual {v1, v2}, Lvp/h;->m0(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_1

    .line 41
    .line 42
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 43
    .line 44
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 45
    .line 46
    .line 47
    iget-object v1, v1, Lvp/p0;->q:Lvp/n0;

    .line 48
    .line 49
    const-string v2, "Deferred Deep Link feature enabled."

    .line 50
    .line 51
    invoke-virtual {v1, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iget-object v1, v0, Lvp/g1;->j:Lvp/e1;

    .line 55
    .line 56
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 57
    .line 58
    .line 59
    new-instance v2, Lvp/w1;

    .line 60
    .line 61
    const/4 v3, 0x2

    .line 62
    invoke-direct {v2, p0, v3}, Lvp/w1;-><init>(Lvp/j2;I)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v1, v2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 66
    .line 67
    .line 68
    :cond_1
    invoke-virtual {v0}, Lvp/g1;->o()Lvp/d3;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-virtual {v1}, Lvp/x;->a0()V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v1}, Lvp/b0;->b0()V

    .line 76
    .line 77
    .line 78
    const/4 v2, 0x1

    .line 79
    invoke-virtual {v1, v2}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    invoke-virtual {v1}, Lvp/d3;->m0()V

    .line 84
    .line 85
    .line 86
    iget-object v3, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v3, Lvp/g1;

    .line 89
    .line 90
    iget-object v4, v3, Lvp/g1;->g:Lvp/h;

    .line 91
    .line 92
    sget-object v5, Lvp/z;->b1:Lvp/y;

    .line 93
    .line 94
    const/4 v6, 0x0

    .line 95
    invoke-virtual {v4, v6, v5}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 96
    .line 97
    .line 98
    invoke-virtual {v3}, Lvp/g1;->n()Lvp/j0;

    .line 99
    .line 100
    .line 101
    move-result-object v3

    .line 102
    const/4 v4, 0x3

    .line 103
    const/4 v5, 0x0

    .line 104
    new-array v7, v5, [B

    .line 105
    .line 106
    invoke-virtual {v3, v4, v7}, Lvp/j0;->h0(I[B)Z

    .line 107
    .line 108
    .line 109
    new-instance v3, Lvp/z2;

    .line 110
    .line 111
    const/4 v4, 0x0

    .line 112
    invoke-direct {v3, v1, v2, v4}, Lvp/z2;-><init>(Lvp/d3;Lvp/f4;I)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v1, v3}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 116
    .line 117
    .line 118
    iput-boolean v5, p0, Lvp/j2;->w:Z

    .line 119
    .line 120
    iget-object v1, v0, Lvp/g1;->h:Lvp/w0;

    .line 121
    .line 122
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v1}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 129
    .line 130
    .line 131
    move-result-object v2

    .line 132
    const-string v3, "previous_os_version"

    .line 133
    .line 134
    invoke-interface {v2, v3, v6}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    iget-object v4, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 139
    .line 140
    check-cast v4, Lvp/g1;

    .line 141
    .line 142
    invoke-virtual {v4}, Lvp/g1;->p()Lvp/q;

    .line 143
    .line 144
    .line 145
    move-result-object v4

    .line 146
    invoke-virtual {v4}, Lvp/n1;->c0()V

    .line 147
    .line 148
    .line 149
    sget-object v4, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    .line 150
    .line 151
    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 152
    .line 153
    .line 154
    move-result v5

    .line 155
    if-nez v5, :cond_2

    .line 156
    .line 157
    invoke-virtual {v4, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v5

    .line 161
    if-nez v5, :cond_2

    .line 162
    .line 163
    invoke-virtual {v1}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    invoke-interface {v1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    invoke-interface {v1, v3, v4}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 172
    .line 173
    .line 174
    invoke-interface {v1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 175
    .line 176
    .line 177
    :cond_2
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    if-nez v1, :cond_3

    .line 182
    .line 183
    invoke-virtual {v0}, Lvp/g1;->p()Lvp/q;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    invoke-virtual {v0}, Lvp/n1;->c0()V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    if-nez v0, :cond_3

    .line 195
    .line 196
    new-instance v0, Landroid/os/Bundle;

    .line 197
    .line 198
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 199
    .line 200
    .line 201
    const-string v1, "_po"

    .line 202
    .line 203
    invoke-virtual {v0, v1, v2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    const-string v1, "auto"

    .line 207
    .line 208
    const-string v2, "_ou"

    .line 209
    .line 210
    invoke-virtual {p0, v1, v2, v0}, Lvp/j2;->h0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 211
    .line 212
    .line 213
    :cond_3
    :goto_0
    return-void
.end method

.method public final n0(Landroid/os/Bundle;J)V
    .locals 12

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Landroid/os/Bundle;

    .line 9
    .line 10
    invoke-direct {v1, p1}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 11
    .line 12
    .line 13
    const-string p1, "app_id"

    .line 14
    .line 15
    invoke-virtual {v1, p1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-nez v2, :cond_0

    .line 24
    .line 25
    iget-object v2, v0, Lvp/g1;->i:Lvp/p0;

    .line 26
    .line 27
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 28
    .line 29
    .line 30
    iget-object v2, v2, Lvp/p0;->m:Lvp/n0;

    .line 31
    .line 32
    const-string v3, "Package name should be null when calling setConditionalUserProperty"

    .line 33
    .line 34
    invoke-virtual {v2, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    :cond_0
    invoke-virtual {v1, p1}, Landroid/os/Bundle;->remove(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    const-class v2, Ljava/lang/String;

    .line 41
    .line 42
    const/4 v3, 0x0

    .line 43
    invoke-static {v1, p1, v2, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    const-string p1, "origin"

    .line 47
    .line 48
    invoke-static {v1, p1, v2, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    const-string v4, "name"

    .line 52
    .line 53
    invoke-static {v1, v4, v2, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    const-class v5, Ljava/lang/Object;

    .line 57
    .line 58
    const-string v6, "value"

    .line 59
    .line 60
    invoke-static {v1, v6, v5, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    const-string v5, "trigger_event_name"

    .line 64
    .line 65
    invoke-static {v1, v5, v2, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    const-wide/16 v7, 0x0

    .line 69
    .line 70
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    const-string v8, "trigger_timeout"

    .line 75
    .line 76
    const-class v9, Ljava/lang/Long;

    .line 77
    .line 78
    invoke-static {v1, v8, v9, v7}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    const-string v10, "timed_out_event_name"

    .line 82
    .line 83
    invoke-static {v1, v10, v2, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    const-string v10, "timed_out_event_params"

    .line 87
    .line 88
    const-class v11, Landroid/os/Bundle;

    .line 89
    .line 90
    invoke-static {v1, v10, v11, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    const-string v10, "triggered_event_name"

    .line 94
    .line 95
    invoke-static {v1, v10, v2, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    const-string v10, "triggered_event_params"

    .line 99
    .line 100
    invoke-static {v1, v10, v11, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    const-string v10, "time_to_live"

    .line 104
    .line 105
    invoke-static {v1, v10, v9, v7}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    const-string v7, "expired_event_name"

    .line 109
    .line 110
    invoke-static {v1, v7, v2, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    const-string v2, "expired_event_params"

    .line 114
    .line 115
    invoke-static {v1, v2, v11, v3}, Lvp/t1;->e(Landroid/os/Bundle;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    invoke-virtual {v1, v4}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    invoke-static {v2}, Lno/c0;->e(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v1, p1}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v1, v6}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    const-string p1, "creation_timestamp"

    .line 140
    .line 141
    invoke-virtual {v1, p1, p2, p3}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v1, v4}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    invoke-virtual {v1, v6}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p2

    .line 152
    iget-object p3, v0, Lvp/g1;->l:Lvp/d4;

    .line 153
    .line 154
    iget-object v2, v0, Lvp/g1;->m:Lvp/k0;

    .line 155
    .line 156
    iget-object v3, v0, Lvp/g1;->i:Lvp/p0;

    .line 157
    .line 158
    invoke-static {p3}, Lvp/g1;->g(Lap0/o;)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {p3, p1}, Lvp/d4;->f1(Ljava/lang/String;)I

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    if-nez v4, :cond_7

    .line 166
    .line 167
    invoke-static {p3}, Lvp/g1;->g(Lap0/o;)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {p3, p2, p1}, Lvp/d4;->n0(Ljava/lang/Object;Ljava/lang/String;)I

    .line 171
    .line 172
    .line 173
    move-result v4

    .line 174
    if-nez v4, :cond_6

    .line 175
    .line 176
    invoke-virtual {p3, p2, p1}, Lvp/d4;->o0(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object p3

    .line 180
    if-nez p3, :cond_1

    .line 181
    .line 182
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 183
    .line 184
    .line 185
    iget-object p0, v3, Lvp/p0;->j:Lvp/n0;

    .line 186
    .line 187
    invoke-virtual {v2, p1}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object p1

    .line 191
    const-string p3, "Unable to normalize conditional user property value"

    .line 192
    .line 193
    invoke-virtual {p0, p1, p2, p3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    return-void

    .line 197
    :cond_1
    invoke-static {v1, p3}, Lvp/t1;->c(Landroid/os/Bundle;Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v1, v8}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 201
    .line 202
    .line 203
    move-result-wide p2

    .line 204
    invoke-virtual {v1, v5}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v4

    .line 208
    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 209
    .line 210
    .line 211
    move-result v4

    .line 212
    const-wide/16 v5, 0x1

    .line 213
    .line 214
    const-wide v7, 0x39ef8b000L

    .line 215
    .line 216
    .line 217
    .line 218
    .line 219
    if-nez v4, :cond_3

    .line 220
    .line 221
    cmp-long v4, p2, v7

    .line 222
    .line 223
    if-gtz v4, :cond_2

    .line 224
    .line 225
    cmp-long v4, p2, v5

    .line 226
    .line 227
    if-gez v4, :cond_3

    .line 228
    .line 229
    :cond_2
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 230
    .line 231
    .line 232
    iget-object p0, v3, Lvp/p0;->j:Lvp/n0;

    .line 233
    .line 234
    invoke-virtual {v2, p1}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object p1

    .line 238
    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 239
    .line 240
    .line 241
    move-result-object p2

    .line 242
    const-string p3, "Invalid conditional user property timeout"

    .line 243
    .line 244
    invoke-virtual {p0, p1, p2, p3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    return-void

    .line 248
    :cond_3
    invoke-virtual {v1, v10}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 249
    .line 250
    .line 251
    move-result-wide p2

    .line 252
    cmp-long v4, p2, v7

    .line 253
    .line 254
    if-gtz v4, :cond_5

    .line 255
    .line 256
    cmp-long v4, p2, v5

    .line 257
    .line 258
    if-gez v4, :cond_4

    .line 259
    .line 260
    goto :goto_0

    .line 261
    :cond_4
    iget-object p1, v0, Lvp/g1;->j:Lvp/e1;

    .line 262
    .line 263
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 264
    .line 265
    .line 266
    new-instance p2, Lvp/e2;

    .line 267
    .line 268
    const/4 p3, 0x0

    .line 269
    invoke-direct {p2, p0, v1, p3}, Lvp/e2;-><init>(Lvp/j2;Landroid/os/Bundle;I)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {p1, p2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 273
    .line 274
    .line 275
    return-void

    .line 276
    :cond_5
    :goto_0
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 277
    .line 278
    .line 279
    iget-object p0, v3, Lvp/p0;->j:Lvp/n0;

    .line 280
    .line 281
    invoke-virtual {v2, p1}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 282
    .line 283
    .line 284
    move-result-object p1

    .line 285
    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 286
    .line 287
    .line 288
    move-result-object p2

    .line 289
    const-string p3, "Invalid conditional user property time to live"

    .line 290
    .line 291
    invoke-virtual {p0, p1, p2, p3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    return-void

    .line 295
    :cond_6
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 296
    .line 297
    .line 298
    iget-object p0, v3, Lvp/p0;->j:Lvp/n0;

    .line 299
    .line 300
    invoke-virtual {v2, p1}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 301
    .line 302
    .line 303
    move-result-object p1

    .line 304
    const-string p3, "Invalid conditional user property value"

    .line 305
    .line 306
    invoke-virtual {p0, p1, p2, p3}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    return-void

    .line 310
    :cond_7
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 311
    .line 312
    .line 313
    iget-object p0, v3, Lvp/p0;->j:Lvp/n0;

    .line 314
    .line 315
    invoke-virtual {v2, p1}, Lvp/k0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 316
    .line 317
    .line 318
    move-result-object p1

    .line 319
    const-string p2, "Invalid conditional user property name"

    .line 320
    .line 321
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 322
    .line 323
    .line 324
    return-void
.end method

.method public final o0(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    iget-object v1, v0, Lvp/g1;->n:Lto/a;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 11
    .line 12
    .line 13
    move-result-wide v1

    .line 14
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    new-instance v3, Landroid/os/Bundle;

    .line 18
    .line 19
    invoke-direct {v3}, Landroid/os/Bundle;-><init>()V

    .line 20
    .line 21
    .line 22
    const-string v4, "name"

    .line 23
    .line 24
    invoke-virtual {v3, v4, p1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const-string p1, "creation_timestamp"

    .line 28
    .line 29
    invoke-virtual {v3, p1, v1, v2}, Landroid/os/BaseBundle;->putLong(Ljava/lang/String;J)V

    .line 30
    .line 31
    .line 32
    if-eqz p2, :cond_0

    .line 33
    .line 34
    const-string p1, "expired_event_name"

    .line 35
    .line 36
    invoke-virtual {v3, p1, p2}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string p1, "expired_event_params"

    .line 40
    .line 41
    invoke-virtual {v3, p1, p3}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 42
    .line 43
    .line 44
    :cond_0
    iget-object p1, v0, Lvp/g1;->j:Lvp/e1;

    .line 45
    .line 46
    invoke-static {p1}, Lvp/g1;->k(Lvp/n1;)V

    .line 47
    .line 48
    .line 49
    new-instance p2, Lk0/g;

    .line 50
    .line 51
    const/16 p3, 0x10

    .line 52
    .line 53
    const/4 v0, 0x0

    .line 54
    invoke-direct {p2, p0, v3, v0, p3}, Lk0/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1, p2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public final p0()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvp/g1;

    .line 4
    .line 5
    :try_start_0
    iget-object v0, p0, Lvp/g1;->d:Landroid/content/Context;

    .line 6
    .line 7
    iget-object v1, p0, Lvp/g1;->s:Ljava/lang/String;

    .line 8
    .line 9
    invoke-static {v0, v1}, Lvp/t1;->b(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    return-object p0

    .line 14
    :catch_0
    move-exception v0

    .line 15
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 16
    .line 17
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lvp/p0;->j:Lvp/n0;

    .line 21
    .line 22
    const-string v1, "getGoogleAppId failed with exception"

    .line 23
    .line 24
    invoke-virtual {p0, v0, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const/4 p0, 0x0

    .line 28
    return-object p0
.end method

.method public final q0(Lvp/s1;JZ)V
    .locals 7

    .line 1
    iget v0, p1, Lvp/s1;->b:I

    .line 2
    .line 3
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Lvp/g1;

    .line 12
    .line 13
    iget-object v2, v1, Lvp/g1;->h:Lvp/w0;

    .line 14
    .line 15
    iget-object v3, v1, Lvp/g1;->i:Lvp/p0;

    .line 16
    .line 17
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v2}, Lvp/w0;->h0()Lvp/s1;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    iget-wide v4, p0, Lvp/j2;->u:J

    .line 25
    .line 26
    cmp-long v4, p2, v4

    .line 27
    .line 28
    if-gtz v4, :cond_1

    .line 29
    .line 30
    iget v2, v2, Lvp/s1;->b:I

    .line 31
    .line 32
    invoke-static {v2, v0}, Lvp/s1;->l(II)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-nez v2, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 40
    .line 41
    .line 42
    iget-object p0, v3, Lvp/p0;->p:Lvp/n0;

    .line 43
    .line 44
    const-string p2, "Dropped out-of-date consent setting, proposed settings"

    .line 45
    .line 46
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_1
    :goto_0
    iget-object v2, v1, Lvp/g1;->h:Lvp/w0;

    .line 51
    .line 52
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v2}, Lap0/o;->a0()V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v2}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    const/16 v5, 0x64

    .line 63
    .line 64
    const-string v6, "consent_source"

    .line 65
    .line 66
    invoke-interface {v4, v6, v5}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 67
    .line 68
    .line 69
    move-result v4

    .line 70
    invoke-static {v0, v4}, Lvp/s1;->l(II)Z

    .line 71
    .line 72
    .line 73
    move-result v4

    .line 74
    if-eqz v4, :cond_5

    .line 75
    .line 76
    invoke-virtual {v2}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    invoke-virtual {p1}, Lvp/s1;->g()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    const-string v5, "consent_settings"

    .line 89
    .line 90
    invoke-interface {v2, v5, v4}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 91
    .line 92
    .line 93
    invoke-interface {v2, v6, v0}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    .line 94
    .line 95
    .line 96
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 97
    .line 98
    .line 99
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 100
    .line 101
    .line 102
    iget-object v0, v3, Lvp/p0;->r:Lvp/n0;

    .line 103
    .line 104
    const-string v2, "Setting storage consent(FE)"

    .line 105
    .line 106
    invoke-virtual {v0, p1, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    iput-wide p2, p0, Lvp/j2;->u:J

    .line 110
    .line 111
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-virtual {p0}, Lvp/d3;->k0()Z

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    if-eqz p0, :cond_2

    .line 120
    .line 121
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 129
    .line 130
    .line 131
    new-instance p1, Lvp/b3;

    .line 132
    .line 133
    const/4 p2, 0x2

    .line 134
    invoke-direct {p1, p0, p2}, Lvp/b3;-><init>(Lvp/d3;I)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {p0, p1}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 138
    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_2
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 146
    .line 147
    .line 148
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 149
    .line 150
    .line 151
    invoke-virtual {p0}, Lvp/d3;->j0()Z

    .line 152
    .line 153
    .line 154
    move-result p1

    .line 155
    if-eqz p1, :cond_3

    .line 156
    .line 157
    const/4 p1, 0x0

    .line 158
    invoke-virtual {p0, p1}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    new-instance p2, Lvp/z2;

    .line 163
    .line 164
    const/4 p3, 0x1

    .line 165
    invoke-direct {p2, p0, p1, p3}, Lvp/z2;-><init>(Lvp/d3;Lvp/f4;I)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {p0, p2}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 169
    .line 170
    .line 171
    :cond_3
    :goto_1
    if-eqz p4, :cond_4

    .line 172
    .line 173
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 178
    .line 179
    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 180
    .line 181
    .line 182
    invoke-virtual {p0, p1}, Lvp/d3;->e0(Ljava/util/concurrent/atomic/AtomicReference;)V

    .line 183
    .line 184
    .line 185
    :cond_4
    return-void

    .line 186
    :cond_5
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 187
    .line 188
    .line 189
    iget-object p0, v3, Lvp/p0;->p:Lvp/n0;

    .line 190
    .line 191
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    const-string p2, "Lower precedence consent source ignored, proposed source"

    .line 196
    .line 197
    invoke-virtual {p0, p1, p2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    return-void
.end method

.method public final r0(Ljava/lang/Boolean;Z)V
    .locals 5

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lvp/g1;

    .line 10
    .line 11
    iget-object v1, v0, Lvp/g1;->i:Lvp/p0;

    .line 12
    .line 13
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 14
    .line 15
    .line 16
    iget-object v1, v1, Lvp/p0;->q:Lvp/n0;

    .line 17
    .line 18
    const-string v2, "Setting app measurement enabled (FE)"

    .line 19
    .line 20
    invoke-virtual {v1, p1, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, v0, Lvp/g1;->h:Lvp/w0;

    .line 24
    .line 25
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    const-string v3, "measurement_enabled"

    .line 40
    .line 41
    if-eqz p1, :cond_0

    .line 42
    .line 43
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    invoke-interface {v2, v3, v4}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    invoke-interface {v2, v3}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 52
    .line 53
    .line 54
    :goto_0
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 55
    .line 56
    .line 57
    if-eqz p2, :cond_2

    .line 58
    .line 59
    invoke-virtual {v1}, Lap0/o;->a0()V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v1}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 63
    .line 64
    .line 65
    move-result-object p2

    .line 66
    invoke-interface {p2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    const-string v1, "measurement_enabled_from_api"

    .line 71
    .line 72
    if-eqz p1, :cond_1

    .line 73
    .line 74
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    invoke-interface {p2, v1, v2}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_1
    invoke-interface {p2, v1}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 83
    .line 84
    .line 85
    :goto_1
    invoke-interface {p2}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 86
    .line 87
    .line 88
    :cond_2
    iget-object p2, v0, Lvp/g1;->j:Lvp/e1;

    .line 89
    .line 90
    invoke-static {p2}, Lvp/g1;->k(Lvp/n1;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p2}, Lvp/e1;->a0()V

    .line 94
    .line 95
    .line 96
    iget-boolean p2, v0, Lvp/g1;->C:Z

    .line 97
    .line 98
    if-nez p2, :cond_4

    .line 99
    .line 100
    if-eqz p1, :cond_3

    .line 101
    .line 102
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    if-nez p1, :cond_3

    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_3
    return-void

    .line 110
    :cond_4
    :goto_2
    invoke-virtual {p0}, Lvp/j2;->s0()V

    .line 111
    .line 112
    .line 113
    return-void
.end method

.method public final s0()V
    .locals 9

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    move-object v6, v1

    .line 7
    check-cast v6, Lvp/g1;

    .line 8
    .line 9
    iget-object v1, v6, Lvp/g1;->h:Lvp/w0;

    .line 10
    .line 11
    iget-object v7, v6, Lvp/g1;->i:Lvp/p0;

    .line 12
    .line 13
    iget-object v2, v6, Lvp/g1;->n:Lto/a;

    .line 14
    .line 15
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 16
    .line 17
    .line 18
    iget-object v1, v1, Lvp/w0;->q:La8/b;

    .line 19
    .line 20
    invoke-virtual {v1}, La8/b;->t()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    const/4 v8, 0x1

    .line 25
    if-eqz v1, :cond_2

    .line 26
    .line 27
    const-string v3, "unset"

    .line 28
    .line 29
    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 39
    .line 40
    .line 41
    move-result-wide v1

    .line 42
    const-string v5, "_npa"

    .line 43
    .line 44
    const/4 v3, 0x0

    .line 45
    const-string v4, "app"

    .line 46
    .line 47
    move-object v0, p0

    .line 48
    invoke-virtual/range {v0 .. v5}, Lvp/j2;->l0(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_0
    const-string v0, "true"

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-eq v8, v0, :cond_1

    .line 59
    .line 60
    const-wide/16 v0, 0x0

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    const-wide/16 v0, 0x1

    .line 64
    .line 65
    :goto_0
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 66
    .line 67
    .line 68
    move-result-object v3

    .line 69
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 73
    .line 74
    .line 75
    move-result-wide v1

    .line 76
    const-string v4, "app"

    .line 77
    .line 78
    const-string v5, "_npa"

    .line 79
    .line 80
    move-object v0, p0

    .line 81
    invoke-virtual/range {v0 .. v5}, Lvp/j2;->l0(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    :cond_2
    :goto_1
    invoke-virtual {v6}, Lvp/g1;->a()Z

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    if-eqz v1, :cond_3

    .line 89
    .line 90
    iget-boolean v1, p0, Lvp/j2;->w:Z

    .line 91
    .line 92
    if-eqz v1, :cond_3

    .line 93
    .line 94
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 95
    .line 96
    .line 97
    iget-object v1, v7, Lvp/p0;->q:Lvp/n0;

    .line 98
    .line 99
    const-string v2, "Recording app launch after enabling measurement for the first time (FE)"

    .line 100
    .line 101
    invoke-virtual {v1, v2}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p0}, Lvp/j2;->m0()V

    .line 105
    .line 106
    .line 107
    iget-object v1, v6, Lvp/g1;->k:Lvp/k3;

    .line 108
    .line 109
    invoke-static {v1}, Lvp/g1;->i(Lvp/b0;)V

    .line 110
    .line 111
    .line 112
    iget-object v1, v1, Lvp/k3;->i:Lt1/j0;

    .line 113
    .line 114
    invoke-virtual {v1}, Lt1/j0;->o()V

    .line 115
    .line 116
    .line 117
    iget-object v1, v6, Lvp/g1;->j:Lvp/e1;

    .line 118
    .line 119
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 120
    .line 121
    .line 122
    new-instance v2, Lvp/w1;

    .line 123
    .line 124
    const/4 v3, 0x1

    .line 125
    invoke-direct {v2, p0, v3}, Lvp/w1;-><init>(Lvp/j2;I)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v1, v2}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 129
    .line 130
    .line 131
    return-void

    .line 132
    :cond_3
    invoke-static {v7}, Lvp/g1;->k(Lvp/n1;)V

    .line 133
    .line 134
    .line 135
    iget-object v0, v7, Lvp/p0;->q:Lvp/n0;

    .line 136
    .line 137
    const-string v1, "Updating Scion state (FE)"

    .line 138
    .line 139
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v6}, Lvp/g1;->o()Lvp/d3;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v0}, Lvp/b0;->b0()V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v0, v8}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    new-instance v2, Lvp/y2;

    .line 157
    .line 158
    const/4 v3, 0x2

    .line 159
    invoke-direct {v2, v0, v1, v3}, Lvp/y2;-><init>(Lvp/d3;Lvp/f4;I)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v0, v2}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 163
    .line 164
    .line 165
    return-void
.end method

.method public final t0()V
    .locals 2

    .line 1
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/g1;

    .line 4
    .line 5
    iget-object v1, v0, Lvp/g1;->d:Landroid/content/Context;

    .line 6
    .line 7
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    instance-of v1, v1, Landroid/app/Application;

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    iget-object v1, p0, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 16
    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    iget-object v0, v0, Lvp/g1;->d:Landroid/content/Context;

    .line 20
    .line 21
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Landroid/app/Application;

    .line 26
    .line 27
    iget-object p0, p0, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 28
    .line 29
    invoke-virtual {v0, p0}, Landroid/app/Application;->unregisterActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    return-void
.end method

.method public final u0(Landroid/os/Bundle;IJ)V
    .locals 10

    .line 1
    iget-object v3, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v3, Lvp/g1;

    .line 4
    .line 5
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 6
    .line 7
    .line 8
    sget-object v4, Lvp/s1;->c:Lvp/s1;

    .line 9
    .line 10
    sget-object v4, Lvp/q1;->e:Lvp/q1;

    .line 11
    .line 12
    iget-object v4, v4, Lvp/q1;->d:[Lvp/r1;

    .line 13
    .line 14
    array-length v5, v4

    .line 15
    const/4 v6, 0x0

    .line 16
    :goto_0
    const/4 v7, 0x0

    .line 17
    if-ge v6, v5, :cond_3

    .line 18
    .line 19
    aget-object v8, v4, v6

    .line 20
    .line 21
    iget-object v8, v8, Lvp/r1;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {p1, v8}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 24
    .line 25
    .line 26
    move-result v9

    .line 27
    if-eqz v9, :cond_2

    .line 28
    .line 29
    invoke-virtual {p1, v8}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v8

    .line 33
    if-eqz v8, :cond_2

    .line 34
    .line 35
    const-string v9, "granted"

    .line 36
    .line 37
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v9

    .line 41
    if-eqz v9, :cond_0

    .line 42
    .line 43
    sget-object v9, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_0
    const-string v9, "denied"

    .line 47
    .line 48
    invoke-virtual {v8, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v9

    .line 52
    if-eqz v9, :cond_1

    .line 53
    .line 54
    sget-object v9, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    move-object v9, v7

    .line 58
    :goto_1
    if-nez v9, :cond_2

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_2
    add-int/lit8 v6, v6, 0x1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_3
    move-object v8, v7

    .line 65
    :goto_2
    if-eqz v8, :cond_4

    .line 66
    .line 67
    iget-object v4, v3, Lvp/g1;->i:Lvp/p0;

    .line 68
    .line 69
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 70
    .line 71
    .line 72
    iget-object v4, v4, Lvp/p0;->o:Lvp/n0;

    .line 73
    .line 74
    const-string v5, "Ignoring invalid consent setting"

    .line 75
    .line 76
    invoke-virtual {v4, v8, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget-object v4, v3, Lvp/g1;->i:Lvp/p0;

    .line 80
    .line 81
    invoke-static {v4}, Lvp/g1;->k(Lvp/n1;)V

    .line 82
    .line 83
    .line 84
    iget-object v4, v4, Lvp/p0;->o:Lvp/n0;

    .line 85
    .line 86
    const-string v5, "Valid consent values are \'granted\', \'denied\'"

    .line 87
    .line 88
    invoke-virtual {v4, v5}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    :cond_4
    iget-object v3, v3, Lvp/g1;->j:Lvp/e1;

    .line 92
    .line 93
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v3}, Lvp/e1;->g0()Z

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    invoke-static {p2, p1}, Lvp/s1;->b(ILandroid/os/Bundle;)Lvp/s1;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    iget-object v5, v4, Lvp/s1;->a:Ljava/util/EnumMap;

    .line 105
    .line 106
    invoke-virtual {v5}, Ljava/util/EnumMap;->values()Ljava/util/Collection;

    .line 107
    .line 108
    .line 109
    move-result-object v5

    .line 110
    invoke-interface {v5}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    :cond_5
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 115
    .line 116
    .line 117
    move-result v6

    .line 118
    sget-object v8, Lvp/p1;->e:Lvp/p1;

    .line 119
    .line 120
    if-eqz v6, :cond_6

    .line 121
    .line 122
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v6

    .line 126
    check-cast v6, Lvp/p1;

    .line 127
    .line 128
    if-eq v6, v8, :cond_5

    .line 129
    .line 130
    invoke-virtual {p0, v4, v3}, Lvp/j2;->w0(Lvp/s1;Z)V

    .line 131
    .line 132
    .line 133
    :cond_6
    invoke-static {p2, p1}, Lvp/p;->c(ILandroid/os/Bundle;)Lvp/p;

    .line 134
    .line 135
    .line 136
    move-result-object v4

    .line 137
    iget-object v5, v4, Lvp/p;->e:Ljava/util/EnumMap;

    .line 138
    .line 139
    invoke-virtual {v5}, Ljava/util/EnumMap;->values()Ljava/util/Collection;

    .line 140
    .line 141
    .line 142
    move-result-object v5

    .line 143
    invoke-interface {v5}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 144
    .line 145
    .line 146
    move-result-object v5

    .line 147
    :cond_7
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 148
    .line 149
    .line 150
    move-result v6

    .line 151
    if-eqz v6, :cond_8

    .line 152
    .line 153
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v6

    .line 157
    check-cast v6, Lvp/p1;

    .line 158
    .line 159
    if-eq v6, v8, :cond_7

    .line 160
    .line 161
    invoke-virtual {p0, v4, v3}, Lvp/j2;->v0(Lvp/p;Z)V

    .line 162
    .line 163
    .line 164
    :cond_8
    if-nez p1, :cond_9

    .line 165
    .line 166
    goto :goto_3

    .line 167
    :cond_9
    const-string v4, "ad_personalization"

    .line 168
    .line 169
    invoke-virtual {p1, v4}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    invoke-static {v1}, Lvp/s1;->d(Ljava/lang/String;)Lvp/p1;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    const/4 v4, 0x2

    .line 182
    if-eq v1, v4, :cond_b

    .line 183
    .line 184
    const/4 v4, 0x3

    .line 185
    if-eq v1, v4, :cond_a

    .line 186
    .line 187
    goto :goto_3

    .line 188
    :cond_a
    sget-object v7, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 189
    .line 190
    goto :goto_3

    .line 191
    :cond_b
    sget-object v7, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 192
    .line 193
    :goto_3
    if-eqz v7, :cond_e

    .line 194
    .line 195
    const/16 v1, -0x1e

    .line 196
    .line 197
    if-ne p2, v1, :cond_c

    .line 198
    .line 199
    const-string v1, "tcf"

    .line 200
    .line 201
    goto :goto_4

    .line 202
    :cond_c
    const-string v1, "app"

    .line 203
    .line 204
    :goto_4
    if-eqz v3, :cond_d

    .line 205
    .line 206
    invoke-virtual {v7}, Ljava/lang/Boolean;->toString()Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v3

    .line 210
    const-string v5, "allow_personalized_ads"

    .line 211
    .line 212
    move-object v0, p0

    .line 213
    move-object v4, v1

    .line 214
    move-wide v1, p3

    .line 215
    invoke-virtual/range {v0 .. v5}, Lvp/j2;->l0(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    return-void

    .line 219
    :cond_d
    invoke-virtual {v7}, Ljava/lang/Boolean;->toString()Ljava/lang/String;

    .line 220
    .line 221
    .line 222
    move-result-object v3

    .line 223
    const-string v2, "allow_personalized_ads"

    .line 224
    .line 225
    const/4 v4, 0x0

    .line 226
    move-object v0, p0

    .line 227
    move-wide v5, p3

    .line 228
    invoke-virtual/range {v0 .. v6}, Lvp/j2;->k0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;ZJ)V

    .line 229
    .line 230
    .line 231
    :cond_e
    return-void
.end method

.method public final v0(Lvp/p;Z)V
    .locals 3

    .line 1
    new-instance v0, Llr/b;

    .line 2
    .line 3
    const/16 v1, 0x14

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, p0, p1, v2, v1}, Llr/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 7
    .line 8
    .line 9
    if-eqz p2, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Llr/b;->run()V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lvp/g1;

    .line 21
    .line 22
    iget-object p0, p0, Lvp/g1;->j:Lvp/e1;

    .line 23
    .line 24
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v0}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public final w0(Lvp/s1;Z)V
    .locals 13

    .line 1
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 2
    .line 3
    .line 4
    iget v0, p1, Lvp/s1;->b:I

    .line 5
    .line 6
    const/16 v1, -0xa

    .line 7
    .line 8
    if-eq v0, v1, :cond_3

    .line 9
    .line 10
    iget-object v2, p1, Lvp/s1;->a:Ljava/util/EnumMap;

    .line 11
    .line 12
    sget-object v3, Lvp/r1;->e:Lvp/r1;

    .line 13
    .line 14
    invoke-virtual {v2, v3}, Ljava/util/EnumMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    check-cast v2, Lvp/p1;

    .line 19
    .line 20
    if-nez v2, :cond_0

    .line 21
    .line 22
    sget-object v2, Lvp/p1;->e:Lvp/p1;

    .line 23
    .line 24
    :cond_0
    sget-object v3, Lvp/p1;->e:Lvp/p1;

    .line 25
    .line 26
    if-ne v2, v3, :cond_3

    .line 27
    .line 28
    iget-object v2, p1, Lvp/s1;->a:Ljava/util/EnumMap;

    .line 29
    .line 30
    sget-object v4, Lvp/r1;->f:Lvp/r1;

    .line 31
    .line 32
    invoke-virtual {v2, v4}, Ljava/util/EnumMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    check-cast v2, Lvp/p1;

    .line 37
    .line 38
    if-nez v2, :cond_1

    .line 39
    .line 40
    move-object v2, v3

    .line 41
    :cond_1
    if-eq v2, v3, :cond_2

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Lvp/g1;

    .line 47
    .line 48
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 49
    .line 50
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 51
    .line 52
    .line 53
    iget-object p0, p0, Lvp/p0;->o:Lvp/n0;

    .line 54
    .line 55
    const-string p1, "Ignoring empty consent settings"

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    return-void

    .line 61
    :cond_3
    :goto_0
    iget-object v2, p0, Lvp/j2;->l:Ljava/lang/Object;

    .line 62
    .line 63
    monitor-enter v2

    .line 64
    :try_start_0
    iget-object v3, p0, Lvp/j2;->s:Lvp/s1;

    .line 65
    .line 66
    iget v3, v3, Lvp/s1;->b:I

    .line 67
    .line 68
    invoke-static {v0, v3}, Lvp/s1;->l(II)Z

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    const/4 v4, 0x0

    .line 73
    if-eqz v3, :cond_7

    .line 74
    .line 75
    iget-object v3, p0, Lvp/j2;->s:Lvp/s1;

    .line 76
    .line 77
    iget-object v5, p1, Lvp/s1;->a:Ljava/util/EnumMap;

    .line 78
    .line 79
    invoke-virtual {v5}, Ljava/util/EnumMap;->keySet()Ljava/util/Set;

    .line 80
    .line 81
    .line 82
    move-result-object v6

    .line 83
    new-array v7, v4, [Lvp/r1;

    .line 84
    .line 85
    invoke-interface {v6, v7}, Ljava/util/Set;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v6

    .line 89
    check-cast v6, [Lvp/r1;

    .line 90
    .line 91
    array-length v7, v6

    .line 92
    move v8, v4

    .line 93
    :goto_1
    const/4 v9, 0x1

    .line 94
    if-ge v8, v7, :cond_5

    .line 95
    .line 96
    aget-object v10, v6, v8

    .line 97
    .line 98
    invoke-virtual {v5, v10}, Ljava/util/EnumMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v11

    .line 102
    check-cast v11, Lvp/p1;

    .line 103
    .line 104
    iget-object v12, v3, Lvp/s1;->a:Ljava/util/EnumMap;

    .line 105
    .line 106
    invoke-virtual {v12, v10}, Ljava/util/EnumMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v10

    .line 110
    check-cast v10, Lvp/p1;

    .line 111
    .line 112
    sget-object v12, Lvp/p1;->g:Lvp/p1;

    .line 113
    .line 114
    if-ne v11, v12, :cond_4

    .line 115
    .line 116
    if-eq v10, v12, :cond_4

    .line 117
    .line 118
    move v3, v9

    .line 119
    goto :goto_2

    .line 120
    :cond_4
    add-int/lit8 v8, v8, 0x1

    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_5
    move v3, v4

    .line 124
    :goto_2
    sget-object v5, Lvp/r1;->f:Lvp/r1;

    .line 125
    .line 126
    invoke-virtual {p1, v5}, Lvp/s1;->i(Lvp/r1;)Z

    .line 127
    .line 128
    .line 129
    move-result v6

    .line 130
    if-eqz v6, :cond_6

    .line 131
    .line 132
    iget-object v6, p0, Lvp/j2;->s:Lvp/s1;

    .line 133
    .line 134
    invoke-virtual {v6, v5}, Lvp/s1;->i(Lvp/r1;)Z

    .line 135
    .line 136
    .line 137
    move-result v5

    .line 138
    if-nez v5, :cond_6

    .line 139
    .line 140
    move v4, v9

    .line 141
    goto :goto_3

    .line 142
    :catchall_0
    move-exception v0

    .line 143
    move-object p0, v0

    .line 144
    goto/16 :goto_7

    .line 145
    .line 146
    :cond_6
    :goto_3
    iget-object v5, p0, Lvp/j2;->s:Lvp/s1;

    .line 147
    .line 148
    invoke-virtual {p1, v5}, Lvp/s1;->k(Lvp/s1;)Lvp/s1;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    iput-object p1, p0, Lvp/j2;->s:Lvp/s1;

    .line 153
    .line 154
    move v8, v4

    .line 155
    move v4, v9

    .line 156
    :goto_4
    move-object v5, p1

    .line 157
    goto :goto_5

    .line 158
    :cond_7
    move v3, v4

    .line 159
    move v8, v3

    .line 160
    goto :goto_4

    .line 161
    :goto_5
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 162
    if-nez v4, :cond_8

    .line 163
    .line 164
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast p0, Lvp/g1;

    .line 167
    .line 168
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 169
    .line 170
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 171
    .line 172
    .line 173
    iget-object p0, p0, Lvp/p0;->p:Lvp/n0;

    .line 174
    .line 175
    const-string p1, "Ignoring lower-priority consent settings, proposed settings"

    .line 176
    .line 177
    invoke-virtual {p0, v5, p1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    return-void

    .line 181
    :cond_8
    iget-object p1, p0, Lvp/j2;->t:Ljava/util/concurrent/atomic/AtomicLong;

    .line 182
    .line 183
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicLong;->getAndIncrement()J

    .line 184
    .line 185
    .line 186
    move-result-wide v6

    .line 187
    if-eqz v3, :cond_a

    .line 188
    .line 189
    iget-object p1, p0, Lvp/j2;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 190
    .line 191
    const/4 v0, 0x0

    .line 192
    invoke-virtual {p1, v0}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    new-instance v3, Lvp/g2;

    .line 196
    .line 197
    const/4 v9, 0x0

    .line 198
    move-object v4, p0

    .line 199
    invoke-direct/range {v3 .. v9}, Lvp/g2;-><init>(Lvp/j2;Lvp/s1;JZI)V

    .line 200
    .line 201
    .line 202
    if-eqz p2, :cond_9

    .line 203
    .line 204
    invoke-virtual {v4}, Lvp/x;->a0()V

    .line 205
    .line 206
    .line 207
    invoke-virtual {v3}, Lvp/g2;->run()V

    .line 208
    .line 209
    .line 210
    return-void

    .line 211
    :cond_9
    iget-object p0, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast p0, Lvp/g1;

    .line 214
    .line 215
    iget-object p0, p0, Lvp/g1;->j:Lvp/e1;

    .line 216
    .line 217
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {p0, v3}, Lvp/e1;->l0(Ljava/lang/Runnable;)V

    .line 221
    .line 222
    .line 223
    return-void

    .line 224
    :cond_a
    move-object v4, p0

    .line 225
    new-instance v3, Lvp/g2;

    .line 226
    .line 227
    const/4 v9, 0x1

    .line 228
    invoke-direct/range {v3 .. v9}, Lvp/g2;-><init>(Lvp/j2;Lvp/s1;JZI)V

    .line 229
    .line 230
    .line 231
    if-eqz p2, :cond_b

    .line 232
    .line 233
    invoke-virtual {v4}, Lvp/x;->a0()V

    .line 234
    .line 235
    .line 236
    invoke-virtual {v3}, Lvp/g2;->run()V

    .line 237
    .line 238
    .line 239
    return-void

    .line 240
    :cond_b
    const/16 p0, 0x1e

    .line 241
    .line 242
    if-eq v0, p0, :cond_d

    .line 243
    .line 244
    if-ne v0, v1, :cond_c

    .line 245
    .line 246
    goto :goto_6

    .line 247
    :cond_c
    iget-object p0, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 248
    .line 249
    check-cast p0, Lvp/g1;

    .line 250
    .line 251
    iget-object p0, p0, Lvp/g1;->j:Lvp/e1;

    .line 252
    .line 253
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {p0, v3}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 257
    .line 258
    .line 259
    return-void

    .line 260
    :cond_d
    :goto_6
    iget-object p0, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 261
    .line 262
    check-cast p0, Lvp/g1;

    .line 263
    .line 264
    iget-object p0, p0, Lvp/g1;->j:Lvp/e1;

    .line 265
    .line 266
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 267
    .line 268
    .line 269
    invoke-virtual {p0, v3}, Lvp/e1;->l0(Ljava/lang/Runnable;)V

    .line 270
    .line 271
    .line 272
    return-void

    .line 273
    :goto_7
    :try_start_1
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 274
    throw p0
.end method

.method public final x0()V
    .locals 8

    .line 1
    invoke-static {}, Lcom/google/android/gms/internal/measurement/u8;->a()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Lvp/g1;

    .line 7
    .line 8
    iget-object v1, v0, Lvp/g1;->g:Lvp/h;

    .line 9
    .line 10
    iget-object v2, v0, Lvp/g1;->j:Lvp/e1;

    .line 11
    .line 12
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    sget-object v4, Lvp/z;->Q0:Lvp/y;

    .line 16
    .line 17
    invoke-virtual {v1, v3, v4}, Lvp/h;->k0(Ljava/lang/String;Lvp/y;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_3

    .line 22
    .line 23
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v2}, Lvp/e1;->g0()Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-nez v1, :cond_2

    .line 31
    .line 32
    invoke-static {}, Lst/b;->i()Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-nez v1, :cond_1

    .line 37
    .line 38
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 39
    .line 40
    .line 41
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 42
    .line 43
    .line 44
    iget-object v1, v0, Lvp/p0;->r:Lvp/n0;

    .line 45
    .line 46
    const-string v3, "Getting trigger URIs (FE)"

    .line 47
    .line 48
    invoke-virtual {v1, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    new-instance v3, Ljava/util/concurrent/atomic/AtomicReference;

    .line 52
    .line 53
    invoke-direct {v3}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 54
    .line 55
    .line 56
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 57
    .line 58
    .line 59
    new-instance v7, Lvp/f2;

    .line 60
    .line 61
    const/4 v1, 0x2

    .line 62
    const/4 v4, 0x0

    .line 63
    invoke-direct {v7, p0, v3, v1, v4}, Lvp/f2;-><init>(Lvp/j2;Ljava/util/concurrent/atomic/AtomicReference;IZ)V

    .line 64
    .line 65
    .line 66
    const-wide/16 v4, 0x2710

    .line 67
    .line 68
    const-string v6, "get trigger URIs"

    .line 69
    .line 70
    invoke-virtual/range {v2 .. v7}, Lvp/e1;->k0(Ljava/util/concurrent/atomic/AtomicReference;JLjava/lang/String;Ljava/lang/Runnable;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v3}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    check-cast v1, Ljava/util/List;

    .line 78
    .line 79
    if-nez v1, :cond_0

    .line 80
    .line 81
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 82
    .line 83
    .line 84
    iget-object p0, v0, Lvp/p0;->l:Lvp/n0;

    .line 85
    .line 86
    const-string v0, "Timed out waiting for get trigger URIs"

    .line 87
    .line 88
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    return-void

    .line 92
    :cond_0
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 93
    .line 94
    .line 95
    new-instance v0, Lk0/g;

    .line 96
    .line 97
    const/16 v3, 0x13

    .line 98
    .line 99
    invoke-direct {v0, v3, p0, v1}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v2, v0}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 103
    .line 104
    .line 105
    return-void

    .line 106
    :cond_1
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 107
    .line 108
    .line 109
    iget-object p0, v0, Lvp/p0;->j:Lvp/n0;

    .line 110
    .line 111
    const-string v0, "Cannot get trigger URIs from main thread"

    .line 112
    .line 113
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    return-void

    .line 117
    :cond_2
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 118
    .line 119
    .line 120
    iget-object p0, v0, Lvp/p0;->j:Lvp/n0;

    .line 121
    .line 122
    const-string v0, "Cannot get trigger URIs from analytics worker thread"

    .line 123
    .line 124
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    :cond_3
    return-void
.end method

.method public final y0()Ljava/util/PriorityQueue;
    .locals 3

    .line 1
    iget-object v0, p0, Lvp/j2;->q:Ljava/util/PriorityQueue;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Ljava/util/PriorityQueue;

    .line 6
    .line 7
    sget-object v1, Lvp/h2;->a:Lvp/h2;

    .line 8
    .line 9
    sget-object v2, Lqa/l;->e:Lqa/l;

    .line 10
    .line 11
    invoke-static {v1, v2}, Ljava/util/Comparator;->comparing(Ljava/util/function/Function;Ljava/util/Comparator;)Ljava/util/Comparator;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-direct {v0, v1}, Ljava/util/PriorityQueue;-><init>(Ljava/util/Comparator;)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lvp/j2;->q:Ljava/util/PriorityQueue;

    .line 19
    .line 20
    :cond_0
    iget-object p0, p0, Lvp/j2;->q:Ljava/util/PriorityQueue;

    .line 21
    .line 22
    return-object p0
.end method

.method public final z0()V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lvp/j2;->r:Z

    .line 6
    .line 7
    invoke-virtual {p0}, Lvp/j2;->y0()Ljava/util/PriorityQueue;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {v1}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-nez v1, :cond_2

    .line 16
    .line 17
    iget-boolean v1, p0, Lvp/j2;->m:Z

    .line 18
    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {p0}, Lvp/j2;->y0()Ljava/util/PriorityQueue;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {v1}, Ljava/util/PriorityQueue;->poll()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lvp/o3;

    .line 31
    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    iget-object v2, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v2, Lvp/g1;

    .line 37
    .line 38
    iget-object v3, v2, Lvp/g1;->l:Lvp/d4;

    .line 39
    .line 40
    invoke-static {v3}, Lvp/g1;->g(Lap0/o;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v3}, Lvp/d4;->u0()Lga/a;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    if-eqz v3, :cond_2

    .line 48
    .line 49
    const/4 v4, 0x1

    .line 50
    iput-boolean v4, p0, Lvp/j2;->m:Z

    .line 51
    .line 52
    iget-object v2, v2, Lvp/g1;->i:Lvp/p0;

    .line 53
    .line 54
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 55
    .line 56
    .line 57
    iget-object v2, v2, Lvp/p0;->r:Lvp/n0;

    .line 58
    .line 59
    iget-object v4, v1, Lvp/o3;->d:Ljava/lang/String;

    .line 60
    .line 61
    const-string v5, "Registering trigger URI"

    .line 62
    .line 63
    invoke-virtual {v2, v4, v5}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-static {v4}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-virtual {v3, v2}, Lga/a;->e(Landroid/net/Uri;)Lcom/google/common/util/concurrent/ListenableFuture;

    .line 71
    .line 72
    .line 73
    move-result-object v2

    .line 74
    if-nez v2, :cond_1

    .line 75
    .line 76
    iput-boolean v0, p0, Lvp/j2;->m:Z

    .line 77
    .line 78
    invoke-virtual {p0}, Lvp/j2;->y0()Ljava/util/PriorityQueue;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-virtual {p0, v1}, Ljava/util/PriorityQueue;->add(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :cond_1
    new-instance v0, Lj0/f;

    .line 87
    .line 88
    const/4 v3, 0x2

    .line 89
    invoke-direct {v0, p0, v3}, Lj0/f;-><init>(Ljava/lang/Object;I)V

    .line 90
    .line 91
    .line 92
    new-instance v3, Lvp/y1;

    .line 93
    .line 94
    const/4 v4, 0x0

    .line 95
    invoke-direct {v3, v4, p0, v1}, Lvp/y1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    new-instance p0, Llr/b;

    .line 99
    .line 100
    const/4 v1, 0x0

    .line 101
    invoke-direct {p0, v1, v2, v3}, Llr/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    invoke-interface {v2, v0, p0}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 105
    .line 106
    .line 107
    :cond_2
    :goto_0
    return-void
.end method
