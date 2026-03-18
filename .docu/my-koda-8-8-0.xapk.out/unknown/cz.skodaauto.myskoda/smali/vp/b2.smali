.class public final Lvp/b2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Lvp/j2;


# direct methods
.method public constructor <init>(Lvp/j2;JI)V
    .locals 0

    .line 1
    iput p4, p0, Lvp/b2;->d:I

    .line 2
    .line 3
    packed-switch p4, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-wide p2, p0, Lvp/b2;->e:J

    .line 10
    .line 11
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lvp/b2;->f:Lvp/j2;

    .line 15
    .line 16
    return-void

    .line 17
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-wide p2, p0, Lvp/b2;->e:J

    .line 21
    .line 22
    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lvp/b2;->f:Lvp/j2;

    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final run()V
    .locals 9

    .line 1
    iget v0, p0, Lvp/b2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvp/b2;->f:Lvp/j2;

    .line 7
    .line 8
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lvp/b0;->b0()V

    .line 12
    .line 13
    .line 14
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lvp/g1;

    .line 17
    .line 18
    iget-object v2, v1, Lvp/g1;->i:Lvp/p0;

    .line 19
    .line 20
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 21
    .line 22
    .line 23
    iget-object v2, v2, Lvp/p0;->q:Lvp/n0;

    .line 24
    .line 25
    const-string v3, "Resetting analytics data (FE)"

    .line 26
    .line 27
    invoke-virtual {v2, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    iget-object v2, v1, Lvp/g1;->k:Lvp/k3;

    .line 31
    .line 32
    invoke-static {v2}, Lvp/g1;->i(Lvp/b0;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v2}, Lvp/x;->a0()V

    .line 36
    .line 37
    .line 38
    iget-object v3, v2, Lvp/k3;->j:Lc1/i2;

    .line 39
    .line 40
    iget-object v4, v3, Lc1/i2;->f:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v4, Lvp/j3;

    .line 43
    .line 44
    invoke-virtual {v4}, Lvp/o;->c()V

    .line 45
    .line 46
    .line 47
    iget-object v4, v3, Lc1/i2;->g:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v4, Lvp/k3;

    .line 50
    .line 51
    iget-object v4, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v4, Lvp/g1;

    .line 54
    .line 55
    iget-object v4, v4, Lvp/g1;->n:Lto/a;

    .line 56
    .line 57
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 61
    .line 62
    .line 63
    move-result-wide v4

    .line 64
    iput-wide v4, v3, Lc1/i2;->d:J

    .line 65
    .line 66
    iput-wide v4, v3, Lc1/i2;->e:J

    .line 67
    .line 68
    invoke-virtual {v1}, Lvp/g1;->q()Lvp/h0;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    invoke-virtual {v3}, Lvp/h0;->f0()V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v1}, Lvp/g1;->a()Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    xor-int/lit8 v3, v3, 0x1

    .line 80
    .line 81
    iget-object v4, v1, Lvp/g1;->h:Lvp/w0;

    .line 82
    .line 83
    invoke-static {v4}, Lvp/g1;->g(Lap0/o;)V

    .line 84
    .line 85
    .line 86
    iget-object v5, v4, Lvp/w0;->j:La8/s1;

    .line 87
    .line 88
    iget-wide v6, p0, Lvp/b2;->e:J

    .line 89
    .line 90
    invoke-virtual {v5, v6, v7}, La8/s1;->h(J)V

    .line 91
    .line 92
    .line 93
    iget-object p0, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p0, Lvp/g1;

    .line 96
    .line 97
    iget-object v5, p0, Lvp/g1;->h:Lvp/w0;

    .line 98
    .line 99
    invoke-static {v5}, Lvp/g1;->g(Lap0/o;)V

    .line 100
    .line 101
    .line 102
    iget-object v5, v5, Lvp/w0;->z:La8/b;

    .line 103
    .line 104
    invoke-virtual {v5}, La8/b;->t()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v5

    .line 108
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 109
    .line 110
    .line 111
    move-result v5

    .line 112
    const/4 v6, 0x0

    .line 113
    if-nez v5, :cond_0

    .line 114
    .line 115
    iget-object v5, v4, Lvp/w0;->z:La8/b;

    .line 116
    .line 117
    invoke-virtual {v5, v6}, La8/b;->u(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    :cond_0
    iget-object v5, v4, Lvp/w0;->t:La8/s1;

    .line 121
    .line 122
    const-wide/16 v7, 0x0

    .line 123
    .line 124
    invoke-virtual {v5, v7, v8}, La8/s1;->h(J)V

    .line 125
    .line 126
    .line 127
    iget-object v5, v4, Lvp/w0;->u:La8/s1;

    .line 128
    .line 129
    invoke-virtual {v5, v7, v8}, La8/s1;->h(J)V

    .line 130
    .line 131
    .line 132
    iget-object p0, p0, Lvp/g1;->g:Lvp/h;

    .line 133
    .line 134
    invoke-virtual {p0}, Lvp/h;->n0()Z

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    if-nez p0, :cond_1

    .line 139
    .line 140
    invoke-virtual {v4, v3}, Lvp/w0;->j0(Z)V

    .line 141
    .line 142
    .line 143
    :cond_1
    iget-object p0, v4, Lvp/w0;->A:La8/b;

    .line 144
    .line 145
    invoke-virtual {p0, v6}, La8/b;->u(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    iget-object p0, v4, Lvp/w0;->B:La8/s1;

    .line 149
    .line 150
    invoke-virtual {p0, v7, v8}, La8/s1;->h(J)V

    .line 151
    .line 152
    .line 153
    iget-object p0, v4, Lvp/w0;->C:Lun/a;

    .line 154
    .line 155
    invoke-virtual {p0, v6}, Lun/a;->c(Landroid/os/Bundle;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    invoke-virtual {p0}, Lvp/x;->a0()V

    .line 163
    .line 164
    .line 165
    invoke-virtual {p0}, Lvp/b0;->b0()V

    .line 166
    .line 167
    .line 168
    const/4 v4, 0x0

    .line 169
    invoke-virtual {p0, v4}, Lvp/d3;->q0(Z)Lvp/f4;

    .line 170
    .line 171
    .line 172
    move-result-object v4

    .line 173
    invoke-virtual {p0}, Lvp/d3;->m0()V

    .line 174
    .line 175
    .line 176
    iget-object v5, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v5, Lvp/g1;

    .line 179
    .line 180
    invoke-virtual {v5}, Lvp/g1;->n()Lvp/j0;

    .line 181
    .line 182
    .line 183
    move-result-object v5

    .line 184
    invoke-virtual {v5}, Lvp/j0;->e0()V

    .line 185
    .line 186
    .line 187
    new-instance v5, Lvp/y2;

    .line 188
    .line 189
    const/4 v6, 0x0

    .line 190
    invoke-direct {v5, p0, v4, v6}, Lvp/y2;-><init>(Lvp/d3;Lvp/f4;I)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {p0, v5}, Lvp/d3;->o0(Ljava/lang/Runnable;)V

    .line 194
    .line 195
    .line 196
    invoke-static {v2}, Lvp/g1;->i(Lvp/b0;)V

    .line 197
    .line 198
    .line 199
    iget-object p0, v2, Lvp/k3;->i:Lt1/j0;

    .line 200
    .line 201
    invoke-virtual {p0}, Lt1/j0;->o()V

    .line 202
    .line 203
    .line 204
    iput-boolean v3, v0, Lvp/j2;->w:Z

    .line 205
    .line 206
    invoke-virtual {v1}, Lvp/g1;->o()Lvp/d3;

    .line 207
    .line 208
    .line 209
    move-result-object p0

    .line 210
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 211
    .line 212
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 213
    .line 214
    .line 215
    invoke-virtual {p0, v0}, Lvp/d3;->e0(Ljava/util/concurrent/atomic/AtomicReference;)V

    .line 216
    .line 217
    .line 218
    return-void

    .line 219
    :pswitch_0
    iget-object v0, p0, Lvp/b2;->f:Lvp/j2;

    .line 220
    .line 221
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 222
    .line 223
    check-cast v0, Lvp/g1;

    .line 224
    .line 225
    iget-object v1, v0, Lvp/g1;->h:Lvp/w0;

    .line 226
    .line 227
    invoke-static {v1}, Lvp/g1;->g(Lap0/o;)V

    .line 228
    .line 229
    .line 230
    iget-object v1, v1, Lvp/w0;->o:La8/s1;

    .line 231
    .line 232
    iget-wide v2, p0, Lvp/b2;->e:J

    .line 233
    .line 234
    invoke-virtual {v1, v2, v3}, La8/s1;->h(J)V

    .line 235
    .line 236
    .line 237
    iget-object p0, v0, Lvp/g1;->i:Lvp/p0;

    .line 238
    .line 239
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 240
    .line 241
    .line 242
    iget-object p0, p0, Lvp/p0;->q:Lvp/n0;

    .line 243
    .line 244
    const-string v0, "Session timeout duration set"

    .line 245
    .line 246
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    invoke-virtual {p0, v1, v0}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    return-void

    .line 254
    nop

    .line 255
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
