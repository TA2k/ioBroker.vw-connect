.class public abstract Lh2/g1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;

.field public static final b:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lgz0/e0;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Lgz0/e0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Ll2/u2;

    .line 8
    .line 9
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 10
    .line 11
    .line 12
    sput-object v1, Lh2/g1;->a:Ll2/u2;

    .line 13
    .line 14
    new-instance v0, Lgz0/e0;

    .line 15
    .line 16
    const/4 v1, 0x7

    .line 17
    invoke-direct {v0, v1}, Lgz0/e0;-><init>(I)V

    .line 18
    .line 19
    .line 20
    new-instance v1, Ll2/u2;

    .line 21
    .line 22
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 23
    .line 24
    .line 25
    sput-object v1, Lh2/g1;->b:Ll2/u2;

    .line 26
    .line 27
    return-void
.end method

.method public static final a(Lh2/f1;J)J
    .locals 10

    .line 1
    iget-wide v0, p0, Lh2/f1;->a:J

    .line 2
    .line 3
    iget-wide v2, p0, Lh2/f1;->U:J

    .line 4
    .line 5
    iget-wide v4, p0, Lh2/f1;->Q:J

    .line 6
    .line 7
    iget-wide v6, p0, Lh2/f1;->M:J

    .line 8
    .line 9
    iget-wide v8, p0, Lh2/f1;->q:J

    .line 10
    .line 11
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-wide p0, p0, Lh2/f1;->b:J

    .line 18
    .line 19
    return-wide p0

    .line 20
    :cond_0
    iget-wide v0, p0, Lh2/f1;->f:J

    .line 21
    .line 22
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    iget-wide p0, p0, Lh2/f1;->g:J

    .line 29
    .line 30
    return-wide p0

    .line 31
    :cond_1
    iget-wide v0, p0, Lh2/f1;->j:J

    .line 32
    .line 33
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    iget-wide p0, p0, Lh2/f1;->k:J

    .line 40
    .line 41
    return-wide p0

    .line 42
    :cond_2
    iget-wide v0, p0, Lh2/f1;->n:J

    .line 43
    .line 44
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_3

    .line 49
    .line 50
    iget-wide p0, p0, Lh2/f1;->o:J

    .line 51
    .line 52
    return-wide p0

    .line 53
    :cond_3
    iget-wide v0, p0, Lh2/f1;->w:J

    .line 54
    .line 55
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-eqz v0, :cond_4

    .line 60
    .line 61
    iget-wide p0, p0, Lh2/f1;->x:J

    .line 62
    .line 63
    return-wide p0

    .line 64
    :cond_4
    iget-wide v0, p0, Lh2/f1;->c:J

    .line 65
    .line 66
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-eqz v0, :cond_5

    .line 71
    .line 72
    iget-wide p0, p0, Lh2/f1;->d:J

    .line 73
    .line 74
    return-wide p0

    .line 75
    :cond_5
    iget-wide v0, p0, Lh2/f1;->h:J

    .line 76
    .line 77
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-eqz v0, :cond_6

    .line 82
    .line 83
    iget-wide p0, p0, Lh2/f1;->i:J

    .line 84
    .line 85
    return-wide p0

    .line 86
    :cond_6
    iget-wide v0, p0, Lh2/f1;->l:J

    .line 87
    .line 88
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-eqz v0, :cond_7

    .line 93
    .line 94
    iget-wide p0, p0, Lh2/f1;->m:J

    .line 95
    .line 96
    return-wide p0

    .line 97
    :cond_7
    iget-wide v0, p0, Lh2/f1;->y:J

    .line 98
    .line 99
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    if-eqz v0, :cond_8

    .line 104
    .line 105
    iget-wide p0, p0, Lh2/f1;->z:J

    .line 106
    .line 107
    return-wide p0

    .line 108
    :cond_8
    iget-wide v0, p0, Lh2/f1;->u:J

    .line 109
    .line 110
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 111
    .line 112
    .line 113
    move-result v0

    .line 114
    if-eqz v0, :cond_9

    .line 115
    .line 116
    iget-wide p0, p0, Lh2/f1;->v:J

    .line 117
    .line 118
    return-wide p0

    .line 119
    :cond_9
    iget-wide v0, p0, Lh2/f1;->p:J

    .line 120
    .line 121
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    if-eqz v0, :cond_a

    .line 126
    .line 127
    return-wide v8

    .line 128
    :cond_a
    iget-wide v0, p0, Lh2/f1;->r:J

    .line 129
    .line 130
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-eqz v0, :cond_b

    .line 135
    .line 136
    iget-wide p0, p0, Lh2/f1;->s:J

    .line 137
    .line 138
    return-wide p0

    .line 139
    :cond_b
    iget-wide v0, p0, Lh2/f1;->D:J

    .line 140
    .line 141
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 142
    .line 143
    .line 144
    move-result v0

    .line 145
    if-eqz v0, :cond_c

    .line 146
    .line 147
    return-wide v8

    .line 148
    :cond_c
    iget-wide v0, p0, Lh2/f1;->F:J

    .line 149
    .line 150
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 151
    .line 152
    .line 153
    move-result v0

    .line 154
    if-eqz v0, :cond_d

    .line 155
    .line 156
    return-wide v8

    .line 157
    :cond_d
    iget-wide v0, p0, Lh2/f1;->G:J

    .line 158
    .line 159
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    if-eqz v0, :cond_e

    .line 164
    .line 165
    return-wide v8

    .line 166
    :cond_e
    iget-wide v0, p0, Lh2/f1;->H:J

    .line 167
    .line 168
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 169
    .line 170
    .line 171
    move-result v0

    .line 172
    if-eqz v0, :cond_f

    .line 173
    .line 174
    return-wide v8

    .line 175
    :cond_f
    iget-wide v0, p0, Lh2/f1;->I:J

    .line 176
    .line 177
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 178
    .line 179
    .line 180
    move-result v0

    .line 181
    if-eqz v0, :cond_10

    .line 182
    .line 183
    return-wide v8

    .line 184
    :cond_10
    iget-wide v0, p0, Lh2/f1;->J:J

    .line 185
    .line 186
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 187
    .line 188
    .line 189
    move-result v0

    .line 190
    if-eqz v0, :cond_11

    .line 191
    .line 192
    return-wide v8

    .line 193
    :cond_11
    iget-wide v0, p0, Lh2/f1;->E:J

    .line 194
    .line 195
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 196
    .line 197
    .line 198
    move-result v0

    .line 199
    if-eqz v0, :cond_12

    .line 200
    .line 201
    return-wide v8

    .line 202
    :cond_12
    iget-wide v0, p0, Lh2/f1;->K:J

    .line 203
    .line 204
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 205
    .line 206
    .line 207
    move-result v0

    .line 208
    if-eqz v0, :cond_13

    .line 209
    .line 210
    return-wide v6

    .line 211
    :cond_13
    iget-wide v0, p0, Lh2/f1;->L:J

    .line 212
    .line 213
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 214
    .line 215
    .line 216
    move-result v0

    .line 217
    if-eqz v0, :cond_14

    .line 218
    .line 219
    return-wide v6

    .line 220
    :cond_14
    iget-wide v0, p0, Lh2/f1;->O:J

    .line 221
    .line 222
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 223
    .line 224
    .line 225
    move-result v0

    .line 226
    if-eqz v0, :cond_15

    .line 227
    .line 228
    return-wide v4

    .line 229
    :cond_15
    iget-wide v0, p0, Lh2/f1;->P:J

    .line 230
    .line 231
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 232
    .line 233
    .line 234
    move-result v0

    .line 235
    if-eqz v0, :cond_16

    .line 236
    .line 237
    return-wide v4

    .line 238
    :cond_16
    iget-wide v0, p0, Lh2/f1;->S:J

    .line 239
    .line 240
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 241
    .line 242
    .line 243
    move-result v0

    .line 244
    if-eqz v0, :cond_17

    .line 245
    .line 246
    return-wide v2

    .line 247
    :cond_17
    iget-wide v0, p0, Lh2/f1;->T:J

    .line 248
    .line 249
    invoke-static {p1, p2, v0, v1}, Le3/s;->c(JJ)Z

    .line 250
    .line 251
    .line 252
    move-result p0

    .line 253
    if-eqz p0, :cond_18

    .line 254
    .line 255
    return-wide v2

    .line 256
    :cond_18
    sget p0, Le3/s;->j:I

    .line 257
    .line 258
    sget-wide p0, Le3/s;->i:J

    .line 259
    .line 260
    return-wide p0
.end method

.method public static final b(JLl2/o;)J
    .locals 2

    .line 1
    check-cast p2, Ll2/t;

    .line 2
    .line 3
    const v0, 0x553c0da

    .line 4
    .line 5
    .line 6
    invoke-virtual {p2, v0}, Ll2/t;->Y(I)V

    .line 7
    .line 8
    .line 9
    sget-object v0, Lh2/g1;->a:Ll2/u2;

    .line 10
    .line 11
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lh2/f1;

    .line 16
    .line 17
    invoke-static {v0, p0, p1}, Lh2/g1;->a(Lh2/f1;J)J

    .line 18
    .line 19
    .line 20
    move-result-wide p0

    .line 21
    const-wide/16 v0, 0x10

    .line 22
    .line 23
    cmp-long v0, p0, v0

    .line 24
    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    sget-object p0, Lh2/p1;->a:Ll2/e0;

    .line 29
    .line 30
    invoke-virtual {p2, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Le3/s;

    .line 35
    .line 36
    iget-wide p0, p0, Le3/s;->a:J

    .line 37
    .line 38
    :goto_0
    const/4 v0, 0x0

    .line 39
    invoke-virtual {p2, v0}, Ll2/t;->q(Z)V

    .line 40
    .line 41
    .line 42
    return-wide p0
.end method

.method public static final c(Lh2/f1;Lk2/l;)J
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    packed-switch p1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p0, La8/r0;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    iget-wide p0, p0, Lh2/f1;->T:J

    .line 15
    .line 16
    return-wide p0

    .line 17
    :pswitch_1
    iget-wide p0, p0, Lh2/f1;->S:J

    .line 18
    .line 19
    return-wide p0

    .line 20
    :pswitch_2
    iget-wide p0, p0, Lh2/f1;->l:J

    .line 21
    .line 22
    return-wide p0

    .line 23
    :pswitch_3
    iget-wide p0, p0, Lh2/f1;->j:J

    .line 24
    .line 25
    return-wide p0

    .line 26
    :pswitch_4
    iget-wide p0, p0, Lh2/f1;->r:J

    .line 27
    .line 28
    return-wide p0

    .line 29
    :pswitch_5
    iget-wide p0, p0, Lh2/f1;->t:J

    .line 30
    .line 31
    return-wide p0

    .line 32
    :pswitch_6
    iget-wide p0, p0, Lh2/f1;->E:J

    .line 33
    .line 34
    return-wide p0

    .line 35
    :pswitch_7
    iget-wide p0, p0, Lh2/f1;->J:J

    .line 36
    .line 37
    return-wide p0

    .line 38
    :pswitch_8
    iget-wide p0, p0, Lh2/f1;->I:J

    .line 39
    .line 40
    return-wide p0

    .line 41
    :pswitch_9
    iget-wide p0, p0, Lh2/f1;->H:J

    .line 42
    .line 43
    return-wide p0

    .line 44
    :pswitch_a
    iget-wide p0, p0, Lh2/f1;->G:J

    .line 45
    .line 46
    return-wide p0

    .line 47
    :pswitch_b
    iget-wide p0, p0, Lh2/f1;->F:J

    .line 48
    .line 49
    return-wide p0

    .line 50
    :pswitch_c
    iget-wide p0, p0, Lh2/f1;->D:J

    .line 51
    .line 52
    return-wide p0

    .line 53
    :pswitch_d
    iget-wide p0, p0, Lh2/f1;->p:J

    .line 54
    .line 55
    return-wide p0

    .line 56
    :pswitch_e
    iget-wide p0, p0, Lh2/f1;->P:J

    .line 57
    .line 58
    return-wide p0

    .line 59
    :pswitch_f
    iget-wide p0, p0, Lh2/f1;->O:J

    .line 60
    .line 61
    return-wide p0

    .line 62
    :pswitch_10
    iget-wide p0, p0, Lh2/f1;->h:J

    .line 63
    .line 64
    return-wide p0

    .line 65
    :pswitch_11
    iget-wide p0, p0, Lh2/f1;->f:J

    .line 66
    .line 67
    return-wide p0

    .line 68
    :pswitch_12
    iget-wide p0, p0, Lh2/f1;->C:J

    .line 69
    .line 70
    return-wide p0

    .line 71
    :pswitch_13
    iget-wide p0, p0, Lh2/f1;->L:J

    .line 72
    .line 73
    return-wide p0

    .line 74
    :pswitch_14
    iget-wide p0, p0, Lh2/f1;->K:J

    .line 75
    .line 76
    return-wide p0

    .line 77
    :pswitch_15
    iget-wide p0, p0, Lh2/f1;->c:J

    .line 78
    .line 79
    return-wide p0

    .line 80
    :pswitch_16
    iget-wide p0, p0, Lh2/f1;->a:J

    .line 81
    .line 82
    return-wide p0

    .line 83
    :pswitch_17
    iget-wide p0, p0, Lh2/f1;->B:J

    .line 84
    .line 85
    return-wide p0

    .line 86
    :pswitch_18
    iget-wide p0, p0, Lh2/f1;->A:J

    .line 87
    .line 88
    return-wide p0

    .line 89
    :pswitch_19
    iget-wide p0, p0, Lh2/f1;->V:J

    .line 90
    .line 91
    return-wide p0

    .line 92
    :pswitch_1a
    iget-wide p0, p0, Lh2/f1;->U:J

    .line 93
    .line 94
    return-wide p0

    .line 95
    :pswitch_1b
    iget-wide p0, p0, Lh2/f1;->m:J

    .line 96
    .line 97
    return-wide p0

    .line 98
    :pswitch_1c
    iget-wide p0, p0, Lh2/f1;->k:J

    .line 99
    .line 100
    return-wide p0

    .line 101
    :pswitch_1d
    iget-wide p0, p0, Lh2/f1;->s:J

    .line 102
    .line 103
    return-wide p0

    .line 104
    :pswitch_1e
    iget-wide p0, p0, Lh2/f1;->q:J

    .line 105
    .line 106
    return-wide p0

    .line 107
    :pswitch_1f
    iget-wide p0, p0, Lh2/f1;->R:J

    .line 108
    .line 109
    return-wide p0

    .line 110
    :pswitch_20
    iget-wide p0, p0, Lh2/f1;->Q:J

    .line 111
    .line 112
    return-wide p0

    .line 113
    :pswitch_21
    iget-wide p0, p0, Lh2/f1;->i:J

    .line 114
    .line 115
    return-wide p0

    .line 116
    :pswitch_22
    iget-wide p0, p0, Lh2/f1;->g:J

    .line 117
    .line 118
    return-wide p0

    .line 119
    :pswitch_23
    iget-wide p0, p0, Lh2/f1;->N:J

    .line 120
    .line 121
    return-wide p0

    .line 122
    :pswitch_24
    iget-wide p0, p0, Lh2/f1;->M:J

    .line 123
    .line 124
    return-wide p0

    .line 125
    :pswitch_25
    iget-wide p0, p0, Lh2/f1;->d:J

    .line 126
    .line 127
    return-wide p0

    .line 128
    :pswitch_26
    iget-wide p0, p0, Lh2/f1;->b:J

    .line 129
    .line 130
    return-wide p0

    .line 131
    :pswitch_27
    iget-wide p0, p0, Lh2/f1;->z:J

    .line 132
    .line 133
    return-wide p0

    .line 134
    :pswitch_28
    iget-wide p0, p0, Lh2/f1;->x:J

    .line 135
    .line 136
    return-wide p0

    .line 137
    :pswitch_29
    iget-wide p0, p0, Lh2/f1;->o:J

    .line 138
    .line 139
    return-wide p0

    .line 140
    :pswitch_2a
    iget-wide p0, p0, Lh2/f1;->u:J

    .line 141
    .line 142
    return-wide p0

    .line 143
    :pswitch_2b
    iget-wide p0, p0, Lh2/f1;->e:J

    .line 144
    .line 145
    return-wide p0

    .line 146
    :pswitch_2c
    iget-wide p0, p0, Lh2/f1;->v:J

    .line 147
    .line 148
    return-wide p0

    .line 149
    :pswitch_2d
    iget-wide p0, p0, Lh2/f1;->y:J

    .line 150
    .line 151
    return-wide p0

    .line 152
    :pswitch_2e
    iget-wide p0, p0, Lh2/f1;->w:J

    .line 153
    .line 154
    return-wide p0

    .line 155
    :pswitch_2f
    iget-wide p0, p0, Lh2/f1;->n:J

    .line 156
    .line 157
    return-wide p0

    .line 158
    nop

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2f
        :pswitch_2e
        :pswitch_2d
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
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

.method public static final d(Lk2/l;Ll2/o;)J
    .locals 1

    .line 1
    sget-object v0, Lh2/g1;->a:Ll2/u2;

    .line 2
    .line 3
    check-cast p1, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lh2/f1;

    .line 10
    .line 11
    invoke-static {p1, p0}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    return-wide p0
.end method

.method public static e(IJJ)Lh2/f1;
    .locals 97

    .line 1
    sget-wide v1, Lk2/k;->z:J

    .line 2
    .line 3
    sget-wide v3, Lk2/k;->j:J

    .line 4
    .line 5
    sget-wide v5, Lk2/k;->A:J

    .line 6
    .line 7
    sget-wide v7, Lk2/k;->k:J

    .line 8
    .line 9
    sget-wide v9, Lk2/k;->e:J

    .line 10
    .line 11
    sget-wide v11, Lk2/k;->E:J

    .line 12
    .line 13
    sget-wide v13, Lk2/k;->n:J

    .line 14
    .line 15
    sget-wide v15, Lk2/k;->F:J

    .line 16
    .line 17
    sget-wide v17, Lk2/k;->o:J

    .line 18
    .line 19
    sget-wide v19, Lk2/k;->R:J

    .line 20
    .line 21
    sget-wide v21, Lk2/k;->t:J

    .line 22
    .line 23
    sget-wide v23, Lk2/k;->S:J

    .line 24
    .line 25
    sget-wide v25, Lk2/k;->u:J

    .line 26
    .line 27
    sget-wide v27, Lk2/k;->a:J

    .line 28
    .line 29
    sget-wide v29, Lk2/k;->g:J

    .line 30
    .line 31
    sget-wide v31, Lk2/k;->I:J

    .line 32
    .line 33
    const/high16 v0, 0x10000

    .line 34
    .line 35
    and-int v0, p0, v0

    .line 36
    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    sget-wide v33, Lk2/k;->r:J

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    move-wide/from16 v33, p1

    .line 43
    .line 44
    :goto_0
    sget-wide v35, Lk2/k;->Q:J

    .line 45
    .line 46
    sget-wide v37, Lk2/k;->s:J

    .line 47
    .line 48
    sget-wide v41, Lk2/k;->f:J

    .line 49
    .line 50
    sget-wide v43, Lk2/k;->d:J

    .line 51
    .line 52
    sget-wide v45, Lk2/k;->b:J

    .line 53
    .line 54
    sget-wide v47, Lk2/k;->h:J

    .line 55
    .line 56
    sget-wide v49, Lk2/k;->c:J

    .line 57
    .line 58
    sget-wide v51, Lk2/k;->i:J

    .line 59
    .line 60
    const/high16 v0, 0x4000000

    .line 61
    .line 62
    and-int v0, p0, v0

    .line 63
    .line 64
    if-eqz v0, :cond_1

    .line 65
    .line 66
    sget-wide v39, Lk2/k;->x:J

    .line 67
    .line 68
    move-wide/from16 v53, v39

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_1
    move-wide/from16 v53, p3

    .line 72
    .line 73
    :goto_1
    sget-wide v55, Lk2/k;->y:J

    .line 74
    .line 75
    sget-wide v57, Lk2/k;->D:J

    .line 76
    .line 77
    sget-wide v59, Lk2/k;->J:J

    .line 78
    .line 79
    sget-wide v63, Lk2/k;->K:J

    .line 80
    .line 81
    sget-wide v65, Lk2/k;->L:J

    .line 82
    .line 83
    sget-wide v67, Lk2/k;->M:J

    .line 84
    .line 85
    sget-wide v69, Lk2/k;->N:J

    .line 86
    .line 87
    sget-wide v71, Lk2/k;->O:J

    .line 88
    .line 89
    sget-wide v61, Lk2/k;->P:J

    .line 90
    .line 91
    sget-wide v73, Lk2/k;->B:J

    .line 92
    .line 93
    sget-wide v75, Lk2/k;->C:J

    .line 94
    .line 95
    sget-wide v77, Lk2/k;->l:J

    .line 96
    .line 97
    sget-wide v79, Lk2/k;->m:J

    .line 98
    .line 99
    sget-wide v81, Lk2/k;->G:J

    .line 100
    .line 101
    sget-wide v83, Lk2/k;->H:J

    .line 102
    .line 103
    sget-wide v85, Lk2/k;->p:J

    .line 104
    .line 105
    sget-wide v87, Lk2/k;->q:J

    .line 106
    .line 107
    sget-wide v89, Lk2/k;->T:J

    .line 108
    .line 109
    sget-wide v91, Lk2/k;->U:J

    .line 110
    .line 111
    sget-wide v93, Lk2/k;->v:J

    .line 112
    .line 113
    sget-wide v95, Lk2/k;->w:J

    .line 114
    .line 115
    new-instance v0, Lh2/f1;

    .line 116
    .line 117
    move-wide/from16 v39, v1

    .line 118
    .line 119
    invoke-direct/range {v0 .. v96}, Lh2/f1;-><init>(JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ)V

    .line 120
    .line 121
    .line 122
    return-object v0
.end method
