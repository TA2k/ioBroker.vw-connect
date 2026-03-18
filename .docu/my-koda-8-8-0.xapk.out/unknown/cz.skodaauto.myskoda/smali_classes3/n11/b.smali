.class public final Ln11/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final A:Ln11/b;

.field public static final B:Ln11/b;

.field public static final C:Ln11/b;

.field public static final D:Ln11/b;

.field public static final h:Ln11/b;

.field public static final i:Ln11/b;

.field public static final j:Ln11/b;

.field public static final k:Ln11/b;

.field public static final l:Ln11/b;

.field public static final m:Ln11/b;

.field public static final n:Ln11/b;

.field public static final o:Ln11/b;

.field public static final p:Ln11/b;

.field public static final q:Ln11/b;

.field public static final r:Ln11/b;

.field public static final s:Ln11/b;

.field public static final t:Ln11/b;

.field public static final u:Ln11/b;

.field public static final v:Ln11/b;

.field public static final w:Ln11/b;

.field public static final x:Ln11/b;

.field public static final y:Ln11/b;

.field public static final z:Ln11/b;


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:B

.field public final transient f:Ln11/h;

.field public final transient g:Ln11/h;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Ln11/b;

    .line 2
    .line 3
    const-string v1, "era"

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    sget-object v3, Ln11/h;->f:Ln11/h;

    .line 7
    .line 8
    const/4 v4, 0x0

    .line 9
    invoke-direct {v0, v1, v2, v3, v4}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Ln11/b;->h:Ln11/b;

    .line 13
    .line 14
    new-instance v0, Ln11/b;

    .line 15
    .line 16
    const-string v1, "yearOfEra"

    .line 17
    .line 18
    const/4 v2, 0x2

    .line 19
    sget-object v5, Ln11/h;->i:Ln11/h;

    .line 20
    .line 21
    invoke-direct {v0, v1, v2, v5, v3}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Ln11/b;->i:Ln11/b;

    .line 25
    .line 26
    new-instance v0, Ln11/b;

    .line 27
    .line 28
    const-string v1, "centuryOfEra"

    .line 29
    .line 30
    const/4 v2, 0x3

    .line 31
    sget-object v6, Ln11/h;->g:Ln11/h;

    .line 32
    .line 33
    invoke-direct {v0, v1, v2, v6, v3}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 34
    .line 35
    .line 36
    sput-object v0, Ln11/b;->j:Ln11/b;

    .line 37
    .line 38
    new-instance v0, Ln11/b;

    .line 39
    .line 40
    const-string v1, "yearOfCentury"

    .line 41
    .line 42
    const/4 v2, 0x4

    .line 43
    invoke-direct {v0, v1, v2, v5, v6}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 44
    .line 45
    .line 46
    sput-object v0, Ln11/b;->k:Ln11/b;

    .line 47
    .line 48
    new-instance v0, Ln11/b;

    .line 49
    .line 50
    const-string v1, "year"

    .line 51
    .line 52
    const/4 v2, 0x5

    .line 53
    invoke-direct {v0, v1, v2, v5, v4}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 54
    .line 55
    .line 56
    sput-object v0, Ln11/b;->l:Ln11/b;

    .line 57
    .line 58
    new-instance v0, Ln11/b;

    .line 59
    .line 60
    const-string v1, "dayOfYear"

    .line 61
    .line 62
    const/4 v2, 0x6

    .line 63
    sget-object v3, Ln11/h;->l:Ln11/h;

    .line 64
    .line 65
    invoke-direct {v0, v1, v2, v3, v5}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 66
    .line 67
    .line 68
    sput-object v0, Ln11/b;->m:Ln11/b;

    .line 69
    .line 70
    new-instance v0, Ln11/b;

    .line 71
    .line 72
    const-string v1, "monthOfYear"

    .line 73
    .line 74
    const/4 v2, 0x7

    .line 75
    sget-object v7, Ln11/h;->j:Ln11/h;

    .line 76
    .line 77
    invoke-direct {v0, v1, v2, v7, v5}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 78
    .line 79
    .line 80
    sput-object v0, Ln11/b;->n:Ln11/b;

    .line 81
    .line 82
    new-instance v0, Ln11/b;

    .line 83
    .line 84
    const-string v1, "dayOfMonth"

    .line 85
    .line 86
    const/16 v2, 0x8

    .line 87
    .line 88
    invoke-direct {v0, v1, v2, v3, v7}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 89
    .line 90
    .line 91
    sput-object v0, Ln11/b;->o:Ln11/b;

    .line 92
    .line 93
    new-instance v0, Ln11/b;

    .line 94
    .line 95
    const-string v1, "weekyearOfCentury"

    .line 96
    .line 97
    const/16 v2, 0x9

    .line 98
    .line 99
    sget-object v5, Ln11/h;->h:Ln11/h;

    .line 100
    .line 101
    invoke-direct {v0, v1, v2, v5, v6}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 102
    .line 103
    .line 104
    sput-object v0, Ln11/b;->p:Ln11/b;

    .line 105
    .line 106
    new-instance v0, Ln11/b;

    .line 107
    .line 108
    const-string v1, "weekyear"

    .line 109
    .line 110
    const/16 v2, 0xa

    .line 111
    .line 112
    invoke-direct {v0, v1, v2, v5, v4}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 113
    .line 114
    .line 115
    sput-object v0, Ln11/b;->q:Ln11/b;

    .line 116
    .line 117
    new-instance v0, Ln11/b;

    .line 118
    .line 119
    const-string v1, "weekOfWeekyear"

    .line 120
    .line 121
    const/16 v2, 0xb

    .line 122
    .line 123
    sget-object v4, Ln11/h;->k:Ln11/h;

    .line 124
    .line 125
    invoke-direct {v0, v1, v2, v4, v5}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 126
    .line 127
    .line 128
    sput-object v0, Ln11/b;->r:Ln11/b;

    .line 129
    .line 130
    new-instance v0, Ln11/b;

    .line 131
    .line 132
    const-string v1, "dayOfWeek"

    .line 133
    .line 134
    const/16 v2, 0xc

    .line 135
    .line 136
    invoke-direct {v0, v1, v2, v3, v4}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 137
    .line 138
    .line 139
    sput-object v0, Ln11/b;->s:Ln11/b;

    .line 140
    .line 141
    new-instance v0, Ln11/b;

    .line 142
    .line 143
    const-string v1, "halfdayOfDay"

    .line 144
    .line 145
    const/16 v2, 0xd

    .line 146
    .line 147
    sget-object v4, Ln11/h;->m:Ln11/h;

    .line 148
    .line 149
    invoke-direct {v0, v1, v2, v4, v3}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 150
    .line 151
    .line 152
    sput-object v0, Ln11/b;->t:Ln11/b;

    .line 153
    .line 154
    new-instance v0, Ln11/b;

    .line 155
    .line 156
    const-string v1, "hourOfHalfday"

    .line 157
    .line 158
    const/16 v2, 0xe

    .line 159
    .line 160
    sget-object v5, Ln11/h;->n:Ln11/h;

    .line 161
    .line 162
    invoke-direct {v0, v1, v2, v5, v4}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 163
    .line 164
    .line 165
    sput-object v0, Ln11/b;->u:Ln11/b;

    .line 166
    .line 167
    new-instance v0, Ln11/b;

    .line 168
    .line 169
    const-string v1, "clockhourOfHalfday"

    .line 170
    .line 171
    const/16 v2, 0xf

    .line 172
    .line 173
    invoke-direct {v0, v1, v2, v5, v4}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 174
    .line 175
    .line 176
    sput-object v0, Ln11/b;->v:Ln11/b;

    .line 177
    .line 178
    new-instance v0, Ln11/b;

    .line 179
    .line 180
    const-string v1, "clockhourOfDay"

    .line 181
    .line 182
    const/16 v2, 0x10

    .line 183
    .line 184
    invoke-direct {v0, v1, v2, v5, v3}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 185
    .line 186
    .line 187
    sput-object v0, Ln11/b;->w:Ln11/b;

    .line 188
    .line 189
    new-instance v0, Ln11/b;

    .line 190
    .line 191
    const-string v1, "hourOfDay"

    .line 192
    .line 193
    const/16 v2, 0x11

    .line 194
    .line 195
    invoke-direct {v0, v1, v2, v5, v3}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 196
    .line 197
    .line 198
    sput-object v0, Ln11/b;->x:Ln11/b;

    .line 199
    .line 200
    new-instance v0, Ln11/b;

    .line 201
    .line 202
    const-string v1, "minuteOfDay"

    .line 203
    .line 204
    const/16 v2, 0x12

    .line 205
    .line 206
    sget-object v4, Ln11/h;->o:Ln11/h;

    .line 207
    .line 208
    invoke-direct {v0, v1, v2, v4, v3}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 209
    .line 210
    .line 211
    sput-object v0, Ln11/b;->y:Ln11/b;

    .line 212
    .line 213
    new-instance v0, Ln11/b;

    .line 214
    .line 215
    const-string v1, "minuteOfHour"

    .line 216
    .line 217
    const/16 v2, 0x13

    .line 218
    .line 219
    invoke-direct {v0, v1, v2, v4, v5}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 220
    .line 221
    .line 222
    sput-object v0, Ln11/b;->z:Ln11/b;

    .line 223
    .line 224
    new-instance v0, Ln11/b;

    .line 225
    .line 226
    const-string v1, "secondOfDay"

    .line 227
    .line 228
    const/16 v2, 0x14

    .line 229
    .line 230
    sget-object v5, Ln11/h;->p:Ln11/h;

    .line 231
    .line 232
    invoke-direct {v0, v1, v2, v5, v3}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 233
    .line 234
    .line 235
    sput-object v0, Ln11/b;->A:Ln11/b;

    .line 236
    .line 237
    new-instance v0, Ln11/b;

    .line 238
    .line 239
    const-string v1, "secondOfMinute"

    .line 240
    .line 241
    const/16 v2, 0x15

    .line 242
    .line 243
    invoke-direct {v0, v1, v2, v5, v4}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 244
    .line 245
    .line 246
    sput-object v0, Ln11/b;->B:Ln11/b;

    .line 247
    .line 248
    new-instance v0, Ln11/b;

    .line 249
    .line 250
    const-string v1, "millisOfDay"

    .line 251
    .line 252
    const/16 v2, 0x16

    .line 253
    .line 254
    sget-object v4, Ln11/h;->q:Ln11/h;

    .line 255
    .line 256
    invoke-direct {v0, v1, v2, v4, v3}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 257
    .line 258
    .line 259
    sput-object v0, Ln11/b;->C:Ln11/b;

    .line 260
    .line 261
    new-instance v0, Ln11/b;

    .line 262
    .line 263
    const-string v1, "millisOfSecond"

    .line 264
    .line 265
    const/16 v2, 0x17

    .line 266
    .line 267
    invoke-direct {v0, v1, v2, v4, v5}, Ln11/b;-><init>(Ljava/lang/String;BLn11/h;Ln11/h;)V

    .line 268
    .line 269
    .line 270
    sput-object v0, Ln11/b;->D:Ln11/b;

    .line 271
    .line 272
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;BLn11/h;Ln11/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln11/b;->d:Ljava/lang/String;

    .line 5
    .line 6
    iput-byte p2, p0, Ln11/b;->e:B

    .line 7
    .line 8
    iput-object p3, p0, Ln11/b;->f:Ln11/h;

    .line 9
    .line 10
    iput-object p4, p0, Ln11/b;->g:Ln11/h;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Ljp/u1;)Ln11/a;
    .locals 1

    .line 1
    sget-object v0, Ln11/c;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lp11/n;->P()Lp11/n;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    :cond_0
    iget-byte p0, p0, Ln11/b;->e:B

    .line 10
    .line 11
    packed-switch p0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    new-instance p0, Ljava/lang/InternalError;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/InternalError;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0

    .line 20
    :pswitch_0
    invoke-virtual {p1}, Ljp/u1;->u()Ln11/a;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_1
    invoke-virtual {p1}, Ljp/u1;->t()Ln11/a;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :pswitch_2
    invoke-virtual {p1}, Ljp/u1;->B()Ln11/a;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_3
    invoke-virtual {p1}, Ljp/u1;->A()Ln11/a;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_4
    invoke-virtual {p1}, Ljp/u1;->w()Ln11/a;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0

    .line 45
    :pswitch_5
    invoke-virtual {p1}, Ljp/u1;->v()Ln11/a;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0

    .line 50
    :pswitch_6
    invoke-virtual {p1}, Ljp/u1;->p()Ln11/a;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0

    .line 55
    :pswitch_7
    invoke-virtual {p1}, Ljp/u1;->c()Ln11/a;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :pswitch_8
    invoke-virtual {p1}, Ljp/u1;->d()Ln11/a;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :pswitch_9
    invoke-virtual {p1}, Ljp/u1;->q()Ln11/a;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    return-object p0

    .line 70
    :pswitch_a
    invoke-virtual {p1}, Ljp/u1;->n()Ln11/a;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_b
    invoke-virtual {p1}, Ljp/u1;->g()Ln11/a;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    return-object p0

    .line 80
    :pswitch_c
    invoke-virtual {p1}, Ljp/u1;->D()Ln11/a;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0

    .line 85
    :pswitch_d
    invoke-virtual {p1}, Ljp/u1;->F()Ln11/a;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    return-object p0

    .line 90
    :pswitch_e
    invoke-virtual {p1}, Ljp/u1;->G()Ln11/a;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    return-object p0

    .line 95
    :pswitch_f
    invoke-virtual {p1}, Ljp/u1;->f()Ln11/a;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    return-object p0

    .line 100
    :pswitch_10
    invoke-virtual {p1}, Ljp/u1;->y()Ln11/a;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0

    .line 105
    :pswitch_11
    invoke-virtual {p1}, Ljp/u1;->h()Ln11/a;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    return-object p0

    .line 110
    :pswitch_12
    invoke-virtual {p1}, Ljp/u1;->K()Ln11/a;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0

    .line 115
    :pswitch_13
    invoke-virtual {p1}, Ljp/u1;->L()Ln11/a;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    return-object p0

    .line 120
    :pswitch_14
    invoke-virtual {p1}, Ljp/u1;->b()Ln11/a;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    return-object p0

    .line 125
    :pswitch_15
    invoke-virtual {p1}, Ljp/u1;->M()Ln11/a;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0

    .line 130
    :pswitch_16
    invoke-virtual {p1}, Ljp/u1;->j()Ln11/a;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    return-object p0

    .line 135
    :pswitch_data_0
    .packed-switch 0x1
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

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    instance-of v0, p1, Ln11/b;

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    check-cast p1, Ln11/b;

    .line 9
    .line 10
    iget-byte p1, p1, Ln11/b;->e:B

    .line 11
    .line 12
    iget-byte p0, p0, Ln11/b;->e:B

    .line 13
    .line 14
    if-ne p0, p1, :cond_1

    .line 15
    .line 16
    :goto_0
    const/4 p0, 0x1

    .line 17
    return p0

    .line 18
    :cond_1
    const/4 p0, 0x0

    .line 19
    return p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iget-byte p0, p0, Ln11/b;->e:B

    .line 3
    .line 4
    shl-int p0, v0, p0

    .line 5
    .line 6
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ln11/b;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
