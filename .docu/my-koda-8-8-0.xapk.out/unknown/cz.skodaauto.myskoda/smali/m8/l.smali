.class public final Lm8/l;
.super Lf8/s;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final G2:[I

.field public static H2:Z

.field public static I2:Z


# instance fields
.field public A2:Lm8/k;

.field public B2:Lm8/x;

.field public C2:J

.field public D2:J

.field public E2:Z

.field public F2:I

.field public final Q1:Landroid/content/Context;

.field public final R1:Z

.field public final S1:Lb81/b;

.field public final T1:I

.field public final U1:Z

.field public final V1:Lm8/y;

.field public final W1:Li9/a;

.field public final X1:J

.field public final Y1:Ljava/util/PriorityQueue;

.field public Z1:Lm8/j;

.field public a2:Z

.field public b2:Z

.field public c2:Lm8/i0;

.field public d2:Z

.field public e2:I

.field public f2:Ljava/util/List;

.field public g2:Landroid/view/Surface;

.field public h2:Lm8/n;

.field public i2:Lw7/q;

.field public j2:Z

.field public k2:I

.field public l2:I

.field public m2:J

.field public n2:I

.field public o2:I

.field public p2:I

.field public q2:La8/q1;

.field public r2:Z

.field public s2:J

.field public t2:I

.field public u2:J

.field public v2:Lt7/a1;

.field public w2:Lt7/a1;

.field public x2:I

.field public y2:Z

.field public z2:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x9

    .line 2
    .line 3
    new-array v0, v0, [I

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v0, Lm8/l;->G2:[I

    .line 9
    .line 10
    return-void

    .line 11
    :array_0
    .array-data 4
        0x780
        0x640
        0x5a0
        0x500
        0x3c0
        0x356
        0x280
        0x21c
        0x1e0
    .end array-data
.end method

.method public constructor <init>(Lm8/i;)V
    .locals 7

    .line 1
    iget-object v0, p1, Lm8/i;->c:Lf8/l;

    .line 2
    .line 3
    const/high16 v1, 0x41f00000    # 30.0f

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    invoke-direct {p0, v2, v0, v1}, Lf8/s;-><init>(ILf8/l;F)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p1, Lm8/i;->a:Landroid/content/Context;

    .line 10
    .line 11
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Lm8/l;->Q1:Landroid/content/Context;

    .line 16
    .line 17
    iget v1, p1, Lm8/i;->g:I

    .line 18
    .line 19
    iput v1, p0, Lm8/l;->T1:I

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iput-object v1, p0, Lm8/l;->c2:Lm8/i0;

    .line 23
    .line 24
    new-instance v2, Lb81/b;

    .line 25
    .line 26
    iget-object v3, p1, Lm8/i;->e:Landroid/os/Handler;

    .line 27
    .line 28
    iget-object v4, p1, Lm8/i;->f:La8/f0;

    .line 29
    .line 30
    invoke-direct {v2, v3, v4}, Lb81/b;-><init>(Landroid/os/Handler;La8/f0;)V

    .line 31
    .line 32
    .line 33
    iput-object v2, p0, Lm8/l;->S1:Lb81/b;

    .line 34
    .line 35
    iget-object v2, p0, Lm8/l;->c2:Lm8/i0;

    .line 36
    .line 37
    const/4 v3, 0x1

    .line 38
    const/4 v4, 0x0

    .line 39
    if-nez v2, :cond_0

    .line 40
    .line 41
    move v2, v3

    .line 42
    goto :goto_0

    .line 43
    :cond_0
    move v2, v4

    .line 44
    :goto_0
    iput-boolean v2, p0, Lm8/l;->R1:Z

    .line 45
    .line 46
    new-instance v2, Lm8/y;

    .line 47
    .line 48
    iget-wide v5, p1, Lm8/i;->d:J

    .line 49
    .line 50
    invoke-direct {v2, v0, p0, v5, v6}, Lm8/y;-><init>(Landroid/content/Context;Lm8/l;J)V

    .line 51
    .line 52
    .line 53
    iput-object v2, p0, Lm8/l;->V1:Lm8/y;

    .line 54
    .line 55
    new-instance p1, Li9/a;

    .line 56
    .line 57
    invoke-direct {p1}, Li9/a;-><init>()V

    .line 58
    .line 59
    .line 60
    iput-object p1, p0, Lm8/l;->W1:Li9/a;

    .line 61
    .line 62
    const-string p1, "NVIDIA"

    .line 63
    .line 64
    sget-object v0, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 65
    .line 66
    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    iput-boolean p1, p0, Lm8/l;->U1:Z

    .line 71
    .line 72
    sget-object p1, Lw7/q;->c:Lw7/q;

    .line 73
    .line 74
    iput-object p1, p0, Lm8/l;->i2:Lw7/q;

    .line 75
    .line 76
    iput v3, p0, Lm8/l;->k2:I

    .line 77
    .line 78
    iput v4, p0, Lm8/l;->l2:I

    .line 79
    .line 80
    sget-object p1, Lt7/a1;->d:Lt7/a1;

    .line 81
    .line 82
    iput-object p1, p0, Lm8/l;->v2:Lt7/a1;

    .line 83
    .line 84
    iput v4, p0, Lm8/l;->z2:I

    .line 85
    .line 86
    iput-object v1, p0, Lm8/l;->w2:Lt7/a1;

    .line 87
    .line 88
    const/16 p1, -0x3e8

    .line 89
    .line 90
    iput p1, p0, Lm8/l;->x2:I

    .line 91
    .line 92
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 93
    .line 94
    .line 95
    .line 96
    .line 97
    iput-wide v2, p0, Lm8/l;->C2:J

    .line 98
    .line 99
    iput-wide v2, p0, Lm8/l;->D2:J

    .line 100
    .line 101
    new-instance p1, Ljava/util/PriorityQueue;

    .line 102
    .line 103
    invoke-direct {p1}, Ljava/util/PriorityQueue;-><init>()V

    .line 104
    .line 105
    .line 106
    iput-object p1, p0, Lm8/l;->Y1:Ljava/util/PriorityQueue;

    .line 107
    .line 108
    iput-wide v2, p0, Lm8/l;->X1:J

    .line 109
    .line 110
    iput-object v1, p0, Lm8/l;->q2:La8/q1;

    .line 111
    .line 112
    return-void
.end method

.method public static A0(Lf8/p;Lt7/o;)I
    .locals 11

    .line 1
    iget v0, p1, Lt7/o;->u:I

    .line 2
    .line 3
    iget v1, p1, Lt7/o;->v:I

    .line 4
    .line 5
    const/4 v2, -0x1

    .line 6
    if-eq v0, v2, :cond_d

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    goto/16 :goto_4

    .line 11
    .line 12
    :cond_0
    iget-object v3, p1, Lt7/o;->n:Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const-string v4, "video/dolby-vision"

    .line 18
    .line 19
    invoke-virtual {v4, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    const-string v5, "video/avc"

    .line 24
    .line 25
    const-string v6, "video/av01"

    .line 26
    .line 27
    const/4 v7, 0x1

    .line 28
    const-string v8, "video/hevc"

    .line 29
    .line 30
    const/4 v9, 0x2

    .line 31
    if-eqz v4, :cond_4

    .line 32
    .line 33
    sget-object v3, Lf8/w;->a:Ljava/util/HashMap;

    .line 34
    .line 35
    invoke-static {p1}, Lw7/c;->b(Lt7/o;)Landroid/util/Pair;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    if-eqz p1, :cond_3

    .line 40
    .line 41
    iget-object p1, p1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p1, Ljava/lang/Integer;

    .line 44
    .line 45
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    const/16 v3, 0x200

    .line 50
    .line 51
    if-eq p1, v3, :cond_2

    .line 52
    .line 53
    if-eq p1, v7, :cond_2

    .line 54
    .line 55
    if-ne p1, v9, :cond_1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_1
    const/16 v3, 0x400

    .line 59
    .line 60
    if-ne p1, v3, :cond_3

    .line 61
    .line 62
    move-object v3, v6

    .line 63
    goto :goto_1

    .line 64
    :cond_2
    :goto_0
    move-object v3, v5

    .line 65
    goto :goto_1

    .line 66
    :cond_3
    move-object v3, v8

    .line 67
    :cond_4
    :goto_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    const/4 v4, 0x4

    .line 72
    const/4 v10, 0x3

    .line 73
    sparse-switch p1, :sswitch_data_0

    .line 74
    .line 75
    .line 76
    :goto_2
    move v7, v2

    .line 77
    goto :goto_3

    .line 78
    :sswitch_0
    const-string p1, "video/x-vnd.on2.vp9"

    .line 79
    .line 80
    invoke-virtual {v3, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    if-nez p1, :cond_5

    .line 85
    .line 86
    goto :goto_2

    .line 87
    :cond_5
    const/4 v7, 0x6

    .line 88
    goto :goto_3

    .line 89
    :sswitch_1
    const-string p1, "video/x-vnd.on2.vp8"

    .line 90
    .line 91
    invoke-virtual {v3, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    if-nez p1, :cond_6

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_6
    const/4 v7, 0x5

    .line 99
    goto :goto_3

    .line 100
    :sswitch_2
    invoke-virtual {v3, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    if-nez p1, :cond_7

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_7
    move v7, v4

    .line 108
    goto :goto_3

    .line 109
    :sswitch_3
    const-string p1, "video/mp4v-es"

    .line 110
    .line 111
    invoke-virtual {v3, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result p1

    .line 115
    if-nez p1, :cond_8

    .line 116
    .line 117
    goto :goto_2

    .line 118
    :cond_8
    move v7, v10

    .line 119
    goto :goto_3

    .line 120
    :sswitch_4
    invoke-virtual {v3, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result p1

    .line 124
    if-nez p1, :cond_9

    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_9
    move v7, v9

    .line 128
    goto :goto_3

    .line 129
    :sswitch_5
    invoke-virtual {v3, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    if-nez p1, :cond_b

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :sswitch_6
    const-string p1, "video/3gpp"

    .line 137
    .line 138
    invoke-virtual {v3, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result p1

    .line 142
    if-nez p1, :cond_a

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_a
    const/4 v7, 0x0

    .line 146
    :cond_b
    :goto_3
    packed-switch v7, :pswitch_data_0

    .line 147
    .line 148
    .line 149
    goto :goto_4

    .line 150
    :pswitch_0
    mul-int/2addr v0, v1

    .line 151
    mul-int/2addr v0, v10

    .line 152
    div-int/lit8 v0, v0, 0x8

    .line 153
    .line 154
    return v0

    .line 155
    :pswitch_1
    sget-object p1, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 156
    .line 157
    const-string v3, "BRAVIA 4K 2015"

    .line 158
    .line 159
    invoke-virtual {v3, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v3

    .line 163
    if-nez v3, :cond_d

    .line 164
    .line 165
    const-string v3, "Amazon"

    .line 166
    .line 167
    sget-object v5, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 168
    .line 169
    invoke-virtual {v3, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v3

    .line 173
    if-eqz v3, :cond_c

    .line 174
    .line 175
    const-string v3, "KFSOWI"

    .line 176
    .line 177
    invoke-virtual {v3, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v3

    .line 181
    if-nez v3, :cond_d

    .line 182
    .line 183
    const-string v3, "AFTS"

    .line 184
    .line 185
    invoke-virtual {v3, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result p1

    .line 189
    if-eqz p1, :cond_c

    .line 190
    .line 191
    iget-boolean p0, p0, Lf8/p;->f:Z

    .line 192
    .line 193
    if-eqz p0, :cond_c

    .line 194
    .line 195
    goto :goto_4

    .line 196
    :cond_c
    const/16 p0, 0x10

    .line 197
    .line 198
    invoke-static {v0, p0}, Lw7/w;->e(II)I

    .line 199
    .line 200
    .line 201
    move-result p1

    .line 202
    invoke-static {v1, p0}, Lw7/w;->e(II)I

    .line 203
    .line 204
    .line 205
    move-result p0

    .line 206
    mul-int/2addr p0, p1

    .line 207
    mul-int/lit16 p0, p0, 0x300

    .line 208
    .line 209
    div-int/2addr p0, v4

    .line 210
    return p0

    .line 211
    :pswitch_2
    mul-int/2addr v0, v1

    .line 212
    mul-int/2addr v0, v10

    .line 213
    div-int/2addr v0, v4

    .line 214
    const/high16 p0, 0x200000

    .line 215
    .line 216
    invoke-static {p0, v0}, Ljava/lang/Math;->max(II)I

    .line 217
    .line 218
    .line 219
    move-result p0

    .line 220
    return p0

    .line 221
    :pswitch_3
    mul-int/2addr v0, v1

    .line 222
    mul-int/2addr v0, v10

    .line 223
    div-int/2addr v0, v4

    .line 224
    return v0

    .line 225
    :cond_d
    :goto_4
    return v2

    .line 226
    nop

    .line 227
    :sswitch_data_0
    .sparse-switch
        -0x63306f58 -> :sswitch_6
        -0x631b55f6 -> :sswitch_5
        -0x63185e82 -> :sswitch_4
        0x46cdc642 -> :sswitch_3
        0x4f62373a -> :sswitch_2
        0x5f50bed8 -> :sswitch_1
        0x5f50bed9 -> :sswitch_0
    .end sparse-switch

    .line 228
    .line 229
    .line 230
    .line 231
    .line 232
    .line 233
    .line 234
    .line 235
    .line 236
    .line 237
    .line 238
    .line 239
    .line 240
    .line 241
    .line 242
    .line 243
    .line 244
    .line 245
    .line 246
    .line 247
    .line 248
    .line 249
    .line 250
    .line 251
    .line 252
    .line 253
    .line 254
    .line 255
    .line 256
    .line 257
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_3
        :pswitch_1
        :pswitch_3
        :pswitch_0
    .end packed-switch
.end method

.method public static B0(Landroid/content/Context;Lf8/k;Lt7/o;ZZ)Ljava/util/List;
    .locals 2

    .line 1
    iget-object v0, p2, Lt7/o;->n:Ljava/lang/String;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lhr/x0;->h:Lhr/x0;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    const-string v1, "video/dolby-vision"

    .line 9
    .line 10
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_2

    .line 15
    .line 16
    invoke-static {p0}, Ljp/t0;->b(Landroid/content/Context;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-nez p0, :cond_2

    .line 21
    .line 22
    invoke-static {p2}, Lf8/w;->b(Lt7/o;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    if-nez p0, :cond_1

    .line 27
    .line 28
    sget-object p0, Lhr/x0;->h:Lhr/x0;

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_1
    invoke-virtual {p1, p0, p3, p4}, Lf8/k;->a(Ljava/lang/String;ZZ)Ljava/util/List;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    :goto_0
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 36
    .line 37
    .line 38
    move-result v0

    .line 39
    if-nez v0, :cond_2

    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_2
    invoke-static {p1, p2, p3, p4}, Lf8/w;->f(Lf8/k;Lt7/o;ZZ)Lhr/x0;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method

.method public static C0(Lf8/p;Lt7/o;)I
    .locals 4

    .line 1
    iget v0, p1, Lt7/o;->o:I

    .line 2
    .line 3
    iget-object v1, p1, Lt7/o;->q:Ljava/util/List;

    .line 4
    .line 5
    const/4 v2, -0x1

    .line 6
    if-eq v0, v2, :cond_1

    .line 7
    .line 8
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    const/4 v0, 0x0

    .line 13
    move v2, v0

    .line 14
    :goto_0
    if-ge v0, p0, :cond_0

    .line 15
    .line 16
    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    check-cast v3, [B

    .line 21
    .line 22
    array-length v3, v3

    .line 23
    add-int/2addr v2, v3

    .line 24
    add-int/lit8 v0, v0, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    iget p0, p1, Lt7/o;->o:I

    .line 28
    .line 29
    add-int/2addr p0, v2

    .line 30
    return p0

    .line 31
    :cond_1
    invoke-static {p0, p1}, Lm8/l;->A0(Lf8/p;Lt7/o;)I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    return p0
.end method

.method public static z0(Ljava/lang/String;)Z
    .locals 5

    .line 1
    const-string v0, "OMX.google"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    const/4 v0, 0x0

    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    return v0

    .line 11
    :cond_0
    const-class p0, Lm8/l;

    .line 12
    .line 13
    monitor-enter p0

    .line 14
    :try_start_0
    sget-boolean v1, Lm8/l;->H2:Z

    .line 15
    .line 16
    if-nez v1, :cond_a

    .line 17
    .line 18
    sget-object v1, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    const/4 v3, 0x1

    .line 28
    const/4 v4, -0x1

    .line 29
    sparse-switch v2, :sswitch_data_0

    .line 30
    .line 31
    .line 32
    goto/16 :goto_0

    .line 33
    .line 34
    :sswitch_0
    const-string v2, "AFTEUFF014"

    .line 35
    .line 36
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-nez v1, :cond_1

    .line 41
    .line 42
    goto/16 :goto_0

    .line 43
    .line 44
    :cond_1
    const/16 v4, 0x8

    .line 45
    .line 46
    goto/16 :goto_0

    .line 47
    .line 48
    :sswitch_1
    const-string v2, "AFTSO001"

    .line 49
    .line 50
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_2

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_2
    const/4 v4, 0x7

    .line 58
    goto :goto_0

    .line 59
    :sswitch_2
    const-string v2, "AFTEU014"

    .line 60
    .line 61
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_3

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_3
    const/4 v4, 0x6

    .line 69
    goto :goto_0

    .line 70
    :sswitch_3
    const-string v2, "AFTEU011"

    .line 71
    .line 72
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_4

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_4
    const/4 v4, 0x5

    .line 80
    goto :goto_0

    .line 81
    :sswitch_4
    const-string v2, "AFTR"

    .line 82
    .line 83
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_5

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_5
    const/4 v4, 0x4

    .line 91
    goto :goto_0

    .line 92
    :sswitch_5
    const-string v2, "AFTN"

    .line 93
    .line 94
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-nez v1, :cond_6

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_6
    const/4 v4, 0x3

    .line 102
    goto :goto_0

    .line 103
    :sswitch_6
    const-string v2, "AFTA"

    .line 104
    .line 105
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-nez v1, :cond_7

    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_7
    const/4 v4, 0x2

    .line 113
    goto :goto_0

    .line 114
    :sswitch_7
    const-string v2, "AFTKMST12"

    .line 115
    .line 116
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-nez v1, :cond_8

    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_8
    move v4, v3

    .line 124
    goto :goto_0

    .line 125
    :sswitch_8
    const-string v2, "AFTJMST12"

    .line 126
    .line 127
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v1

    .line 131
    if-nez v1, :cond_9

    .line 132
    .line 133
    goto :goto_0

    .line 134
    :cond_9
    move v4, v0

    .line 135
    :goto_0
    packed-switch v4, :pswitch_data_0

    .line 136
    .line 137
    .line 138
    goto :goto_1

    .line 139
    :pswitch_0
    move v0, v3

    .line 140
    :goto_1
    :try_start_1
    sput-boolean v0, Lm8/l;->I2:Z

    .line 141
    .line 142
    sput-boolean v3, Lm8/l;->H2:Z

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :catchall_0
    move-exception v0

    .line 146
    goto :goto_3

    .line 147
    :cond_a
    :goto_2
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 148
    sget-boolean p0, Lm8/l;->I2:Z

    .line 149
    .line 150
    return p0

    .line 151
    :goto_3
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 152
    throw v0

    .line 153
    :sswitch_data_0
    .sparse-switch
        -0x14d76e6c -> :sswitch_8
        -0x132295cd -> :sswitch_7
        0x1e9d52 -> :sswitch_6
        0x1e9d5f -> :sswitch_5
        0x1e9d63 -> :sswitch_4
        0x6a6b6031 -> :sswitch_3
        0x6a6b6034 -> :sswitch_2
        0x6b2deee6 -> :sswitch_1
        0x7e53ab34 -> :sswitch_0
    .end sparse-switch

    .line 154
    .line 155
    .line 156
    .line 157
    .line 158
    .line 159
    .line 160
    .line 161
    .line 162
    .line 163
    .line 164
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final A(FF)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Lf8/s;->A(FF)V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Lm8/l;->c2:Lm8/i0;

    .line 5
    .line 6
    if-eqz p2, :cond_0

    .line 7
    .line 8
    invoke-interface {p2, p1}, Lm8/i0;->q(F)V

    .line 9
    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object p0, p0, Lm8/l;->V1:Lm8/y;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lm8/y;->i(F)V

    .line 15
    .line 16
    .line 17
    :goto_0
    return-void
.end method

.method public final D0(Lf8/p;)Landroid/view/Surface;
    .locals 5

    .line 1
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Lm8/i0;->l()Landroid/view/Surface;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    iget-object v0, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    return-object v0

    .line 15
    :cond_1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 16
    .line 17
    const/16 v1, 0x23

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    if-lt v0, v1, :cond_2

    .line 21
    .line 22
    iget-boolean v0, p1, Lf8/p;->h:Z

    .line 23
    .line 24
    if-eqz v0, :cond_2

    .line 25
    .line 26
    return-object v2

    .line 27
    :cond_2
    invoke-virtual {p0, p1}, Lm8/l;->M0(Lf8/p;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 32
    .line 33
    .line 34
    iget-object v0, p0, Lm8/l;->h2:Lm8/n;

    .line 35
    .line 36
    if-eqz v0, :cond_3

    .line 37
    .line 38
    iget-boolean v1, v0, Lm8/n;->d:Z

    .line 39
    .line 40
    iget-boolean v3, p1, Lf8/p;->f:Z

    .line 41
    .line 42
    if-eq v1, v3, :cond_3

    .line 43
    .line 44
    if-eqz v0, :cond_3

    .line 45
    .line 46
    invoke-virtual {v0}, Lm8/n;->release()V

    .line 47
    .line 48
    .line 49
    iput-object v2, p0, Lm8/l;->h2:Lm8/n;

    .line 50
    .line 51
    :cond_3
    iget-object v0, p0, Lm8/l;->h2:Lm8/n;

    .line 52
    .line 53
    if-nez v0, :cond_b

    .line 54
    .line 55
    iget-boolean p1, p1, Lf8/p;->f:Z

    .line 56
    .line 57
    const/4 v0, 0x1

    .line 58
    const/4 v1, 0x0

    .line 59
    if-eqz p1, :cond_5

    .line 60
    .line 61
    invoke-static {}, Lm8/n;->h()Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-eqz v2, :cond_4

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_4
    move v2, v1

    .line 69
    goto :goto_1

    .line 70
    :cond_5
    sget v2, Lm8/n;->g:I

    .line 71
    .line 72
    :goto_0
    move v2, v0

    .line 73
    :goto_1
    invoke-static {v2}, Lw7/a;->j(Z)V

    .line 74
    .line 75
    .line 76
    new-instance v2, Lm8/m;

    .line 77
    .line 78
    const-string v3, "ExoPlayer:PlaceholderSurface"

    .line 79
    .line 80
    invoke-direct {v2, v3}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    if-eqz p1, :cond_6

    .line 84
    .line 85
    sget p1, Lm8/n;->g:I

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_6
    move p1, v1

    .line 89
    :goto_2
    invoke-virtual {v2}, Ljava/lang/Thread;->start()V

    .line 90
    .line 91
    .line 92
    new-instance v3, Landroid/os/Handler;

    .line 93
    .line 94
    invoke-virtual {v2}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    invoke-direct {v3, v4, v2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;Landroid/os/Handler$Callback;)V

    .line 99
    .line 100
    .line 101
    iput-object v3, v2, Lm8/m;->e:Landroid/os/Handler;

    .line 102
    .line 103
    new-instance v4, Lw7/g;

    .line 104
    .line 105
    invoke-direct {v4, v3}, Lw7/g;-><init>(Landroid/os/Handler;)V

    .line 106
    .line 107
    .line 108
    iput-object v4, v2, Lm8/m;->d:Lw7/g;

    .line 109
    .line 110
    monitor-enter v2

    .line 111
    :try_start_0
    iget-object v3, v2, Lm8/m;->e:Landroid/os/Handler;

    .line 112
    .line 113
    invoke-virtual {v3, v0, p1, v1}, Landroid/os/Handler;->obtainMessage(III)Landroid/os/Message;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    invoke-virtual {p1}, Landroid/os/Message;->sendToTarget()V

    .line 118
    .line 119
    .line 120
    :goto_3
    iget-object p1, v2, Lm8/m;->h:Lm8/n;

    .line 121
    .line 122
    if-nez p1, :cond_7

    .line 123
    .line 124
    iget-object p1, v2, Lm8/m;->g:Ljava/lang/RuntimeException;

    .line 125
    .line 126
    if-nez p1, :cond_7

    .line 127
    .line 128
    iget-object p1, v2, Lm8/m;->f:Ljava/lang/Error;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 129
    .line 130
    if-nez p1, :cond_7

    .line 131
    .line 132
    :try_start_1
    invoke-virtual {v2}, Ljava/lang/Object;->wait()V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 133
    .line 134
    .line 135
    goto :goto_3

    .line 136
    :catchall_0
    move-exception p0

    .line 137
    goto :goto_4

    .line 138
    :catch_0
    move v1, v0

    .line 139
    goto :goto_3

    .line 140
    :cond_7
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 141
    if-eqz v1, :cond_8

    .line 142
    .line 143
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    invoke-virtual {p1}, Ljava/lang/Thread;->interrupt()V

    .line 148
    .line 149
    .line 150
    :cond_8
    iget-object p1, v2, Lm8/m;->g:Ljava/lang/RuntimeException;

    .line 151
    .line 152
    if-nez p1, :cond_a

    .line 153
    .line 154
    iget-object p1, v2, Lm8/m;->f:Ljava/lang/Error;

    .line 155
    .line 156
    if-nez p1, :cond_9

    .line 157
    .line 158
    iget-object p1, v2, Lm8/m;->h:Lm8/n;

    .line 159
    .line 160
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 161
    .line 162
    .line 163
    iput-object p1, p0, Lm8/l;->h2:Lm8/n;

    .line 164
    .line 165
    goto :goto_5

    .line 166
    :cond_9
    throw p1

    .line 167
    :cond_a
    throw p1

    .line 168
    :goto_4
    :try_start_3
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 169
    throw p0

    .line 170
    :cond_b
    :goto_5
    iget-object p0, p0, Lm8/l;->h2:Lm8/n;

    .line 171
    .line 172
    return-object p0
.end method

.method public final E(Lf8/p;Lt7/o;Lt7/o;)La8/h;
    .locals 8

    .line 1
    invoke-virtual {p1, p2, p3}, Lf8/p;->b(Lt7/o;Lt7/o;)La8/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget v1, v0, La8/h;->e:I

    .line 6
    .line 7
    iget-object p0, p0, Lm8/l;->Z1:Lm8/j;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    iget v2, p3, Lt7/o;->u:I

    .line 13
    .line 14
    iget v3, p0, Lm8/j;->a:I

    .line 15
    .line 16
    if-gt v2, v3, :cond_0

    .line 17
    .line 18
    iget v2, p3, Lt7/o;->v:I

    .line 19
    .line 20
    iget v3, p0, Lm8/j;->b:I

    .line 21
    .line 22
    if-le v2, v3, :cond_1

    .line 23
    .line 24
    :cond_0
    or-int/lit16 v1, v1, 0x100

    .line 25
    .line 26
    :cond_1
    invoke-static {p1, p3}, Lm8/l;->C0(Lf8/p;Lt7/o;)I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    iget p0, p0, Lm8/j;->c:I

    .line 31
    .line 32
    if-le v2, p0, :cond_2

    .line 33
    .line 34
    or-int/lit8 v1, v1, 0x40

    .line 35
    .line 36
    :cond_2
    move v7, v1

    .line 37
    new-instance v2, La8/h;

    .line 38
    .line 39
    iget-object v3, p1, Lf8/p;->a:Ljava/lang/String;

    .line 40
    .line 41
    if-eqz v7, :cond_3

    .line 42
    .line 43
    const/4 p0, 0x0

    .line 44
    :goto_0
    move v6, p0

    .line 45
    move-object v4, p2

    .line 46
    move-object v5, p3

    .line 47
    goto :goto_1

    .line 48
    :cond_3
    iget p0, v0, La8/h;->d:I

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :goto_1
    invoke-direct/range {v2 .. v7}, La8/h;-><init>(Ljava/lang/String;Lt7/o;Lt7/o;II)V

    .line 52
    .line 53
    .line 54
    return-object v2
.end method

.method public final E0(Lf8/p;)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 2
    .line 3
    if-nez v0, :cond_3

    .line 4
    .line 5
    iget-object v0, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/view/Surface;->isValid()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_3

    .line 14
    .line 15
    :cond_0
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 16
    .line 17
    const/16 v1, 0x23

    .line 18
    .line 19
    if-lt v0, v1, :cond_1

    .line 20
    .line 21
    iget-boolean v0, p1, Lf8/p;->h:Z

    .line 22
    .line 23
    if-eqz v0, :cond_1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    invoke-virtual {p0, p1}, Lm8/l;->M0(Lf8/p;)Z

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-eqz p0, :cond_2

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_2
    const/4 p0, 0x0

    .line 34
    return p0

    .line 35
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 36
    return p0
.end method

.method public final F(Ljava/lang/IllegalStateException;Lf8/p;)Lf8/o;
    .locals 1

    .line 1
    new-instance v0, Lm8/f;

    .line 2
    .line 3
    iget-object p0, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 4
    .line 5
    invoke-direct {v0, p1, p2}, Lf8/o;-><init>(Ljava/lang/IllegalStateException;Lf8/p;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p0}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 9
    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/view/Surface;->isValid()Z

    .line 14
    .line 15
    .line 16
    :cond_0
    return-object v0
.end method

.method public final F0(Lz7/e;)Z
    .locals 6

    .line 1
    invoke-virtual {p0}, La8/f;->l()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-nez v0, :cond_3

    .line 7
    .line 8
    const/high16 v0, 0x20000000

    .line 9
    .line 10
    invoke-virtual {p1, v0}, Lkq/d;->c(I)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    iget-wide v2, p0, Lm8/l;->D2:J

    .line 18
    .line 19
    const-wide v4, -0x7fffffffffffffffL    # -4.9E-324

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    cmp-long v0, v2, v4

    .line 25
    .line 26
    if-nez v0, :cond_1

    .line 27
    .line 28
    return v1

    .line 29
    :cond_1
    iget-wide v4, p1, Lz7/e;->j:J

    .line 30
    .line 31
    iget-object p0, p0, Lf8/s;->I1:Lf8/r;

    .line 32
    .line 33
    iget-wide p0, p0, Lf8/r;->c:J

    .line 34
    .line 35
    sub-long/2addr v4, p0

    .line 36
    sub-long/2addr v2, v4

    .line 37
    const-wide/32 p0, 0x186a0

    .line 38
    .line 39
    .line 40
    cmp-long p0, v2, p0

    .line 41
    .line 42
    if-gtz p0, :cond_2

    .line 43
    .line 44
    return v1

    .line 45
    :cond_2
    const/4 p0, 0x0

    .line 46
    return p0

    .line 47
    :cond_3
    :goto_0
    return v1
.end method

.method public final G0()V
    .locals 8

    .line 1
    iget v0, p0, Lm8/l;->n2:I

    .line 2
    .line 3
    if-lez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, La8/f;->j:Lw7/r;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    iget-wide v2, p0, Lm8/l;->m2:J

    .line 15
    .line 16
    sub-long v2, v0, v2

    .line 17
    .line 18
    iget v4, p0, Lm8/l;->n2:I

    .line 19
    .line 20
    iget-object v5, p0, Lm8/l;->S1:Lb81/b;

    .line 21
    .line 22
    iget-object v6, v5, Lb81/b;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v6, Landroid/os/Handler;

    .line 25
    .line 26
    if-eqz v6, :cond_0

    .line 27
    .line 28
    new-instance v7, Lm8/e0;

    .line 29
    .line 30
    invoke-direct {v7, v5, v4, v2, v3}, Lm8/e0;-><init>(Lb81/b;IJ)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v6, v7}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 34
    .line 35
    .line 36
    :cond_0
    const/4 v2, 0x0

    .line 37
    iput v2, p0, Lm8/l;->n2:I

    .line 38
    .line 39
    iput-wide v0, p0, Lm8/l;->m2:J

    .line 40
    .line 41
    :cond_1
    return-void
.end method

.method public final H0()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lm8/l;->y2:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 6
    .line 7
    iget-object v1, p0, Lf8/s;->O:Lf8/m;

    .line 8
    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    new-instance v2, Lm8/k;

    .line 13
    .line 14
    invoke-direct {v2, p0, v1}, Lm8/k;-><init>(Lm8/l;Lf8/m;)V

    .line 15
    .line 16
    .line 17
    iput-object v2, p0, Lm8/l;->A2:Lm8/k;

    .line 18
    .line 19
    const/16 p0, 0x21

    .line 20
    .line 21
    if-lt v0, p0, :cond_1

    .line 22
    .line 23
    new-instance p0, Landroid/os/Bundle;

    .line 24
    .line 25
    invoke-direct {p0}, Landroid/os/Bundle;-><init>()V

    .line 26
    .line 27
    .line 28
    const-string v0, "tunnel-peek"

    .line 29
    .line 30
    const/4 v2, 0x1

    .line 31
    invoke-virtual {p0, v0, v2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 32
    .line 33
    .line 34
    invoke-interface {v1, p0}, Lf8/m;->a(Landroid/os/Bundle;)V

    .line 35
    .line 36
    .line 37
    :cond_1
    :goto_0
    return-void
.end method

.method public final I0(J)V
    .locals 7

    .line 1
    invoke-virtual {p0, p1, p2}, Lf8/s;->y0(J)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lm8/l;->v2:Lt7/a1;

    .line 5
    .line 6
    sget-object v1, Lt7/a1;->d:Lt7/a1;

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Lt7/a1;->equals(Ljava/lang/Object;)Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    iget-object v2, p0, Lm8/l;->S1:Lb81/b;

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    iget-object v1, p0, Lm8/l;->w2:Lt7/a1;

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Lt7/a1;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-nez v1, :cond_0

    .line 23
    .line 24
    iput-object v0, p0, Lm8/l;->w2:Lt7/a1;

    .line 25
    .line 26
    invoke-virtual {v2, v0}, Lb81/b;->A(Lt7/a1;)V

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object v0, p0, Lf8/s;->H1:La8/g;

    .line 30
    .line 31
    iget v1, v0, La8/g;->e:I

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    add-int/2addr v1, v3

    .line 35
    iput v1, v0, La8/g;->e:I

    .line 36
    .line 37
    iget-object v0, p0, Lm8/l;->V1:Lm8/y;

    .line 38
    .line 39
    iget v1, v0, Lm8/y;->e:I

    .line 40
    .line 41
    const/4 v4, 0x3

    .line 42
    if-eq v1, v4, :cond_1

    .line 43
    .line 44
    move v1, v3

    .line 45
    goto :goto_0

    .line 46
    :cond_1
    const/4 v1, 0x0

    .line 47
    :goto_0
    iput v4, v0, Lm8/y;->e:I

    .line 48
    .line 49
    iget-object v4, v0, Lm8/y;->l:Lw7/r;

    .line 50
    .line 51
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 55
    .line 56
    .line 57
    move-result-wide v4

    .line 58
    invoke-static {v4, v5}, Lw7/w;->D(J)J

    .line 59
    .line 60
    .line 61
    move-result-wide v4

    .line 62
    iput-wide v4, v0, Lm8/y;->g:J

    .line 63
    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    iget-object v0, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 67
    .line 68
    if-eqz v0, :cond_3

    .line 69
    .line 70
    iget-object v1, v2, Lb81/b;->e:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v1, Landroid/os/Handler;

    .line 73
    .line 74
    if-eqz v1, :cond_2

    .line 75
    .line 76
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 77
    .line 78
    .line 79
    move-result-wide v4

    .line 80
    new-instance v6, Lms/o;

    .line 81
    .line 82
    invoke-direct {v6, v2, v0, v4, v5}, Lms/o;-><init>(Lb81/b;Ljava/lang/Object;J)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v1, v6}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 86
    .line 87
    .line 88
    :cond_2
    iput-boolean v3, p0, Lm8/l;->j2:Z

    .line 89
    .line 90
    :cond_3
    invoke-virtual {p0, p1, p2}, Lm8/l;->d0(J)V

    .line 91
    .line 92
    .line 93
    return-void
.end method

.method public final J0(Lf8/m;IJ)V
    .locals 3

    .line 1
    const-string v0, "releaseOutputBuffer"

    .line 2
    .line 3
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p2, p3, p4}, Lf8/m;->p(IJ)V

    .line 7
    .line 8
    .line 9
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Lf8/s;->H1:La8/g;

    .line 13
    .line 14
    iget p2, p1, La8/g;->e:I

    .line 15
    .line 16
    const/4 p3, 0x1

    .line 17
    add-int/2addr p2, p3

    .line 18
    iput p2, p1, La8/g;->e:I

    .line 19
    .line 20
    const/4 p1, 0x0

    .line 21
    iput p1, p0, Lm8/l;->o2:I

    .line 22
    .line 23
    iget-object p2, p0, Lm8/l;->c2:Lm8/i0;

    .line 24
    .line 25
    if-nez p2, :cond_3

    .line 26
    .line 27
    iget-object p2, p0, Lm8/l;->v2:Lt7/a1;

    .line 28
    .line 29
    sget-object p4, Lt7/a1;->d:Lt7/a1;

    .line 30
    .line 31
    invoke-virtual {p2, p4}, Lt7/a1;->equals(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result p4

    .line 35
    iget-object v0, p0, Lm8/l;->S1:Lb81/b;

    .line 36
    .line 37
    if-nez p4, :cond_0

    .line 38
    .line 39
    iget-object p4, p0, Lm8/l;->w2:Lt7/a1;

    .line 40
    .line 41
    invoke-virtual {p2, p4}, Lt7/a1;->equals(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p4

    .line 45
    if-nez p4, :cond_0

    .line 46
    .line 47
    iput-object p2, p0, Lm8/l;->w2:Lt7/a1;

    .line 48
    .line 49
    invoke-virtual {v0, p2}, Lb81/b;->A(Lt7/a1;)V

    .line 50
    .line 51
    .line 52
    :cond_0
    iget-object p2, p0, Lm8/l;->V1:Lm8/y;

    .line 53
    .line 54
    iget p4, p2, Lm8/y;->e:I

    .line 55
    .line 56
    const/4 v1, 0x3

    .line 57
    if-eq p4, v1, :cond_1

    .line 58
    .line 59
    move p1, p3

    .line 60
    :cond_1
    iput v1, p2, Lm8/y;->e:I

    .line 61
    .line 62
    iget-object p4, p2, Lm8/y;->l:Lw7/r;

    .line 63
    .line 64
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 68
    .line 69
    .line 70
    move-result-wide v1

    .line 71
    invoke-static {v1, v2}, Lw7/w;->D(J)J

    .line 72
    .line 73
    .line 74
    move-result-wide v1

    .line 75
    iput-wide v1, p2, Lm8/y;->g:J

    .line 76
    .line 77
    if-eqz p1, :cond_3

    .line 78
    .line 79
    iget-object p1, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 80
    .line 81
    if-eqz p1, :cond_3

    .line 82
    .line 83
    iget-object p2, v0, Lb81/b;->e:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast p2, Landroid/os/Handler;

    .line 86
    .line 87
    if-eqz p2, :cond_2

    .line 88
    .line 89
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 90
    .line 91
    .line 92
    move-result-wide v1

    .line 93
    new-instance p4, Lms/o;

    .line 94
    .line 95
    invoke-direct {p4, v0, p1, v1, v2}, Lms/o;-><init>(Lb81/b;Ljava/lang/Object;J)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {p2, p4}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 99
    .line 100
    .line 101
    :cond_2
    iput-boolean p3, p0, Lm8/l;->j2:Z

    .line 102
    .line 103
    :cond_3
    return-void
.end method

.method public final K0(Ljava/lang/Object;)V
    .locals 8

    .line 1
    instance-of v0, p1, Landroid/view/Surface;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    check-cast p1, Landroid/view/Surface;

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move-object p1, v1

    .line 10
    :goto_0
    iget-object v0, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 11
    .line 12
    iget-object v2, p0, Lm8/l;->S1:Lb81/b;

    .line 13
    .line 14
    if-eq v0, p1, :cond_a

    .line 15
    .line 16
    iput-object p1, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 17
    .line 18
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 19
    .line 20
    iget-object v3, p0, Lm8/l;->V1:Lm8/y;

    .line 21
    .line 22
    if-nez v0, :cond_1

    .line 23
    .line 24
    invoke-virtual {v3, p1}, Lm8/y;->h(Landroid/view/Surface;)V

    .line 25
    .line 26
    .line 27
    :cond_1
    const/4 v0, 0x0

    .line 28
    iput-boolean v0, p0, Lm8/l;->j2:Z

    .line 29
    .line 30
    iget v0, p0, La8/f;->k:I

    .line 31
    .line 32
    iget-object v4, p0, Lf8/s;->O:Lf8/m;

    .line 33
    .line 34
    if-eqz v4, :cond_5

    .line 35
    .line 36
    iget-object v5, p0, Lm8/l;->c2:Lm8/i0;

    .line 37
    .line 38
    if-nez v5, :cond_5

    .line 39
    .line 40
    iget-object v5, p0, Lf8/s;->V:Lf8/p;

    .line 41
    .line 42
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, v5}, Lm8/l;->E0(Lf8/p;)Z

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    sget v7, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 50
    .line 51
    if-eqz v6, :cond_4

    .line 52
    .line 53
    iget-boolean v6, p0, Lm8/l;->a2:Z

    .line 54
    .line 55
    if-nez v6, :cond_4

    .line 56
    .line 57
    invoke-virtual {p0, v5}, Lm8/l;->D0(Lf8/p;)Landroid/view/Surface;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    if-eqz v5, :cond_2

    .line 62
    .line 63
    invoke-interface {v4, v5}, Lf8/m;->l(Landroid/view/Surface;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    const/16 v5, 0x23

    .line 68
    .line 69
    if-lt v7, v5, :cond_3

    .line 70
    .line 71
    invoke-interface {v4}, Lf8/m;->h()V

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 76
    .line 77
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 78
    .line 79
    .line 80
    throw p0

    .line 81
    :cond_4
    invoke-virtual {p0}, Lf8/s;->j0()V

    .line 82
    .line 83
    .line 84
    invoke-virtual {p0}, Lf8/s;->U()V

    .line 85
    .line 86
    .line 87
    :cond_5
    :goto_1
    if-eqz p1, :cond_6

    .line 88
    .line 89
    iget-object p1, p0, Lm8/l;->w2:Lt7/a1;

    .line 90
    .line 91
    if-eqz p1, :cond_7

    .line 92
    .line 93
    invoke-virtual {v2, p1}, Lb81/b;->A(Lt7/a1;)V

    .line 94
    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_6
    iput-object v1, p0, Lm8/l;->w2:Lt7/a1;

    .line 98
    .line 99
    iget-object p1, p0, Lm8/l;->c2:Lm8/i0;

    .line 100
    .line 101
    if-eqz p1, :cond_7

    .line 102
    .line 103
    invoke-interface {p1}, Lm8/i0;->r()V

    .line 104
    .line 105
    .line 106
    :cond_7
    :goto_2
    const/4 p1, 0x2

    .line 107
    if-ne v0, p1, :cond_9

    .line 108
    .line 109
    iget-object p1, p0, Lm8/l;->c2:Lm8/i0;

    .line 110
    .line 111
    const/4 v0, 0x1

    .line 112
    if-eqz p1, :cond_8

    .line 113
    .line 114
    invoke-interface {p1, v0}, Lm8/i0;->w(Z)V

    .line 115
    .line 116
    .line 117
    goto :goto_3

    .line 118
    :cond_8
    invoke-virtual {v3, v0}, Lm8/y;->c(Z)V

    .line 119
    .line 120
    .line 121
    :cond_9
    :goto_3
    invoke-virtual {p0}, Lm8/l;->H0()V

    .line 122
    .line 123
    .line 124
    return-void

    .line 125
    :cond_a
    if-eqz p1, :cond_c

    .line 126
    .line 127
    iget-object p1, p0, Lm8/l;->w2:Lt7/a1;

    .line 128
    .line 129
    if-eqz p1, :cond_b

    .line 130
    .line 131
    invoke-virtual {v2, p1}, Lb81/b;->A(Lt7/a1;)V

    .line 132
    .line 133
    .line 134
    :cond_b
    iget-object p1, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 135
    .line 136
    if-eqz p1, :cond_c

    .line 137
    .line 138
    iget-boolean p0, p0, Lm8/l;->j2:Z

    .line 139
    .line 140
    if-eqz p0, :cond_c

    .line 141
    .line 142
    iget-object p0, v2, Lb81/b;->e:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast p0, Landroid/os/Handler;

    .line 145
    .line 146
    if-eqz p0, :cond_c

    .line 147
    .line 148
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 149
    .line 150
    .line 151
    move-result-wide v0

    .line 152
    new-instance v3, Lms/o;

    .line 153
    .line 154
    invoke-direct {v3, v2, p1, v0, v1}, Lms/o;-><init>(Lb81/b;Ljava/lang/Object;J)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {p0, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 158
    .line 159
    .line 160
    :cond_c
    return-void
.end method

.method public final L0(JJZZ)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean v0, p0, Lm8/l;->R1:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-wide v0, p0, Lm8/l;->C2:J

    .line 10
    .line 11
    neg-long v0, v0

    .line 12
    sub-long/2addr p3, v0

    .line 13
    :cond_0
    const-wide/32 v0, -0x7a120

    .line 14
    .line 15
    .line 16
    cmp-long p1, p1, v0

    .line 17
    .line 18
    const/4 p2, 0x0

    .line 19
    if-gez p1, :cond_5

    .line 20
    .line 21
    if-nez p5, :cond_5

    .line 22
    .line 23
    iget-object p1, p0, La8/f;->l:Lh8/y0;

    .line 24
    .line 25
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    iget-wide v0, p0, La8/f;->n:J

    .line 29
    .line 30
    sub-long/2addr p3, v0

    .line 31
    invoke-interface {p1, p3, p4}, Lh8/y0;->l(J)I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    if-nez p1, :cond_1

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/4 p3, 0x1

    .line 39
    iget-object p4, p0, Lm8/l;->Y1:Ljava/util/PriorityQueue;

    .line 40
    .line 41
    if-eqz p6, :cond_2

    .line 42
    .line 43
    iget-object p5, p0, Lf8/s;->H1:La8/g;

    .line 44
    .line 45
    iget p6, p5, La8/g;->d:I

    .line 46
    .line 47
    add-int/2addr p6, p1

    .line 48
    iput p6, p5, La8/g;->d:I

    .line 49
    .line 50
    iget p1, p5, La8/g;->f:I

    .line 51
    .line 52
    iget v0, p0, Lm8/l;->p2:I

    .line 53
    .line 54
    add-int/2addr p1, v0

    .line 55
    iput p1, p5, La8/g;->f:I

    .line 56
    .line 57
    invoke-virtual {p4}, Ljava/util/PriorityQueue;->size()I

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    add-int/2addr p1, p6

    .line 62
    iput p1, p5, La8/g;->d:I

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_2
    iget-object p5, p0, Lf8/s;->H1:La8/g;

    .line 66
    .line 67
    iget p6, p5, La8/g;->j:I

    .line 68
    .line 69
    add-int/2addr p6, p3

    .line 70
    iput p6, p5, La8/g;->j:I

    .line 71
    .line 72
    invoke-virtual {p4}, Ljava/util/PriorityQueue;->size()I

    .line 73
    .line 74
    .line 75
    move-result p4

    .line 76
    add-int/2addr p4, p1

    .line 77
    iget p1, p0, Lm8/l;->p2:I

    .line 78
    .line 79
    invoke-virtual {p0, p4, p1}, Lm8/l;->O0(II)V

    .line 80
    .line 81
    .line 82
    :goto_0
    invoke-virtual {p0}, Lf8/s;->K()Z

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    if-eqz p1, :cond_3

    .line 87
    .line 88
    invoke-virtual {p0}, Lf8/s;->U()V

    .line 89
    .line 90
    .line 91
    :cond_3
    iget-object p0, p0, Lm8/l;->c2:Lm8/i0;

    .line 92
    .line 93
    if-eqz p0, :cond_4

    .line 94
    .line 95
    invoke-interface {p0, p2}, Lm8/i0;->t(Z)V

    .line 96
    .line 97
    .line 98
    :cond_4
    return p3

    .line 99
    :cond_5
    :goto_1
    return p2
.end method

.method public final M(Lz7/e;)I
    .locals 4

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x22

    .line 4
    .line 5
    if-lt v0, v1, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Lm8/l;->q2:La8/q1;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-boolean v0, p0, Lm8/l;->y2:Z

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    :goto_0
    iget-wide v0, p1, Lz7/e;->j:J

    .line 17
    .line 18
    iget-wide v2, p0, La8/f;->o:J

    .line 19
    .line 20
    cmp-long v0, v0, v2

    .line 21
    .line 22
    if-gez v0, :cond_1

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lm8/l;->F0(Lz7/e;)Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-nez p0, :cond_1

    .line 29
    .line 30
    const/16 p0, 0x20

    .line 31
    .line 32
    return p0

    .line 33
    :cond_1
    const/4 p0, 0x0

    .line 34
    return p0
.end method

.method public final M0(Lf8/p;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lm8/l;->y2:Z

    .line 2
    .line 3
    if-nez p0, :cond_1

    .line 4
    .line 5
    iget-object p0, p1, Lf8/p;->a:Ljava/lang/String;

    .line 6
    .line 7
    invoke-static {p0}, Lm8/l;->z0(Ljava/lang/String;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-nez p0, :cond_1

    .line 12
    .line 13
    iget-boolean p0, p1, Lf8/p;->f:Z

    .line 14
    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    invoke-static {}, Lm8/n;->h()Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_1

    .line 22
    .line 23
    :cond_0
    const/4 p0, 0x1

    .line 24
    return p0

    .line 25
    :cond_1
    const/4 p0, 0x0

    .line 26
    return p0
.end method

.method public final N(FLt7/o;[Lt7/o;)F
    .locals 6

    .line 1
    array-length v0, p3

    .line 2
    const/high16 v1, -0x40800000    # -1.0f

    .line 3
    .line 4
    const/4 v2, 0x0

    .line 5
    move v3, v1

    .line 6
    :goto_0
    if-ge v2, v0, :cond_1

    .line 7
    .line 8
    aget-object v4, p3, v2

    .line 9
    .line 10
    iget v4, v4, Lt7/o;->y:F

    .line 11
    .line 12
    cmpl-float v5, v4, v1

    .line 13
    .line 14
    if-eqz v5, :cond_0

    .line 15
    .line 16
    invoke-static {v3, v4}, Ljava/lang/Math;->max(FF)F

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    cmpl-float p3, v3, v1

    .line 24
    .line 25
    if-nez p3, :cond_2

    .line 26
    .line 27
    move v3, v1

    .line 28
    goto :goto_1

    .line 29
    :cond_2
    mul-float/2addr v3, p1

    .line 30
    :goto_1
    iget-object p1, p0, Lm8/l;->q2:La8/q1;

    .line 31
    .line 32
    if-eqz p1, :cond_9

    .line 33
    .line 34
    iget-object p0, p0, Lf8/s;->V:Lf8/p;

    .line 35
    .line 36
    if-eqz p0, :cond_9

    .line 37
    .line 38
    iget p1, p2, Lt7/o;->u:I

    .line 39
    .line 40
    iget p2, p2, Lt7/o;->v:I

    .line 41
    .line 42
    iget-boolean p3, p0, Lf8/p;->i:Z

    .line 43
    .line 44
    const v0, -0x800001

    .line 45
    .line 46
    .line 47
    if-nez p3, :cond_3

    .line 48
    .line 49
    goto :goto_4

    .line 50
    :cond_3
    iget p3, p0, Lf8/p;->l:F

    .line 51
    .line 52
    cmpl-float v0, p3, v0

    .line 53
    .line 54
    if-eqz v0, :cond_4

    .line 55
    .line 56
    iget v0, p0, Lf8/p;->j:I

    .line 57
    .line 58
    if-ne v0, p1, :cond_4

    .line 59
    .line 60
    iget v0, p0, Lf8/p;->k:I

    .line 61
    .line 62
    if-ne v0, p2, :cond_4

    .line 63
    .line 64
    move v0, p3

    .line 65
    goto :goto_4

    .line 66
    :cond_4
    const/high16 p3, 0x44800000    # 1024.0f

    .line 67
    .line 68
    float-to-double v4, p3

    .line 69
    invoke-virtual {p0, v4, v5, p1, p2}, Lf8/p;->g(DII)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-eqz v0, :cond_5

    .line 74
    .line 75
    move v0, p3

    .line 76
    goto :goto_3

    .line 77
    :cond_5
    const/4 v0, 0x0

    .line 78
    :goto_2
    sub-float v2, p3, v0

    .line 79
    .line 80
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    const/high16 v5, 0x40a00000    # 5.0f

    .line 85
    .line 86
    cmpl-float v4, v4, v5

    .line 87
    .line 88
    if-lez v4, :cond_7

    .line 89
    .line 90
    const/high16 v4, 0x40000000    # 2.0f

    .line 91
    .line 92
    div-float/2addr v2, v4

    .line 93
    add-float/2addr v2, v0

    .line 94
    float-to-double v4, v2

    .line 95
    invoke-virtual {p0, v4, v5, p1, p2}, Lf8/p;->g(DII)Z

    .line 96
    .line 97
    .line 98
    move-result v4

    .line 99
    if-eqz v4, :cond_6

    .line 100
    .line 101
    move v0, v2

    .line 102
    goto :goto_2

    .line 103
    :cond_6
    move p3, v2

    .line 104
    goto :goto_2

    .line 105
    :cond_7
    :goto_3
    iput v0, p0, Lf8/p;->l:F

    .line 106
    .line 107
    iput p1, p0, Lf8/p;->j:I

    .line 108
    .line 109
    iput p2, p0, Lf8/p;->k:I

    .line 110
    .line 111
    :goto_4
    cmpl-float p0, v3, v1

    .line 112
    .line 113
    if-eqz p0, :cond_8

    .line 114
    .line 115
    invoke-static {v3, v0}, Ljava/lang/Math;->max(FF)F

    .line 116
    .line 117
    .line 118
    move-result p0

    .line 119
    return p0

    .line 120
    :cond_8
    return v0

    .line 121
    :cond_9
    return v3
.end method

.method public final N0(Lf8/m;I)V
    .locals 1

    .line 1
    const-string v0, "skipVideoBuffer"

    .line 2
    .line 3
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p2}, Lf8/m;->n(I)V

    .line 7
    .line 8
    .line 9
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lf8/s;->H1:La8/g;

    .line 13
    .line 14
    iget p1, p0, La8/g;->f:I

    .line 15
    .line 16
    add-int/lit8 p1, p1, 0x1

    .line 17
    .line 18
    iput p1, p0, La8/g;->f:I

    .line 19
    .line 20
    return-void
.end method

.method public final O(Lf8/k;Lt7/o;Z)Ljava/util/ArrayList;
    .locals 1

    .line 1
    iget-object v0, p0, Lm8/l;->Q1:Landroid/content/Context;

    .line 2
    .line 3
    iget-boolean p0, p0, Lm8/l;->y2:Z

    .line 4
    .line 5
    invoke-static {v0, p1, p2, p3, p0}, Lm8/l;->B0(Landroid/content/Context;Lf8/k;Lt7/o;ZZ)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    sget-object p1, Lf8/w;->a:Ljava/util/HashMap;

    .line 10
    .line 11
    new-instance p1, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {p1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, La8/t;

    .line 17
    .line 18
    const/16 p3, 0x19

    .line 19
    .line 20
    invoke-direct {p0, p2, p3}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    new-instance p2, Ld4/a0;

    .line 24
    .line 25
    const/4 p3, 0x2

    .line 26
    invoke-direct {p2, p0, p3}, Ld4/a0;-><init>(Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    invoke-static {p1, p2}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 30
    .line 31
    .line 32
    return-object p1
.end method

.method public final O0(II)V
    .locals 2

    .line 1
    iget-object v0, p0, Lf8/s;->H1:La8/g;

    .line 2
    .line 3
    iget v1, v0, La8/g;->h:I

    .line 4
    .line 5
    add-int/2addr v1, p1

    .line 6
    iput v1, v0, La8/g;->h:I

    .line 7
    .line 8
    add-int/2addr p1, p2

    .line 9
    iget p2, v0, La8/g;->g:I

    .line 10
    .line 11
    add-int/2addr p2, p1

    .line 12
    iput p2, v0, La8/g;->g:I

    .line 13
    .line 14
    iget p2, p0, Lm8/l;->n2:I

    .line 15
    .line 16
    add-int/2addr p2, p1

    .line 17
    iput p2, p0, Lm8/l;->n2:I

    .line 18
    .line 19
    iget p2, p0, Lm8/l;->o2:I

    .line 20
    .line 21
    add-int/2addr p2, p1

    .line 22
    iput p2, p0, Lm8/l;->o2:I

    .line 23
    .line 24
    iget p1, v0, La8/g;->i:I

    .line 25
    .line 26
    invoke-static {p2, p1}, Ljava/lang/Math;->max(II)I

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    iput p1, v0, La8/g;->i:I

    .line 31
    .line 32
    iget p1, p0, Lm8/l;->T1:I

    .line 33
    .line 34
    if-lez p1, :cond_0

    .line 35
    .line 36
    iget p2, p0, Lm8/l;->n2:I

    .line 37
    .line 38
    if-lt p2, p1, :cond_0

    .line 39
    .line 40
    invoke-virtual {p0}, Lm8/l;->G0()V

    .line 41
    .line 42
    .line 43
    :cond_0
    return-void
.end method

.method public final P0(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lf8/s;->H1:La8/g;

    .line 2
    .line 3
    iget-wide v1, v0, La8/g;->k:J

    .line 4
    .line 5
    add-long/2addr v1, p1

    .line 6
    iput-wide v1, v0, La8/g;->k:J

    .line 7
    .line 8
    iget v1, v0, La8/g;->l:I

    .line 9
    .line 10
    add-int/lit8 v1, v1, 0x1

    .line 11
    .line 12
    iput v1, v0, La8/g;->l:I

    .line 13
    .line 14
    iget-wide v0, p0, Lm8/l;->s2:J

    .line 15
    .line 16
    add-long/2addr v0, p1

    .line 17
    iput-wide v0, p0, Lm8/l;->s2:J

    .line 18
    .line 19
    iget p1, p0, Lm8/l;->t2:I

    .line 20
    .line 21
    add-int/lit8 p1, p1, 0x1

    .line 22
    .line 23
    iput p1, p0, Lm8/l;->t2:I

    .line 24
    .line 25
    return-void
.end method

.method public final Q(Lf8/p;Lt7/o;Landroid/media/MediaCrypto;F)Lu/x0;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    iget-object v4, v1, Lf8/p;->c:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v5, v0, La8/f;->m:[Lt7/o;

    .line 10
    .line 11
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget v6, v3, Lt7/o;->u:I

    .line 15
    .line 16
    iget v7, v3, Lt7/o;->y:F

    .line 17
    .line 18
    iget-object v8, v3, Lt7/o;->D:Lt7/f;

    .line 19
    .line 20
    iget v9, v3, Lt7/o;->v:I

    .line 21
    .line 22
    invoke-static/range {p1 .. p2}, Lm8/l;->C0(Lf8/p;Lt7/o;)I

    .line 23
    .line 24
    .line 25
    move-result v10

    .line 26
    array-length v11, v5

    .line 27
    const/4 v13, -0x1

    .line 28
    const/4 v14, 0x1

    .line 29
    if-ne v11, v14, :cond_1

    .line 30
    .line 31
    if-eq v10, v13, :cond_0

    .line 32
    .line 33
    invoke-static/range {p1 .. p2}, Lm8/l;->A0(Lf8/p;Lt7/o;)I

    .line 34
    .line 35
    .line 36
    move-result v5

    .line 37
    if-eq v5, v13, :cond_0

    .line 38
    .line 39
    int-to-float v10, v10

    .line 40
    const/high16 v11, 0x3fc00000    # 1.5f

    .line 41
    .line 42
    mul-float/2addr v10, v11

    .line 43
    float-to-int v10, v10

    .line 44
    invoke-static {v10, v5}, Ljava/lang/Math;->min(II)I

    .line 45
    .line 46
    .line 47
    move-result v10

    .line 48
    :cond_0
    new-instance v5, Lm8/j;

    .line 49
    .line 50
    invoke-direct {v5, v6, v9, v10}, Lm8/j;-><init>(III)V

    .line 51
    .line 52
    .line 53
    move-object/from16 v19, v8

    .line 54
    .line 55
    move v15, v9

    .line 56
    goto/16 :goto_11

    .line 57
    .line 58
    :cond_1
    array-length v11, v5

    .line 59
    move v14, v6

    .line 60
    move v12, v9

    .line 61
    const/4 v15, 0x0

    .line 62
    const/16 v16, 0x0

    .line 63
    .line 64
    :goto_0
    if-ge v15, v11, :cond_6

    .line 65
    .line 66
    aget-object v13, v5, v15

    .line 67
    .line 68
    move-object/from16 v18, v5

    .line 69
    .line 70
    if-eqz v8, :cond_2

    .line 71
    .line 72
    iget-object v5, v13, Lt7/o;->D:Lt7/f;

    .line 73
    .line 74
    if-nez v5, :cond_2

    .line 75
    .line 76
    invoke-virtual {v13}, Lt7/o;->a()Lt7/n;

    .line 77
    .line 78
    .line 79
    move-result-object v5

    .line 80
    iput-object v8, v5, Lt7/n;->C:Lt7/f;

    .line 81
    .line 82
    new-instance v13, Lt7/o;

    .line 83
    .line 84
    invoke-direct {v13, v5}, Lt7/o;-><init>(Lt7/n;)V

    .line 85
    .line 86
    .line 87
    :cond_2
    invoke-virtual {v1, v3, v13}, Lf8/p;->b(Lt7/o;Lt7/o;)La8/h;

    .line 88
    .line 89
    .line 90
    move-result-object v5

    .line 91
    move/from16 v19, v11

    .line 92
    .line 93
    iget v11, v13, Lt7/o;->v:I

    .line 94
    .line 95
    iget v5, v5, La8/h;->d:I

    .line 96
    .line 97
    if-eqz v5, :cond_5

    .line 98
    .line 99
    iget v5, v13, Lt7/o;->u:I

    .line 100
    .line 101
    move/from16 v20, v15

    .line 102
    .line 103
    const/4 v15, -0x1

    .line 104
    if-eq v5, v15, :cond_4

    .line 105
    .line 106
    if-ne v11, v15, :cond_3

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_3
    const/16 v17, 0x0

    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_4
    :goto_1
    const/16 v17, 0x1

    .line 113
    .line 114
    :goto_2
    or-int v16, v16, v17

    .line 115
    .line 116
    invoke-static {v14, v5}, Ljava/lang/Math;->max(II)I

    .line 117
    .line 118
    .line 119
    move-result v14

    .line 120
    invoke-static {v12, v11}, Ljava/lang/Math;->max(II)I

    .line 121
    .line 122
    .line 123
    move-result v12

    .line 124
    invoke-static {v1, v13}, Lm8/l;->C0(Lf8/p;Lt7/o;)I

    .line 125
    .line 126
    .line 127
    move-result v5

    .line 128
    invoke-static {v10, v5}, Ljava/lang/Math;->max(II)I

    .line 129
    .line 130
    .line 131
    move-result v5

    .line 132
    move v10, v5

    .line 133
    goto :goto_3

    .line 134
    :cond_5
    move/from16 v20, v15

    .line 135
    .line 136
    const/4 v15, -0x1

    .line 137
    :goto_3
    add-int/lit8 v5, v20, 0x1

    .line 138
    .line 139
    move v13, v15

    .line 140
    move/from16 v11, v19

    .line 141
    .line 142
    move v15, v5

    .line 143
    move-object/from16 v5, v18

    .line 144
    .line 145
    goto :goto_0

    .line 146
    :cond_6
    if-eqz v16, :cond_12

    .line 147
    .line 148
    new-instance v5, Ljava/lang/StringBuilder;

    .line 149
    .line 150
    const-string v11, "Resolutions unknown. Codec max resolution: "

    .line 151
    .line 152
    invoke-direct {v5, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v5, v14}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    const-string v11, "x"

    .line 159
    .line 160
    invoke-virtual {v5, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v5, v12}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 164
    .line 165
    .line 166
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v5

    .line 170
    const-string v13, "MediaCodecVideoRenderer"

    .line 171
    .line 172
    invoke-static {v13, v5}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    if-le v9, v6, :cond_7

    .line 176
    .line 177
    const/4 v5, 0x1

    .line 178
    goto :goto_4

    .line 179
    :cond_7
    const/4 v5, 0x0

    .line 180
    :goto_4
    if-eqz v5, :cond_8

    .line 181
    .line 182
    move v15, v9

    .line 183
    goto :goto_5

    .line 184
    :cond_8
    move v15, v6

    .line 185
    :goto_5
    move/from16 v16, v5

    .line 186
    .line 187
    if-eqz v5, :cond_9

    .line 188
    .line 189
    move v5, v6

    .line 190
    goto :goto_6

    .line 191
    :cond_9
    move v5, v9

    .line 192
    :goto_6
    int-to-float v2, v5

    .line 193
    move/from16 v17, v2

    .line 194
    .line 195
    int-to-float v2, v15

    .line 196
    div-float v2, v17, v2

    .line 197
    .line 198
    move/from16 v17, v2

    .line 199
    .line 200
    const/4 v2, 0x0

    .line 201
    :goto_7
    const/16 v18, 0x0

    .line 202
    .line 203
    move-object/from16 v19, v8

    .line 204
    .line 205
    const/16 v8, 0x9

    .line 206
    .line 207
    if-ge v2, v8, :cond_11

    .line 208
    .line 209
    sget-object v8, Lm8/l;->G2:[I

    .line 210
    .line 211
    aget v8, v8, v2

    .line 212
    .line 213
    move/from16 v20, v2

    .line 214
    .line 215
    int-to-float v2, v8

    .line 216
    mul-float v2, v2, v17

    .line 217
    .line 218
    float-to-int v2, v2

    .line 219
    if-le v8, v15, :cond_11

    .line 220
    .line 221
    if-gt v2, v5, :cond_a

    .line 222
    .line 223
    goto/16 :goto_e

    .line 224
    .line 225
    :cond_a
    move/from16 v21, v2

    .line 226
    .line 227
    if-eqz v16, :cond_b

    .line 228
    .line 229
    goto :goto_8

    .line 230
    :cond_b
    move v2, v8

    .line 231
    :goto_8
    if-eqz v16, :cond_c

    .line 232
    .line 233
    :goto_9
    move/from16 v21, v5

    .line 234
    .line 235
    goto :goto_a

    .line 236
    :cond_c
    move/from16 v8, v21

    .line 237
    .line 238
    goto :goto_9

    .line 239
    :goto_a
    iget-object v5, v1, Lf8/p;->d:Landroid/media/MediaCodecInfo$CodecCapabilities;

    .line 240
    .line 241
    if-nez v5, :cond_d

    .line 242
    .line 243
    :goto_b
    move/from16 v23, v15

    .line 244
    .line 245
    move-object/from16 v3, v18

    .line 246
    .line 247
    goto :goto_c

    .line 248
    :cond_d
    invoke-virtual {v5}, Landroid/media/MediaCodecInfo$CodecCapabilities;->getVideoCapabilities()Landroid/media/MediaCodecInfo$VideoCapabilities;

    .line 249
    .line 250
    .line 251
    move-result-object v5

    .line 252
    if-nez v5, :cond_e

    .line 253
    .line 254
    goto :goto_b

    .line 255
    :cond_e
    move-object/from16 v22, v5

    .line 256
    .line 257
    invoke-virtual/range {v22 .. v22}, Landroid/media/MediaCodecInfo$VideoCapabilities;->getWidthAlignment()I

    .line 258
    .line 259
    .line 260
    move-result v5

    .line 261
    move/from16 v23, v15

    .line 262
    .line 263
    invoke-virtual/range {v22 .. v22}, Landroid/media/MediaCodecInfo$VideoCapabilities;->getHeightAlignment()I

    .line 264
    .line 265
    .line 266
    move-result v15

    .line 267
    new-instance v3, Landroid/graphics/Point;

    .line 268
    .line 269
    invoke-static {v2, v5}, Lw7/w;->e(II)I

    .line 270
    .line 271
    .line 272
    move-result v2

    .line 273
    mul-int/2addr v2, v5

    .line 274
    invoke-static {v8, v15}, Lw7/w;->e(II)I

    .line 275
    .line 276
    .line 277
    move-result v5

    .line 278
    mul-int/2addr v5, v15

    .line 279
    invoke-direct {v3, v2, v5}, Landroid/graphics/Point;-><init>(II)V

    .line 280
    .line 281
    .line 282
    :goto_c
    if-eqz v3, :cond_f

    .line 283
    .line 284
    iget v2, v3, Landroid/graphics/Point;->x:I

    .line 285
    .line 286
    iget v5, v3, Landroid/graphics/Point;->y:I

    .line 287
    .line 288
    move v15, v9

    .line 289
    float-to-double v8, v7

    .line 290
    invoke-virtual {v1, v8, v9, v2, v5}, Lf8/p;->g(DII)Z

    .line 291
    .line 292
    .line 293
    move-result v2

    .line 294
    if-eqz v2, :cond_10

    .line 295
    .line 296
    goto :goto_f

    .line 297
    :cond_f
    move v15, v9

    .line 298
    :cond_10
    add-int/lit8 v2, v20, 0x1

    .line 299
    .line 300
    move-object/from16 v3, p2

    .line 301
    .line 302
    move v9, v15

    .line 303
    move-object/from16 v8, v19

    .line 304
    .line 305
    move/from16 v5, v21

    .line 306
    .line 307
    move/from16 v15, v23

    .line 308
    .line 309
    goto :goto_7

    .line 310
    :goto_d
    move-object/from16 v3, v18

    .line 311
    .line 312
    goto :goto_f

    .line 313
    :cond_11
    :goto_e
    move v15, v9

    .line 314
    goto :goto_d

    .line 315
    :goto_f
    if-eqz v3, :cond_13

    .line 316
    .line 317
    iget v2, v3, Landroid/graphics/Point;->x:I

    .line 318
    .line 319
    invoke-static {v14, v2}, Ljava/lang/Math;->max(II)I

    .line 320
    .line 321
    .line 322
    move-result v14

    .line 323
    iget v2, v3, Landroid/graphics/Point;->y:I

    .line 324
    .line 325
    invoke-static {v12, v2}, Ljava/lang/Math;->max(II)I

    .line 326
    .line 327
    .line 328
    move-result v12

    .line 329
    invoke-virtual/range {p2 .. p2}, Lt7/o;->a()Lt7/n;

    .line 330
    .line 331
    .line 332
    move-result-object v2

    .line 333
    iput v14, v2, Lt7/n;->t:I

    .line 334
    .line 335
    iput v12, v2, Lt7/n;->u:I

    .line 336
    .line 337
    new-instance v3, Lt7/o;

    .line 338
    .line 339
    invoke-direct {v3, v2}, Lt7/o;-><init>(Lt7/n;)V

    .line 340
    .line 341
    .line 342
    invoke-static {v1, v3}, Lm8/l;->A0(Lf8/p;Lt7/o;)I

    .line 343
    .line 344
    .line 345
    move-result v2

    .line 346
    invoke-static {v10, v2}, Ljava/lang/Math;->max(II)I

    .line 347
    .line 348
    .line 349
    move-result v10

    .line 350
    new-instance v2, Ljava/lang/StringBuilder;

    .line 351
    .line 352
    const-string v3, "Codec max resolution adjusted to: "

    .line 353
    .line 354
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    invoke-virtual {v2, v14}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 358
    .line 359
    .line 360
    invoke-virtual {v2, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 361
    .line 362
    .line 363
    invoke-virtual {v2, v12}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 364
    .line 365
    .line 366
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 367
    .line 368
    .line 369
    move-result-object v2

    .line 370
    invoke-static {v13, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    goto :goto_10

    .line 374
    :cond_12
    move-object/from16 v19, v8

    .line 375
    .line 376
    move v15, v9

    .line 377
    :cond_13
    :goto_10
    new-instance v5, Lm8/j;

    .line 378
    .line 379
    invoke-direct {v5, v14, v12, v10}, Lm8/j;-><init>(III)V

    .line 380
    .line 381
    .line 382
    :goto_11
    iput-object v5, v0, Lm8/l;->Z1:Lm8/j;

    .line 383
    .line 384
    iget-boolean v2, v0, Lm8/l;->y2:Z

    .line 385
    .line 386
    if-eqz v2, :cond_14

    .line 387
    .line 388
    iget v2, v0, Lm8/l;->z2:I

    .line 389
    .line 390
    goto :goto_12

    .line 391
    :cond_14
    const/4 v2, 0x0

    .line 392
    :goto_12
    new-instance v3, Landroid/media/MediaFormat;

    .line 393
    .line 394
    invoke-direct {v3}, Landroid/media/MediaFormat;-><init>()V

    .line 395
    .line 396
    .line 397
    const-string v8, "mime"

    .line 398
    .line 399
    invoke-virtual {v3, v8, v4}, Landroid/media/MediaFormat;->setString(Ljava/lang/String;Ljava/lang/String;)V

    .line 400
    .line 401
    .line 402
    const-string v4, "width"

    .line 403
    .line 404
    invoke-virtual {v3, v4, v6}, Landroid/media/MediaFormat;->setInteger(Ljava/lang/String;I)V

    .line 405
    .line 406
    .line 407
    const-string v4, "height"

    .line 408
    .line 409
    invoke-virtual {v3, v4, v15}, Landroid/media/MediaFormat;->setInteger(Ljava/lang/String;I)V

    .line 410
    .line 411
    .line 412
    move-object/from16 v4, p2

    .line 413
    .line 414
    iget-object v6, v4, Lt7/o;->q:Ljava/util/List;

    .line 415
    .line 416
    invoke-static {v3, v6}, Lw7/a;->x(Landroid/media/MediaFormat;Ljava/util/List;)V

    .line 417
    .line 418
    .line 419
    const/high16 v6, -0x40800000    # -1.0f

    .line 420
    .line 421
    cmpl-float v8, v7, v6

    .line 422
    .line 423
    if-eqz v8, :cond_15

    .line 424
    .line 425
    const-string v8, "frame-rate"

    .line 426
    .line 427
    invoke-virtual {v3, v8, v7}, Landroid/media/MediaFormat;->setFloat(Ljava/lang/String;F)V

    .line 428
    .line 429
    .line 430
    :cond_15
    const-string v7, "rotation-degrees"

    .line 431
    .line 432
    iget v8, v4, Lt7/o;->z:I

    .line 433
    .line 434
    invoke-static {v3, v7, v8}, Lw7/a;->w(Landroid/media/MediaFormat;Ljava/lang/String;I)V

    .line 435
    .line 436
    .line 437
    if-eqz v19, :cond_16

    .line 438
    .line 439
    const-string v7, "color-transfer"

    .line 440
    .line 441
    move-object/from16 v8, v19

    .line 442
    .line 443
    iget v9, v8, Lt7/f;->c:I

    .line 444
    .line 445
    invoke-static {v3, v7, v9}, Lw7/a;->w(Landroid/media/MediaFormat;Ljava/lang/String;I)V

    .line 446
    .line 447
    .line 448
    const-string v7, "color-standard"

    .line 449
    .line 450
    iget v9, v8, Lt7/f;->a:I

    .line 451
    .line 452
    invoke-static {v3, v7, v9}, Lw7/a;->w(Landroid/media/MediaFormat;Ljava/lang/String;I)V

    .line 453
    .line 454
    .line 455
    const-string v7, "color-range"

    .line 456
    .line 457
    iget v9, v8, Lt7/f;->b:I

    .line 458
    .line 459
    invoke-static {v3, v7, v9}, Lw7/a;->w(Landroid/media/MediaFormat;Ljava/lang/String;I)V

    .line 460
    .line 461
    .line 462
    iget-object v7, v8, Lt7/f;->d:[B

    .line 463
    .line 464
    if-eqz v7, :cond_16

    .line 465
    .line 466
    invoke-static {v7}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    .line 467
    .line 468
    .line 469
    move-result-object v7

    .line 470
    const-string v8, "hdr-static-info"

    .line 471
    .line 472
    invoke-virtual {v3, v8, v7}, Landroid/media/MediaFormat;->setByteBuffer(Ljava/lang/String;Ljava/nio/ByteBuffer;)V

    .line 473
    .line 474
    .line 475
    :cond_16
    const-string v7, "video/dolby-vision"

    .line 476
    .line 477
    iget-object v8, v4, Lt7/o;->n:Ljava/lang/String;

    .line 478
    .line 479
    invoke-virtual {v7, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 480
    .line 481
    .line 482
    move-result v7

    .line 483
    if-eqz v7, :cond_17

    .line 484
    .line 485
    sget-object v7, Lf8/w;->a:Ljava/util/HashMap;

    .line 486
    .line 487
    invoke-static {v4}, Lw7/c;->b(Lt7/o;)Landroid/util/Pair;

    .line 488
    .line 489
    .line 490
    move-result-object v7

    .line 491
    if-eqz v7, :cond_17

    .line 492
    .line 493
    iget-object v7, v7, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 494
    .line 495
    check-cast v7, Ljava/lang/Integer;

    .line 496
    .line 497
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 498
    .line 499
    .line 500
    move-result v7

    .line 501
    const-string v8, "profile"

    .line 502
    .line 503
    invoke-static {v3, v8, v7}, Lw7/a;->w(Landroid/media/MediaFormat;Ljava/lang/String;I)V

    .line 504
    .line 505
    .line 506
    :cond_17
    const-string v7, "max-width"

    .line 507
    .line 508
    iget v8, v5, Lm8/j;->a:I

    .line 509
    .line 510
    invoke-virtual {v3, v7, v8}, Landroid/media/MediaFormat;->setInteger(Ljava/lang/String;I)V

    .line 511
    .line 512
    .line 513
    const-string v7, "max-height"

    .line 514
    .line 515
    iget v8, v5, Lm8/j;->b:I

    .line 516
    .line 517
    invoke-virtual {v3, v7, v8}, Landroid/media/MediaFormat;->setInteger(Ljava/lang/String;I)V

    .line 518
    .line 519
    .line 520
    const-string v7, "max-input-size"

    .line 521
    .line 522
    iget v5, v5, Lm8/j;->c:I

    .line 523
    .line 524
    invoke-static {v3, v7, v5}, Lw7/a;->w(Landroid/media/MediaFormat;Ljava/lang/String;I)V

    .line 525
    .line 526
    .line 527
    sget v5, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 528
    .line 529
    const-string v7, "priority"

    .line 530
    .line 531
    const/4 v8, 0x0

    .line 532
    invoke-virtual {v3, v7, v8}, Landroid/media/MediaFormat;->setInteger(Ljava/lang/String;I)V

    .line 533
    .line 534
    .line 535
    cmpl-float v6, p4, v6

    .line 536
    .line 537
    if-eqz v6, :cond_18

    .line 538
    .line 539
    const-string v6, "operating-rate"

    .line 540
    .line 541
    move/from16 v7, p4

    .line 542
    .line 543
    invoke-virtual {v3, v6, v7}, Landroid/media/MediaFormat;->setFloat(Ljava/lang/String;F)V

    .line 544
    .line 545
    .line 546
    :cond_18
    iget-boolean v6, v0, Lm8/l;->U1:Z

    .line 547
    .line 548
    if-eqz v6, :cond_19

    .line 549
    .line 550
    const-string v6, "no-post-process"

    .line 551
    .line 552
    const/4 v7, 0x1

    .line 553
    invoke-virtual {v3, v6, v7}, Landroid/media/MediaFormat;->setInteger(Ljava/lang/String;I)V

    .line 554
    .line 555
    .line 556
    const-string v6, "auto-frc"

    .line 557
    .line 558
    const/4 v8, 0x0

    .line 559
    invoke-virtual {v3, v6, v8}, Landroid/media/MediaFormat;->setInteger(Ljava/lang/String;I)V

    .line 560
    .line 561
    .line 562
    goto :goto_13

    .line 563
    :cond_19
    const/4 v7, 0x1

    .line 564
    :goto_13
    if-eqz v2, :cond_1a

    .line 565
    .line 566
    const-string v6, "tunneled-playback"

    .line 567
    .line 568
    invoke-virtual {v3, v6, v7}, Landroid/media/MediaFormat;->setFeatureEnabled(Ljava/lang/String;Z)V

    .line 569
    .line 570
    .line 571
    const-string v6, "audio-session-id"

    .line 572
    .line 573
    invoke-virtual {v3, v6, v2}, Landroid/media/MediaFormat;->setInteger(Ljava/lang/String;I)V

    .line 574
    .line 575
    .line 576
    :cond_1a
    const/16 v2, 0x23

    .line 577
    .line 578
    if-lt v5, v2, :cond_1b

    .line 579
    .line 580
    iget v2, v0, Lm8/l;->x2:I

    .line 581
    .line 582
    neg-int v2, v2

    .line 583
    const/4 v8, 0x0

    .line 584
    invoke-static {v8, v2}, Ljava/lang/Math;->max(II)I

    .line 585
    .line 586
    .line 587
    move-result v2

    .line 588
    const-string v5, "importance"

    .line 589
    .line 590
    invoke-virtual {v3, v5, v2}, Landroid/media/MediaFormat;->setInteger(Ljava/lang/String;I)V

    .line 591
    .line 592
    .line 593
    :cond_1b
    invoke-virtual/range {p0 .. p1}, Lm8/l;->D0(Lf8/p;)Landroid/view/Surface;

    .line 594
    .line 595
    .line 596
    move-result-object v4

    .line 597
    iget-object v2, v0, Lm8/l;->c2:Lm8/i0;

    .line 598
    .line 599
    if-eqz v2, :cond_1c

    .line 600
    .line 601
    iget-object v0, v0, Lm8/l;->Q1:Landroid/content/Context;

    .line 602
    .line 603
    invoke-static {v0}, Lw7/w;->B(Landroid/content/Context;)Z

    .line 604
    .line 605
    .line 606
    move-result v0

    .line 607
    if-nez v0, :cond_1c

    .line 608
    .line 609
    const-string v0, "allow-frame-drop"

    .line 610
    .line 611
    const/4 v8, 0x0

    .line 612
    invoke-virtual {v3, v0, v8}, Landroid/media/MediaFormat;->setInteger(Ljava/lang/String;I)V

    .line 613
    .line 614
    .line 615
    :cond_1c
    new-instance v0, Lu/x0;

    .line 616
    .line 617
    const/4 v6, 0x0

    .line 618
    move-object/from16 v5, p3

    .line 619
    .line 620
    move-object v2, v3

    .line 621
    move-object/from16 v3, p2

    .line 622
    .line 623
    invoke-direct/range {v0 .. v6}, Lu/x0;-><init>(Lf8/p;Landroid/media/MediaFormat;Lt7/o;Landroid/view/Surface;Landroid/media/MediaCrypto;Lgw0/c;)V

    .line 624
    .line 625
    .line 626
    return-object v0
.end method

.method public final R(Lz7/e;)V
    .locals 7

    .line 1
    iget-boolean v0, p0, Lm8/l;->b2:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    iget-object p1, p1, Lz7/e;->k:Ljava/nio/ByteBuffer;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/nio/Buffer;->remaining()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/4 v1, 0x7

    .line 16
    if-lt v0, v1, :cond_2

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->get()B

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->getShort()S

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->getShort()S

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->get()B

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    invoke-virtual {p1}, Ljava/nio/ByteBuffer;->get()B

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    const/4 v5, 0x0

    .line 39
    invoke-virtual {p1, v5}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 40
    .line 41
    .line 42
    const/16 v6, -0x4b

    .line 43
    .line 44
    if-ne v0, v6, :cond_2

    .line 45
    .line 46
    const/16 v0, 0x3c

    .line 47
    .line 48
    if-ne v1, v0, :cond_2

    .line 49
    .line 50
    const/4 v0, 0x1

    .line 51
    if-ne v2, v0, :cond_2

    .line 52
    .line 53
    const/4 v1, 0x4

    .line 54
    if-ne v3, v1, :cond_2

    .line 55
    .line 56
    if-eqz v4, :cond_1

    .line 57
    .line 58
    if-ne v4, v0, :cond_2

    .line 59
    .line 60
    :cond_1
    invoke-virtual {p1}, Ljava/nio/Buffer;->remaining()I

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    new-array v0, v0, [B

    .line 65
    .line 66
    invoke-virtual {p1, v0}, Ljava/nio/ByteBuffer;->get([B)Ljava/nio/ByteBuffer;

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1, v5}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 70
    .line 71
    .line 72
    iget-object p0, p0, Lf8/s;->O:Lf8/m;

    .line 73
    .line 74
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    new-instance p1, Landroid/os/Bundle;

    .line 78
    .line 79
    invoke-direct {p1}, Landroid/os/Bundle;-><init>()V

    .line 80
    .line 81
    .line 82
    const-string v1, "hdr10-plus-info"

    .line 83
    .line 84
    invoke-virtual {p1, v1, v0}, Landroid/os/Bundle;->putByteArray(Ljava/lang/String;[B)V

    .line 85
    .line 86
    .line 87
    invoke-interface {p0, p1}, Lf8/m;->a(Landroid/os/Bundle;)V

    .line 88
    .line 89
    .line 90
    :cond_2
    :goto_0
    return-void
.end method

.method public final W(Lt7/o;)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Lm8/i0;->isInitialized()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    :try_start_0
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 12
    .line 13
    invoke-interface {v0, p1}, Lm8/i0;->j(Lt7/o;)Z

    .line 14
    .line 15
    .line 16
    move-result p0
    :try_end_0
    .catch Lm8/h0; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    return p0

    .line 18
    :catch_0
    move-exception v0

    .line 19
    const/16 v1, 0x1b58

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    invoke-virtual {p0, v0, p1, v2, v1}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    throw p0

    .line 27
    :cond_0
    const/4 p0, 0x1

    .line 28
    return p0
.end method

.method public final X(Ljava/lang/Exception;)V
    .locals 3

    .line 1
    const-string v0, "MediaCodecVideoRenderer"

    .line 2
    .line 3
    const-string v1, "Video codec error"

    .line 4
    .line 5
    invoke-static {v0, v1, p1}, Lw7/a;->p(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lm8/l;->S1:Lb81/b;

    .line 9
    .line 10
    iget-object v0, p0, Lb81/b;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Landroid/os/Handler;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    new-instance v1, Lm8/e0;

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-direct {v1, p0, p1, v2}, Lm8/e0;-><init>(Lb81/b;Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method

.method public final Y(JLjava/lang/String;J)V
    .locals 8

    .line 1
    iget-object v1, p0, Lm8/l;->S1:Lb81/b;

    .line 2
    .line 3
    iget-object v0, v1, Lb81/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    move-object v7, v0

    .line 6
    check-cast v7, Landroid/os/Handler;

    .line 7
    .line 8
    if-eqz v7, :cond_0

    .line 9
    .line 10
    new-instance v0, Lm8/e0;

    .line 11
    .line 12
    move-wide v3, p1

    .line 13
    move-object v2, p3

    .line 14
    move-wide v5, p4

    .line 15
    invoke-direct/range {v0 .. v6}, Lm8/e0;-><init>(Lb81/b;Ljava/lang/String;JJ)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v7, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move-object v2, p3

    .line 23
    :goto_0
    invoke-static {v2}, Lm8/l;->z0(Ljava/lang/String;)Z

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    iput-boolean p1, p0, Lm8/l;->a2:Z

    .line 28
    .line 29
    iget-object p1, p0, Lf8/s;->V:Lf8/p;

    .line 30
    .line 31
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const-string p2, "video/x-vnd.on2.vp9"

    .line 35
    .line 36
    iget-object p3, p1, Lf8/p;->b:Ljava/lang/String;

    .line 37
    .line 38
    invoke-virtual {p2, p3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result p2

    .line 42
    const/4 p3, 0x0

    .line 43
    if-eqz p2, :cond_4

    .line 44
    .line 45
    iget-object p1, p1, Lf8/p;->d:Landroid/media/MediaCodecInfo$CodecCapabilities;

    .line 46
    .line 47
    if-eqz p1, :cond_1

    .line 48
    .line 49
    iget-object p1, p1, Landroid/media/MediaCodecInfo$CodecCapabilities;->profileLevels:[Landroid/media/MediaCodecInfo$CodecProfileLevel;

    .line 50
    .line 51
    if-nez p1, :cond_2

    .line 52
    .line 53
    :cond_1
    new-array p1, p3, [Landroid/media/MediaCodecInfo$CodecProfileLevel;

    .line 54
    .line 55
    :cond_2
    array-length p2, p1

    .line 56
    move p4, p3

    .line 57
    :goto_1
    if-ge p4, p2, :cond_4

    .line 58
    .line 59
    aget-object p5, p1, p4

    .line 60
    .line 61
    iget p5, p5, Landroid/media/MediaCodecInfo$CodecProfileLevel;->profile:I

    .line 62
    .line 63
    const/16 v0, 0x4000

    .line 64
    .line 65
    if-ne p5, v0, :cond_3

    .line 66
    .line 67
    const/4 p3, 0x1

    .line 68
    goto :goto_2

    .line 69
    :cond_3
    add-int/lit8 p4, p4, 0x1

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_4
    :goto_2
    iput-boolean p3, p0, Lm8/l;->b2:Z

    .line 73
    .line 74
    invoke-virtual {p0}, Lm8/l;->H0()V

    .line 75
    .line 76
    .line 77
    return-void
.end method

.method public final Z(Ljava/lang/String;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lm8/l;->S1:Lb81/b;

    .line 2
    .line 3
    iget-object v0, p0, Lb81/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Landroid/os/Handler;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    new-instance v1, Lm8/e0;

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    invoke-direct {v1, p0, p1, v2}, Lm8/e0;-><init>(Lb81/b;Ljava/lang/Object;I)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final a(ILjava/lang/Object;)V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p1, v0, :cond_e

    .line 3
    .line 4
    const/4 v1, 0x7

    .line 5
    if-eq p1, v1, :cond_c

    .line 6
    .line 7
    const/16 v1, 0xa

    .line 8
    .line 9
    if-eq p1, v1, :cond_b

    .line 10
    .line 11
    const/4 v1, 0x4

    .line 12
    if-eq p1, v1, :cond_a

    .line 13
    .line 14
    const/4 v1, 0x5

    .line 15
    if-eq p1, v1, :cond_7

    .line 16
    .line 17
    const/16 v1, 0xd

    .line 18
    .line 19
    if-eq p1, v1, :cond_4

    .line 20
    .line 21
    const/16 v1, 0xe

    .line 22
    .line 23
    if-eq p1, v1, :cond_3

    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    packed-switch p1, :pswitch_data_0

    .line 27
    .line 28
    .line 29
    const/16 v0, 0xb

    .line 30
    .line 31
    if-ne p1, v0, :cond_d

    .line 32
    .line 33
    check-cast p2, La8/l0;

    .line 34
    .line 35
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    iput-object p2, p0, Lf8/s;->J:La8/l0;

    .line 39
    .line 40
    return-void

    .line 41
    :pswitch_0
    iget-object p1, p0, Lm8/l;->q2:La8/q1;

    .line 42
    .line 43
    if-eqz p1, :cond_0

    .line 44
    .line 45
    move p1, v0

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    move p1, v1

    .line 48
    :goto_0
    check-cast p2, La8/q1;

    .line 49
    .line 50
    iput-object p2, p0, Lm8/l;->q2:La8/q1;

    .line 51
    .line 52
    if-eqz p2, :cond_1

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_1
    move v0, v1

    .line 56
    :goto_1
    if-eq p1, v0, :cond_d

    .line 57
    .line 58
    iget-object p1, p0, Lf8/s;->P:Lt7/o;

    .line 59
    .line 60
    invoke-virtual {p0, p1}, Lf8/s;->w0(Lt7/o;)Z

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :pswitch_1
    iget-object p1, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 65
    .line 66
    const/4 v1, 0x0

    .line 67
    invoke-virtual {p0, v1}, Lm8/l;->K0(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    check-cast p2, Lm8/l;

    .line 74
    .line 75
    invoke-virtual {p2, v0, p1}, Lm8/l;->a(ILjava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    return-void

    .line 79
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 80
    .line 81
    .line 82
    check-cast p2, Ljava/lang/Integer;

    .line 83
    .line 84
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    iput p1, p0, Lm8/l;->x2:I

    .line 89
    .line 90
    iget-object p1, p0, Lf8/s;->O:Lf8/m;

    .line 91
    .line 92
    if-nez p1, :cond_2

    .line 93
    .line 94
    goto/16 :goto_2

    .line 95
    .line 96
    :cond_2
    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 97
    .line 98
    const/16 v0, 0x23

    .line 99
    .line 100
    if-lt p2, v0, :cond_d

    .line 101
    .line 102
    new-instance p2, Landroid/os/Bundle;

    .line 103
    .line 104
    invoke-direct {p2}, Landroid/os/Bundle;-><init>()V

    .line 105
    .line 106
    .line 107
    iget p0, p0, Lm8/l;->x2:I

    .line 108
    .line 109
    neg-int p0, p0

    .line 110
    invoke-static {v1, p0}, Ljava/lang/Math;->max(II)I

    .line 111
    .line 112
    .line 113
    move-result p0

    .line 114
    const-string v0, "importance"

    .line 115
    .line 116
    invoke-virtual {p2, v0, p0}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 117
    .line 118
    .line 119
    invoke-interface {p1, p2}, Lf8/m;->a(Landroid/os/Bundle;)V

    .line 120
    .line 121
    .line 122
    return-void

    .line 123
    :cond_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    check-cast p2, Lw7/q;

    .line 127
    .line 128
    iget p1, p2, Lw7/q;->a:I

    .line 129
    .line 130
    if-eqz p1, :cond_d

    .line 131
    .line 132
    iget p1, p2, Lw7/q;->b:I

    .line 133
    .line 134
    if-eqz p1, :cond_d

    .line 135
    .line 136
    iput-object p2, p0, Lm8/l;->i2:Lw7/q;

    .line 137
    .line 138
    iget-object p1, p0, Lm8/l;->c2:Lm8/i0;

    .line 139
    .line 140
    if-eqz p1, :cond_d

    .line 141
    .line 142
    iget-object p0, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 143
    .line 144
    invoke-static {p0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    invoke-interface {p1, p0, p2}, Lm8/i0;->s(Landroid/view/Surface;Lw7/q;)V

    .line 148
    .line 149
    .line 150
    return-void

    .line 151
    :cond_4
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 152
    .line 153
    .line 154
    check-cast p2, Ljava/util/List;

    .line 155
    .line 156
    sget-object p1, Lt7/z0;->a:Lhr/x0;

    .line 157
    .line 158
    invoke-interface {p2, p1}, Ljava/util/List;->equals(Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result p1

    .line 162
    if-eqz p1, :cond_6

    .line 163
    .line 164
    iget-object p1, p0, Lm8/l;->c2:Lm8/i0;

    .line 165
    .line 166
    if-eqz p1, :cond_d

    .line 167
    .line 168
    invoke-interface {p1}, Lm8/i0;->isInitialized()Z

    .line 169
    .line 170
    .line 171
    move-result p1

    .line 172
    if-nez p1, :cond_5

    .line 173
    .line 174
    goto :goto_2

    .line 175
    :cond_5
    iget-object p0, p0, Lm8/l;->c2:Lm8/i0;

    .line 176
    .line 177
    invoke-interface {p0}, Lm8/i0;->h()V

    .line 178
    .line 179
    .line 180
    return-void

    .line 181
    :cond_6
    iput-object p2, p0, Lm8/l;->f2:Ljava/util/List;

    .line 182
    .line 183
    iget-object p0, p0, Lm8/l;->c2:Lm8/i0;

    .line 184
    .line 185
    if-eqz p0, :cond_d

    .line 186
    .line 187
    invoke-interface {p0, p2}, Lm8/i0;->f(Ljava/util/List;)V

    .line 188
    .line 189
    .line 190
    return-void

    .line 191
    :cond_7
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 192
    .line 193
    .line 194
    check-cast p2, Ljava/lang/Integer;

    .line 195
    .line 196
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 197
    .line 198
    .line 199
    move-result p1

    .line 200
    iput p1, p0, Lm8/l;->l2:I

    .line 201
    .line 202
    iget-object p2, p0, Lm8/l;->c2:Lm8/i0;

    .line 203
    .line 204
    if-eqz p2, :cond_8

    .line 205
    .line 206
    invoke-interface {p2, p1}, Lm8/i0;->p(I)V

    .line 207
    .line 208
    .line 209
    return-void

    .line 210
    :cond_8
    iget-object p0, p0, Lm8/l;->V1:Lm8/y;

    .line 211
    .line 212
    iget-object p0, p0, Lm8/y;->b:Lm8/c0;

    .line 213
    .line 214
    iget p2, p0, Lm8/c0;->j:I

    .line 215
    .line 216
    if-ne p2, p1, :cond_9

    .line 217
    .line 218
    goto :goto_2

    .line 219
    :cond_9
    iput p1, p0, Lm8/c0;->j:I

    .line 220
    .line 221
    invoke-virtual {p0, v0}, Lm8/c0;->d(Z)V

    .line 222
    .line 223
    .line 224
    return-void

    .line 225
    :cond_a
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 226
    .line 227
    .line 228
    check-cast p2, Ljava/lang/Integer;

    .line 229
    .line 230
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 231
    .line 232
    .line 233
    move-result p1

    .line 234
    iput p1, p0, Lm8/l;->k2:I

    .line 235
    .line 236
    iget-object p0, p0, Lf8/s;->O:Lf8/m;

    .line 237
    .line 238
    if-eqz p0, :cond_d

    .line 239
    .line 240
    invoke-interface {p0, p1}, Lf8/m;->j(I)V

    .line 241
    .line 242
    .line 243
    return-void

    .line 244
    :cond_b
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 245
    .line 246
    .line 247
    check-cast p2, Ljava/lang/Integer;

    .line 248
    .line 249
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 250
    .line 251
    .line 252
    move-result p1

    .line 253
    iget p2, p0, Lm8/l;->z2:I

    .line 254
    .line 255
    if-eq p2, p1, :cond_d

    .line 256
    .line 257
    iput p1, p0, Lm8/l;->z2:I

    .line 258
    .line 259
    iget-boolean p1, p0, Lm8/l;->y2:Z

    .line 260
    .line 261
    if-eqz p1, :cond_d

    .line 262
    .line 263
    invoke-virtual {p0}, Lf8/s;->j0()V

    .line 264
    .line 265
    .line 266
    return-void

    .line 267
    :cond_c
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 268
    .line 269
    .line 270
    check-cast p2, Lm8/x;

    .line 271
    .line 272
    iput-object p2, p0, Lm8/l;->B2:Lm8/x;

    .line 273
    .line 274
    iget-object p0, p0, Lm8/l;->c2:Lm8/i0;

    .line 275
    .line 276
    if-eqz p0, :cond_d

    .line 277
    .line 278
    invoke-interface {p0, p2}, Lm8/i0;->n(Lm8/x;)V

    .line 279
    .line 280
    .line 281
    :cond_d
    :goto_2
    return-void

    .line 282
    :cond_e
    invoke-virtual {p0, p2}, Lm8/l;->K0(Ljava/lang/Object;)V

    .line 283
    .line 284
    .line 285
    return-void

    .line 286
    nop

    .line 287
    :pswitch_data_0
    .packed-switch 0x10
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final a0(Lb81/d;)La8/h;
    .locals 3

    .line 1
    invoke-super {p0, p1}, Lf8/s;->a0(Lb81/d;)La8/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p1, p1, Lb81/d;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p1, Lt7/o;

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lm8/l;->S1:Lb81/b;

    .line 13
    .line 14
    iget-object v1, p0, Lb81/b;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Landroid/os/Handler;

    .line 17
    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    new-instance v2, Lm8/e0;

    .line 21
    .line 22
    invoke-direct {v2, p0, p1, v0}, Lm8/e0;-><init>(Lb81/b;Lt7/o;La8/h;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 26
    .line 27
    .line 28
    :cond_0
    return-object v0
.end method

.method public final b0(Lt7/o;Landroid/media/MediaFormat;)V
    .locals 11

    .line 1
    iget-object v0, p0, Lf8/s;->O:Lf8/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget v1, p0, Lm8/l;->k2:I

    .line 6
    .line 7
    invoke-interface {v0, v1}, Lf8/m;->j(I)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-boolean v0, p0, Lm8/l;->y2:Z

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    iget p2, p1, Lt7/o;->u:I

    .line 16
    .line 17
    iget v0, p1, Lt7/o;->v:I

    .line 18
    .line 19
    goto :goto_3

    .line 20
    :cond_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    const-string v0, "crop-right"

    .line 24
    .line 25
    invoke-virtual {p2, v0}, Landroid/media/MediaFormat;->containsKey(Ljava/lang/String;)Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    const-string v3, "crop-top"

    .line 30
    .line 31
    const-string v4, "crop-bottom"

    .line 32
    .line 33
    const-string v5, "crop-left"

    .line 34
    .line 35
    const/4 v6, 0x1

    .line 36
    if-eqz v2, :cond_2

    .line 37
    .line 38
    invoke-virtual {p2, v5}, Landroid/media/MediaFormat;->containsKey(Ljava/lang/String;)Z

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    if-eqz v2, :cond_2

    .line 43
    .line 44
    invoke-virtual {p2, v4}, Landroid/media/MediaFormat;->containsKey(Ljava/lang/String;)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    invoke-virtual {p2, v3}, Landroid/media/MediaFormat;->containsKey(Ljava/lang/String;)Z

    .line 51
    .line 52
    .line 53
    move-result v2

    .line 54
    if-eqz v2, :cond_2

    .line 55
    .line 56
    move v2, v6

    .line 57
    goto :goto_0

    .line 58
    :cond_2
    move v2, v1

    .line 59
    :goto_0
    if-eqz v2, :cond_3

    .line 60
    .line 61
    invoke-virtual {p2, v0}, Landroid/media/MediaFormat;->getInteger(Ljava/lang/String;)I

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    invoke-virtual {p2, v5}, Landroid/media/MediaFormat;->getInteger(Ljava/lang/String;)I

    .line 66
    .line 67
    .line 68
    move-result v5

    .line 69
    sub-int/2addr v0, v5

    .line 70
    add-int/2addr v0, v6

    .line 71
    goto :goto_1

    .line 72
    :cond_3
    const-string v0, "width"

    .line 73
    .line 74
    invoke-virtual {p2, v0}, Landroid/media/MediaFormat;->getInteger(Ljava/lang/String;)I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    :goto_1
    if-eqz v2, :cond_4

    .line 79
    .line 80
    invoke-virtual {p2, v4}, Landroid/media/MediaFormat;->getInteger(Ljava/lang/String;)I

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    invoke-virtual {p2, v3}, Landroid/media/MediaFormat;->getInteger(Ljava/lang/String;)I

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    sub-int/2addr v2, p2

    .line 89
    add-int/2addr v2, v6

    .line 90
    move p2, v2

    .line 91
    goto :goto_2

    .line 92
    :cond_4
    const-string v2, "height"

    .line 93
    .line 94
    invoke-virtual {p2, v2}, Landroid/media/MediaFormat;->getInteger(Ljava/lang/String;)I

    .line 95
    .line 96
    .line 97
    move-result p2

    .line 98
    :goto_2
    move v10, v0

    .line 99
    move v0, p2

    .line 100
    move p2, v10

    .line 101
    :goto_3
    iget v2, p1, Lt7/o;->A:F

    .line 102
    .line 103
    iget v3, p1, Lt7/o;->z:I

    .line 104
    .line 105
    const/16 v4, 0x5a

    .line 106
    .line 107
    if-eq v3, v4, :cond_5

    .line 108
    .line 109
    const/16 v4, 0x10e

    .line 110
    .line 111
    if-ne v3, v4, :cond_6

    .line 112
    .line 113
    :cond_5
    const/high16 v3, 0x3f800000    # 1.0f

    .line 114
    .line 115
    div-float v2, v3, v2

    .line 116
    .line 117
    move v10, v0

    .line 118
    move v0, p2

    .line 119
    move p2, v10

    .line 120
    :cond_6
    new-instance v3, Lt7/a1;

    .line 121
    .line 122
    invoke-direct {v3, p2, v0, v2}, Lt7/a1;-><init>(IIF)V

    .line 123
    .line 124
    .line 125
    iput-object v3, p0, Lm8/l;->v2:Lt7/a1;

    .line 126
    .line 127
    iget-object v4, p0, Lm8/l;->c2:Lm8/i0;

    .line 128
    .line 129
    if-eqz v4, :cond_8

    .line 130
    .line 131
    iget-boolean v3, p0, Lm8/l;->E2:Z

    .line 132
    .line 133
    if-eqz v3, :cond_8

    .line 134
    .line 135
    invoke-virtual {p1}, Lt7/o;->a()Lt7/n;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    iput p2, p1, Lt7/n;->t:I

    .line 140
    .line 141
    iput v0, p1, Lt7/n;->u:I

    .line 142
    .line 143
    iput v2, p1, Lt7/n;->z:F

    .line 144
    .line 145
    new-instance v5, Lt7/o;

    .line 146
    .line 147
    invoke-direct {v5, p1}, Lt7/o;-><init>(Lt7/n;)V

    .line 148
    .line 149
    .line 150
    iget v8, p0, Lm8/l;->e2:I

    .line 151
    .line 152
    iget-object p1, p0, Lm8/l;->f2:Ljava/util/List;

    .line 153
    .line 154
    if-eqz p1, :cond_7

    .line 155
    .line 156
    :goto_4
    move-object v9, p1

    .line 157
    goto :goto_5

    .line 158
    :cond_7
    sget-object p1, Lhr/h0;->e:Lhr/f0;

    .line 159
    .line 160
    sget-object p1, Lhr/x0;->h:Lhr/x0;

    .line 161
    .line 162
    goto :goto_4

    .line 163
    :goto_5
    iget-object p1, p0, Lf8/s;->I1:Lf8/r;

    .line 164
    .line 165
    iget-wide v6, p1, Lf8/r;->b:J

    .line 166
    .line 167
    invoke-interface/range {v4 .. v9}, Lm8/i0;->u(Lt7/o;JILjava/util/List;)V

    .line 168
    .line 169
    .line 170
    const/4 p1, 0x2

    .line 171
    iput p1, p0, Lm8/l;->e2:I

    .line 172
    .line 173
    goto :goto_6

    .line 174
    :cond_8
    iget-object p2, p0, Lm8/l;->V1:Lm8/y;

    .line 175
    .line 176
    iget p1, p1, Lt7/o;->y:F

    .line 177
    .line 178
    invoke-virtual {p2, p1}, Lm8/y;->g(F)V

    .line 179
    .line 180
    .line 181
    :goto_6
    iput-boolean v1, p0, Lm8/l;->E2:Z

    .line 182
    .line 183
    return-void
.end method

.method public final d0(J)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Lf8/s;->d0(J)V

    .line 2
    .line 3
    .line 4
    iget-boolean p1, p0, Lm8/l;->y2:Z

    .line 5
    .line 6
    if-nez p1, :cond_0

    .line 7
    .line 8
    iget p1, p0, Lm8/l;->p2:I

    .line 9
    .line 10
    add-int/lit8 p1, p1, -0x1

    .line 11
    .line 12
    iput p1, p0, Lm8/l;->p2:I

    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final e0()V
    .locals 4

    .line 1
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-interface {v0}, Lm8/i0;->e()V

    .line 6
    .line 7
    .line 8
    iget-wide v0, p0, Lm8/l;->C2:J

    .line 9
    .line 10
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    cmp-long v0, v0, v2

    .line 16
    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    iget-object v0, p0, Lf8/s;->I1:Lf8/r;

    .line 20
    .line 21
    iget-wide v0, v0, Lf8/r;->b:J

    .line 22
    .line 23
    iput-wide v0, p0, Lm8/l;->C2:J

    .line 24
    .line 25
    :cond_0
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 26
    .line 27
    iget-wide v1, p0, Lm8/l;->C2:J

    .line 28
    .line 29
    neg-long v1, v1

    .line 30
    invoke-interface {v0, v1, v2}, Lm8/i0;->d(J)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    iget-object v0, p0, Lm8/l;->V1:Lm8/y;

    .line 35
    .line 36
    const/4 v1, 0x2

    .line 37
    invoke-virtual {v0, v1}, Lm8/y;->f(I)V

    .line 38
    .line 39
    .line 40
    :goto_0
    const/4 v0, 0x1

    .line 41
    iput-boolean v0, p0, Lm8/l;->E2:Z

    .line 42
    .line 43
    invoke-virtual {p0}, Lm8/l;->H0()V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final f0(Lz7/e;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lm8/l;->F2:I

    .line 3
    .line 4
    invoke-virtual {p0, p1}, Lm8/l;->M(Lz7/e;)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 9
    .line 10
    const/16 v1, 0x22

    .line 11
    .line 12
    if-lt v0, v1, :cond_0

    .line 13
    .line 14
    and-int/lit8 p1, p1, 0x20

    .line 15
    .line 16
    if-nez p1, :cond_1

    .line 17
    .line 18
    :cond_0
    iget-boolean p1, p0, Lm8/l;->y2:Z

    .line 19
    .line 20
    if-nez p1, :cond_1

    .line 21
    .line 22
    iget p1, p0, Lm8/l;->p2:I

    .line 23
    .line 24
    add-int/lit8 p1, p1, 0x1

    .line 25
    .line 26
    iput p1, p0, Lm8/l;->p2:I

    .line 27
    .line 28
    :cond_1
    return-void
.end method

.method public final h()V
    .locals 3

    .line 1
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_2

    .line 5
    .line 6
    iget v2, p0, Lm8/l;->e2:I

    .line 7
    .line 8
    if-eqz v2, :cond_1

    .line 9
    .line 10
    if-ne v2, v1, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-interface {v0}, Lm8/i0;->k()V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_1
    :goto_0
    const/4 v0, 0x0

    .line 18
    iput v0, p0, Lm8/l;->e2:I

    .line 19
    .line 20
    return-void

    .line 21
    :cond_2
    iget-object p0, p0, Lm8/l;->V1:Lm8/y;

    .line 22
    .line 23
    iget v0, p0, Lm8/y;->e:I

    .line 24
    .line 25
    if-nez v0, :cond_3

    .line 26
    .line 27
    iput v1, p0, Lm8/y;->e:I

    .line 28
    .line 29
    :cond_3
    return-void
.end method

.method public final h0(JJLf8/m;Ljava/nio/ByteBuffer;IIIJZZLt7/o;)Z
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p5

    .line 4
    .line 5
    move/from16 v3, p7

    .line 6
    .line 7
    move-wide/from16 v6, p10

    .line 8
    .line 9
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    iget-object v0, v1, Lf8/s;->I1:Lf8/r;

    .line 13
    .line 14
    iget-wide v4, v0, Lf8/r;->c:J

    .line 15
    .line 16
    sub-long v4, v6, v4

    .line 17
    .line 18
    const/4 v12, 0x0

    .line 19
    move v0, v12

    .line 20
    :goto_0
    iget-object v8, v1, Lm8/l;->Y1:Ljava/util/PriorityQueue;

    .line 21
    .line 22
    invoke-virtual {v8}, Ljava/util/PriorityQueue;->peek()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v9

    .line 26
    check-cast v9, Ljava/lang/Long;

    .line 27
    .line 28
    if-eqz v9, :cond_0

    .line 29
    .line 30
    invoke-virtual {v9}, Ljava/lang/Long;->longValue()J

    .line 31
    .line 32
    .line 33
    move-result-wide v9

    .line 34
    cmp-long v9, v9, v6

    .line 35
    .line 36
    if-gez v9, :cond_0

    .line 37
    .line 38
    add-int/lit8 v0, v0, 0x1

    .line 39
    .line 40
    invoke-virtual {v8}, Ljava/util/PriorityQueue;->poll()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    invoke-virtual {v1, v0, v12}, Lm8/l;->O0(II)V

    .line 45
    .line 46
    .line 47
    iget-object v8, v1, Lm8/l;->c2:Lm8/i0;

    .line 48
    .line 49
    const/4 v13, 0x1

    .line 50
    if-eqz v8, :cond_2

    .line 51
    .line 52
    if-eqz p12, :cond_1

    .line 53
    .line 54
    if-nez p13, :cond_1

    .line 55
    .line 56
    invoke-virtual {v1, v2, v3}, Lm8/l;->N0(Lf8/m;I)V

    .line 57
    .line 58
    .line 59
    return v13

    .line 60
    :cond_1
    new-instance v0, Lm8/h;

    .line 61
    .line 62
    invoke-direct/range {v0 .. v5}, Lm8/h;-><init>(Lm8/l;Lf8/m;IJ)V

    .line 63
    .line 64
    .line 65
    invoke-interface {v8, v6, v7, v0}, Lm8/i0;->i(JLm8/h;)Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    return v0

    .line 70
    :cond_2
    move-object v14, v1

    .line 71
    move-object v15, v2

    .line 72
    move-wide/from16 v16, v4

    .line 73
    .line 74
    iget-object v0, v14, Lf8/s;->I1:Lf8/r;

    .line 75
    .line 76
    iget-wide v0, v0, Lf8/r;->b:J

    .line 77
    .line 78
    iget-object v11, v14, Lm8/l;->W1:Li9/a;

    .line 79
    .line 80
    move-wide v7, v0

    .line 81
    iget-object v0, v14, Lm8/l;->V1:Lm8/y;

    .line 82
    .line 83
    move-wide/from16 v3, p1

    .line 84
    .line 85
    move-wide/from16 v5, p3

    .line 86
    .line 87
    move-wide/from16 v1, p10

    .line 88
    .line 89
    move/from16 v9, p12

    .line 90
    .line 91
    move/from16 v10, p13

    .line 92
    .line 93
    move/from16 p6, v12

    .line 94
    .line 95
    move/from16 v12, p7

    .line 96
    .line 97
    invoke-virtual/range {v0 .. v11}, Lm8/y;->a(JJJJZZLi9/a;)I

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    iget-object v1, v14, Lm8/l;->W1:Li9/a;

    .line 102
    .line 103
    if-eqz v0, :cond_a

    .line 104
    .line 105
    if-eq v0, v13, :cond_7

    .line 106
    .line 107
    const/4 v2, 0x2

    .line 108
    if-eq v0, v2, :cond_6

    .line 109
    .line 110
    const/4 v2, 0x3

    .line 111
    if-eq v0, v2, :cond_5

    .line 112
    .line 113
    const/4 v1, 0x4

    .line 114
    if-eq v0, v1, :cond_4

    .line 115
    .line 116
    const/4 v1, 0x5

    .line 117
    if-ne v0, v1, :cond_3

    .line 118
    .line 119
    goto :goto_1

    .line 120
    :cond_3
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 121
    .line 122
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    throw v1

    .line 130
    :cond_4
    :goto_1
    return p6

    .line 131
    :cond_5
    invoke-virtual {v14, v15, v12}, Lm8/l;->N0(Lf8/m;I)V

    .line 132
    .line 133
    .line 134
    iget-wide v0, v1, Li9/a;->a:J

    .line 135
    .line 136
    invoke-virtual {v14, v0, v1}, Lm8/l;->P0(J)V

    .line 137
    .line 138
    .line 139
    return v13

    .line 140
    :cond_6
    const-string v0, "dropVideoBuffer"

    .line 141
    .line 142
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    invoke-interface {v15, v12}, Lf8/m;->n(I)V

    .line 146
    .line 147
    .line 148
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 149
    .line 150
    .line 151
    move/from16 v0, p6

    .line 152
    .line 153
    invoke-virtual {v14, v0, v13}, Lm8/l;->O0(II)V

    .line 154
    .line 155
    .line 156
    iget-wide v0, v1, Li9/a;->a:J

    .line 157
    .line 158
    invoke-virtual {v14, v0, v1}, Lm8/l;->P0(J)V

    .line 159
    .line 160
    .line 161
    return v13

    .line 162
    :cond_7
    iget-wide v9, v1, Li9/a;->b:J

    .line 163
    .line 164
    iget-wide v0, v1, Li9/a;->a:J

    .line 165
    .line 166
    iget-wide v2, v14, Lm8/l;->u2:J

    .line 167
    .line 168
    cmp-long v2, v9, v2

    .line 169
    .line 170
    if-nez v2, :cond_8

    .line 171
    .line 172
    invoke-virtual {v14, v15, v12}, Lm8/l;->N0(Lf8/m;I)V

    .line 173
    .line 174
    .line 175
    goto :goto_3

    .line 176
    :cond_8
    iget-object v6, v14, Lm8/l;->B2:Lm8/x;

    .line 177
    .line 178
    if-eqz v6, :cond_9

    .line 179
    .line 180
    iget-object v12, v14, Lf8/s;->Q:Landroid/media/MediaFormat;

    .line 181
    .line 182
    move/from16 v3, p7

    .line 183
    .line 184
    move-object/from16 v11, p14

    .line 185
    .line 186
    move-wide/from16 v7, v16

    .line 187
    .line 188
    invoke-interface/range {v6 .. v12}, Lm8/x;->b(JJLt7/o;Landroid/media/MediaFormat;)V

    .line 189
    .line 190
    .line 191
    goto :goto_2

    .line 192
    :cond_9
    move v3, v12

    .line 193
    :goto_2
    invoke-virtual {v14, v15, v3, v9, v10}, Lm8/l;->J0(Lf8/m;IJ)V

    .line 194
    .line 195
    .line 196
    :goto_3
    invoke-virtual {v14, v0, v1}, Lm8/l;->P0(J)V

    .line 197
    .line 198
    .line 199
    iput-wide v9, v14, Lm8/l;->u2:J

    .line 200
    .line 201
    return v13

    .line 202
    :cond_a
    move v3, v12

    .line 203
    move-wide/from16 v7, v16

    .line 204
    .line 205
    iget-object v0, v14, La8/f;->j:Lw7/r;

    .line 206
    .line 207
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 208
    .line 209
    .line 210
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 211
    .line 212
    .line 213
    move-result-wide v9

    .line 214
    iget-object v6, v14, Lm8/l;->B2:Lm8/x;

    .line 215
    .line 216
    if-eqz v6, :cond_b

    .line 217
    .line 218
    iget-object v12, v14, Lf8/s;->Q:Landroid/media/MediaFormat;

    .line 219
    .line 220
    move-object/from16 v11, p14

    .line 221
    .line 222
    invoke-interface/range {v6 .. v12}, Lm8/x;->b(JJLt7/o;Landroid/media/MediaFormat;)V

    .line 223
    .line 224
    .line 225
    :cond_b
    invoke-virtual {v14, v15, v3, v9, v10}, Lm8/l;->J0(Lf8/m;IJ)V

    .line 226
    .line 227
    .line 228
    iget-wide v0, v1, Li9/a;->a:J

    .line 229
    .line 230
    invoke-virtual {v14, v0, v1}, Lm8/l;->P0(J)V

    .line 231
    .line 232
    .line 233
    return v13
.end method

.method public final k()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "MediaCodecVideoRenderer"

    .line 2
    .line 3
    return-object p0
.end method

.method public final k0()V
    .locals 0

    .line 1
    iget-object p0, p0, Lm8/l;->c2:Lm8/i0;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Lm8/i0;->e()V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public final m()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lf8/s;->D1:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-object p0, p0, Lm8/l;->c2:Lm8/i0;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-interface {p0}, Lm8/i0;->c()Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_1

    .line 14
    .line 15
    :cond_0
    const/4 p0, 0x1

    .line 16
    return p0

    .line 17
    :cond_1
    const/4 p0, 0x0

    .line 18
    return p0
.end method

.method public final m0()V
    .locals 1

    .line 1
    invoke-super {p0}, Lf8/s;->m0()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lm8/l;->Y1:Ljava/util/PriorityQueue;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/PriorityQueue;->clear()V

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    iput v0, p0, Lm8/l;->p2:I

    .line 11
    .line 12
    iput v0, p0, Lm8/l;->F2:I

    .line 13
    .line 14
    iput-boolean v0, p0, Lm8/l;->r2:Z

    .line 15
    .line 16
    return-void
.end method

.method public final o()Z
    .locals 2

    .line 1
    invoke-super {p0}, Lf8/s;->o()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Lm8/l;->c2:Lm8/i0;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-interface {v1, v0}, Lm8/i0;->g(Z)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0

    .line 14
    :cond_0
    if-eqz v0, :cond_2

    .line 15
    .line 16
    iget-object v1, p0, Lf8/s;->O:Lf8/m;

    .line 17
    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    iget-boolean v1, p0, Lm8/l;->y2:Z

    .line 21
    .line 22
    if-eqz v1, :cond_2

    .line 23
    .line 24
    :cond_1
    const/4 p0, 0x1

    .line 25
    return p0

    .line 26
    :cond_2
    iget-object p0, p0, Lm8/l;->V1:Lm8/y;

    .line 27
    .line 28
    invoke-virtual {p0, v0}, Lm8/y;->b(Z)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0
.end method

.method public final p()V
    .locals 5

    .line 1
    iget-object v0, p0, Lm8/l;->S1:Lb81/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    iput-object v1, p0, Lm8/l;->w2:Lt7/a1;

    .line 5
    .line 6
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    iput-wide v2, p0, Lm8/l;->D2:J

    .line 12
    .line 13
    invoke-virtual {p0}, Lm8/l;->H0()V

    .line 14
    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    iput-boolean v2, p0, Lm8/l;->j2:Z

    .line 18
    .line 19
    iput-object v1, p0, Lm8/l;->A2:Lm8/k;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    iput-boolean v1, p0, Lm8/l;->r2:Z

    .line 23
    .line 24
    :try_start_0
    invoke-super {p0}, Lf8/s;->p()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lf8/s;->H1:La8/g;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    monitor-enter p0

    .line 33
    monitor-exit p0

    .line 34
    iget-object v1, v0, Lb81/b;->e:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v1, Landroid/os/Handler;

    .line 37
    .line 38
    if-eqz v1, :cond_0

    .line 39
    .line 40
    new-instance v2, Lh0/h0;

    .line 41
    .line 42
    const/16 v3, 0x15

    .line 43
    .line 44
    invoke-direct {v2, v3, v0, p0}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 48
    .line 49
    .line 50
    :cond_0
    sget-object p0, Lt7/a1;->d:Lt7/a1;

    .line 51
    .line 52
    invoke-virtual {v0, p0}, Lb81/b;->A(Lt7/a1;)V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :catchall_0
    move-exception v1

    .line 57
    iget-object p0, p0, Lf8/s;->H1:La8/g;

    .line 58
    .line 59
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 60
    .line 61
    .line 62
    monitor-enter p0

    .line 63
    monitor-exit p0

    .line 64
    iget-object v2, v0, Lb81/b;->e:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v2, Landroid/os/Handler;

    .line 67
    .line 68
    if-eqz v2, :cond_1

    .line 69
    .line 70
    new-instance v3, Lh0/h0;

    .line 71
    .line 72
    const/16 v4, 0x15

    .line 73
    .line 74
    invoke-direct {v3, v4, v0, p0}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v2, v3}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 78
    .line 79
    .line 80
    :cond_1
    sget-object p0, Lt7/a1;->d:Lt7/a1;

    .line 81
    .line 82
    invoke-virtual {v0, p0}, Lb81/b;->A(Lt7/a1;)V

    .line 83
    .line 84
    .line 85
    throw v1
.end method

.method public final q(ZZ)V
    .locals 6

    .line 1
    new-instance p1, La8/g;

    .line 2
    .line 3
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lf8/s;->H1:La8/g;

    .line 7
    .line 8
    iget-object p1, p0, La8/f;->g:La8/o1;

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    iget-boolean p1, p1, La8/o1;->b:Z

    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    const/4 v1, 0x1

    .line 17
    if-eqz p1, :cond_1

    .line 18
    .line 19
    iget v2, p0, Lm8/l;->z2:I

    .line 20
    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v2, v0

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    :goto_0
    move v2, v1

    .line 27
    :goto_1
    invoke-static {v2}, Lw7/a;->j(Z)V

    .line 28
    .line 29
    .line 30
    iget-boolean v2, p0, Lm8/l;->y2:Z

    .line 31
    .line 32
    if-eq v2, p1, :cond_2

    .line 33
    .line 34
    iput-boolean p1, p0, Lm8/l;->y2:Z

    .line 35
    .line 36
    invoke-virtual {p0}, Lf8/s;->j0()V

    .line 37
    .line 38
    .line 39
    :cond_2
    iget-object p1, p0, Lf8/s;->H1:La8/g;

    .line 40
    .line 41
    iget-object v2, p0, Lm8/l;->S1:Lb81/b;

    .line 42
    .line 43
    iget-object v3, v2, Lb81/b;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v3, Landroid/os/Handler;

    .line 46
    .line 47
    if-eqz v3, :cond_3

    .line 48
    .line 49
    new-instance v4, Lm8/e0;

    .line 50
    .line 51
    const/4 v5, 0x5

    .line 52
    invoke-direct {v4, v2, p1, v5}, Lm8/e0;-><init>(Lb81/b;Ljava/lang/Object;I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v3, v4}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 56
    .line 57
    .line 58
    :cond_3
    iget-boolean p1, p0, Lm8/l;->d2:Z

    .line 59
    .line 60
    iget-object v2, p0, Lm8/l;->V1:Lm8/y;

    .line 61
    .line 62
    if-nez p1, :cond_7

    .line 63
    .line 64
    iget-object p1, p0, Lm8/l;->f2:Ljava/util/List;

    .line 65
    .line 66
    if-eqz p1, :cond_6

    .line 67
    .line 68
    iget-object p1, p0, Lm8/l;->c2:Lm8/i0;

    .line 69
    .line 70
    if-nez p1, :cond_6

    .line 71
    .line 72
    new-instance p1, La8/l;

    .line 73
    .line 74
    iget-object v3, p0, Lm8/l;->Q1:Landroid/content/Context;

    .line 75
    .line 76
    invoke-direct {p1, v3, v2}, La8/l;-><init>(Landroid/content/Context;Lm8/y;)V

    .line 77
    .line 78
    .line 79
    iput-boolean v1, p1, La8/l;->d:Z

    .line 80
    .line 81
    iget-object v3, p0, La8/f;->j:Lw7/r;

    .line 82
    .line 83
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    iput-object v3, p1, La8/l;->i:Ljava/lang/Object;

    .line 87
    .line 88
    iget-boolean v3, p1, La8/l;->e:Z

    .line 89
    .line 90
    xor-int/2addr v3, v1

    .line 91
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 92
    .line 93
    .line 94
    iget-object v3, p1, La8/l;->h:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v3, Lm8/r;

    .line 97
    .line 98
    if-nez v3, :cond_4

    .line 99
    .line 100
    new-instance v3, Lm8/r;

    .line 101
    .line 102
    invoke-direct {v3}, Lm8/r;-><init>()V

    .line 103
    .line 104
    .line 105
    iput-object v3, p1, La8/l;->h:Ljava/lang/Object;

    .line 106
    .line 107
    :cond_4
    new-instance v3, Lm8/t;

    .line 108
    .line 109
    invoke-direct {v3, p1}, Lm8/t;-><init>(La8/l;)V

    .line 110
    .line 111
    .line 112
    iput-boolean v1, p1, La8/l;->e:Z

    .line 113
    .line 114
    iput v1, v3, Lm8/t;->n:I

    .line 115
    .line 116
    iget-object p1, v3, Lm8/t;->c:Landroid/util/SparseArray;

    .line 117
    .line 118
    invoke-static {p1, v0}, Lw7/w;->i(Landroid/util/SparseArray;I)Z

    .line 119
    .line 120
    .line 121
    move-result v4

    .line 122
    if-eqz v4, :cond_5

    .line 123
    .line 124
    invoke-virtual {p1, v0}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    check-cast p1, Lm8/i0;

    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_5
    new-instance v4, Lm8/p;

    .line 132
    .line 133
    iget-object v5, v3, Lm8/t;->a:Landroid/content/Context;

    .line 134
    .line 135
    invoke-direct {v4, v3, v5}, Lm8/p;-><init>(Lm8/t;Landroid/content/Context;)V

    .line 136
    .line 137
    .line 138
    iget-object v3, v3, Lm8/t;->g:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 139
    .line 140
    invoke-virtual {v3, v4}, Ljava/util/concurrent/CopyOnWriteArraySet;->add(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    invoke-virtual {p1, v0, v4}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    move-object p1, v4

    .line 147
    :goto_2
    iput-object p1, p0, Lm8/l;->c2:Lm8/i0;

    .line 148
    .line 149
    :cond_6
    iput-boolean v1, p0, Lm8/l;->d2:Z

    .line 150
    .line 151
    :cond_7
    iget-object p1, p0, Lm8/l;->c2:Lm8/i0;

    .line 152
    .line 153
    if-eqz p1, :cond_b

    .line 154
    .line 155
    new-instance v0, Lm8/g;

    .line 156
    .line 157
    invoke-direct {v0, p0}, Lm8/g;-><init>(Lm8/l;)V

    .line 158
    .line 159
    .line 160
    invoke-interface {p1, v0}, Lm8/i0;->x(Lm8/g;)V

    .line 161
    .line 162
    .line 163
    iget-object p1, p0, Lm8/l;->B2:Lm8/x;

    .line 164
    .line 165
    if-eqz p1, :cond_8

    .line 166
    .line 167
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 168
    .line 169
    invoke-interface {v0, p1}, Lm8/i0;->n(Lm8/x;)V

    .line 170
    .line 171
    .line 172
    :cond_8
    iget-object p1, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 173
    .line 174
    if-eqz p1, :cond_9

    .line 175
    .line 176
    iget-object p1, p0, Lm8/l;->i2:Lw7/q;

    .line 177
    .line 178
    sget-object v0, Lw7/q;->c:Lw7/q;

    .line 179
    .line 180
    invoke-virtual {p1, v0}, Lw7/q;->equals(Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result p1

    .line 184
    if-nez p1, :cond_9

    .line 185
    .line 186
    iget-object p1, p0, Lm8/l;->c2:Lm8/i0;

    .line 187
    .line 188
    iget-object v0, p0, Lm8/l;->g2:Landroid/view/Surface;

    .line 189
    .line 190
    iget-object v2, p0, Lm8/l;->i2:Lw7/q;

    .line 191
    .line 192
    invoke-interface {p1, v0, v2}, Lm8/i0;->s(Landroid/view/Surface;Lw7/q;)V

    .line 193
    .line 194
    .line 195
    :cond_9
    iget-object p1, p0, Lm8/l;->c2:Lm8/i0;

    .line 196
    .line 197
    iget v0, p0, Lm8/l;->l2:I

    .line 198
    .line 199
    invoke-interface {p1, v0}, Lm8/i0;->p(I)V

    .line 200
    .line 201
    .line 202
    iget-object p1, p0, Lm8/l;->c2:Lm8/i0;

    .line 203
    .line 204
    iget v0, p0, Lf8/s;->M:F

    .line 205
    .line 206
    invoke-interface {p1, v0}, Lm8/i0;->q(F)V

    .line 207
    .line 208
    .line 209
    iget-object p1, p0, Lm8/l;->f2:Ljava/util/List;

    .line 210
    .line 211
    if-eqz p1, :cond_a

    .line 212
    .line 213
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 214
    .line 215
    invoke-interface {v0, p1}, Lm8/i0;->f(Ljava/util/List;)V

    .line 216
    .line 217
    .line 218
    :cond_a
    xor-int/lit8 p1, p2, 0x1

    .line 219
    .line 220
    iput p1, p0, Lm8/l;->e2:I

    .line 221
    .line 222
    iput-boolean v1, p0, Lf8/s;->L1:Z

    .line 223
    .line 224
    return-void

    .line 225
    :cond_b
    iget-object p0, p0, La8/f;->j:Lw7/r;

    .line 226
    .line 227
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 228
    .line 229
    .line 230
    iput-object p0, v2, Lm8/y;->l:Lw7/r;

    .line 231
    .line 232
    xor-int/lit8 p0, p2, 0x1

    .line 233
    .line 234
    invoke-virtual {v2, p0}, Lm8/y;->f(I)V

    .line 235
    .line 236
    .line 237
    return-void
.end method

.method public final q0(Lz7/e;)Z
    .locals 6

    .line 1
    invoke-virtual {p0, p1}, Lm8/l;->F0(Lz7/e;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    goto :goto_1

    .line 9
    :cond_0
    iget-wide v2, p1, Lz7/e;->j:J

    .line 10
    .line 11
    iget-wide v4, p0, La8/f;->o:J

    .line 12
    .line 13
    cmp-long v0, v2, v4

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    if-gez v0, :cond_1

    .line 17
    .line 18
    move v0, v2

    .line 19
    goto :goto_0

    .line 20
    :cond_1
    move v0, v1

    .line 21
    :goto_0
    if-nez v0, :cond_2

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_2
    const/high16 v3, 0x10000000

    .line 25
    .line 26
    invoke-virtual {p1, v3}, Lkq/d;->c(I)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-eqz v3, :cond_3

    .line 31
    .line 32
    :goto_1
    return v1

    .line 33
    :cond_3
    const/high16 v3, 0x4000000

    .line 34
    .line 35
    invoke-virtual {p1, v3}, Lkq/d;->c(I)Z

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    if-eqz v3, :cond_4

    .line 40
    .line 41
    invoke-virtual {p1}, Lz7/e;->m()V

    .line 42
    .line 43
    .line 44
    move v1, v2

    .line 45
    :cond_4
    if-eqz v1, :cond_6

    .line 46
    .line 47
    if-eqz v0, :cond_5

    .line 48
    .line 49
    iget-object p0, p0, Lf8/s;->H1:La8/g;

    .line 50
    .line 51
    iget p1, p0, La8/g;->d:I

    .line 52
    .line 53
    add-int/2addr p1, v2

    .line 54
    iput p1, p0, La8/g;->d:I

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_5
    iget-wide v3, p1, Lz7/e;->j:J

    .line 58
    .line 59
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    iget-object v0, p0, Lm8/l;->Y1:Ljava/util/PriorityQueue;

    .line 64
    .line 65
    invoke-virtual {v0, p1}, Ljava/util/PriorityQueue;->add(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    iget p1, p0, Lm8/l;->F2:I

    .line 69
    .line 70
    add-int/2addr p1, v2

    .line 71
    iput p1, p0, Lm8/l;->F2:I

    .line 72
    .line 73
    :cond_6
    :goto_2
    return v1
.end method

.method public final r(JZ)V
    .locals 4

    .line 1
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    if-nez p3, :cond_0

    .line 7
    .line 8
    invoke-interface {v0, v1}, Lm8/i0;->t(Z)V

    .line 9
    .line 10
    .line 11
    :cond_0
    invoke-super {p0, p1, p2, p3}, Lf8/s;->r(JZ)V

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lm8/l;->c2:Lm8/i0;

    .line 15
    .line 16
    iget-object p2, p0, Lm8/l;->V1:Lm8/y;

    .line 17
    .line 18
    if-nez p1, :cond_1

    .line 19
    .line 20
    iget-object p1, p2, Lm8/y;->b:Lm8/c0;

    .line 21
    .line 22
    const-wide/16 v2, 0x0

    .line 23
    .line 24
    iput-wide v2, p1, Lm8/c0;->m:J

    .line 25
    .line 26
    const-wide/16 v2, -0x1

    .line 27
    .line 28
    iput-wide v2, p1, Lm8/c0;->p:J

    .line 29
    .line 30
    iput-wide v2, p1, Lm8/c0;->n:J

    .line 31
    .line 32
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    iput-wide v2, p2, Lm8/y;->h:J

    .line 38
    .line 39
    iput-wide v2, p2, Lm8/y;->f:J

    .line 40
    .line 41
    iget p1, p2, Lm8/y;->e:I

    .line 42
    .line 43
    invoke-static {p1, v1}, Ljava/lang/Math;->min(II)I

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    iput p1, p2, Lm8/y;->e:I

    .line 48
    .line 49
    iput-wide v2, p2, Lm8/y;->i:J

    .line 50
    .line 51
    :cond_1
    const/4 p1, 0x0

    .line 52
    if-eqz p3, :cond_3

    .line 53
    .line 54
    iget-object p3, p0, Lm8/l;->c2:Lm8/i0;

    .line 55
    .line 56
    if-eqz p3, :cond_2

    .line 57
    .line 58
    invoke-interface {p3, p1}, Lm8/i0;->w(Z)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    invoke-virtual {p2, p1}, Lm8/y;->c(Z)V

    .line 63
    .line 64
    .line 65
    :cond_3
    :goto_0
    invoke-virtual {p0}, Lm8/l;->H0()V

    .line 66
    .line 67
    .line 68
    iput p1, p0, Lm8/l;->o2:I

    .line 69
    .line 70
    return-void
.end method

.method public final r0()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lf8/s;->P:Lt7/o;

    .line 2
    .line 3
    iget-object v1, p0, Lm8/l;->q2:La8/q1;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget-boolean v1, p0, Lm8/l;->r2:Z

    .line 9
    .line 10
    if-nez v1, :cond_3

    .line 11
    .line 12
    iget-boolean v1, p0, Lm8/l;->y2:Z

    .line 13
    .line 14
    if-nez v1, :cond_3

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    iget v0, v0, Lt7/o;->p:I

    .line 19
    .line 20
    if-gtz v0, :cond_3

    .line 21
    .line 22
    :cond_1
    iget-boolean v0, p0, Lf8/s;->M1:Z

    .line 23
    .line 24
    if-nez v0, :cond_3

    .line 25
    .line 26
    iget-wide v0, p0, Lf8/s;->B1:J

    .line 27
    .line 28
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    cmp-long p0, v0, v2

    .line 34
    .line 35
    if-eqz p0, :cond_2

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    const/4 p0, 0x0

    .line 39
    return p0

    .line 40
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 41
    return p0
.end method

.method public final s()V
    .locals 1

    .line 1
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean p0, p0, Lm8/l;->R1:Z

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-interface {v0}, Lm8/i0;->b()V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final s0(Lf8/p;)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lm8/l;->E0(Lf8/p;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final t()V
    .locals 6

    .line 1
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x0

    .line 8
    :try_start_0
    iput-boolean v2, p0, Lf8/s;->q1:Z

    .line 9
    .line 10
    invoke-virtual {p0}, Lf8/s;->l0()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Lf8/s;->j0()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 14
    .line 15
    .line 16
    :try_start_1
    iget-object v4, p0, Lf8/s;->I:Laq/a;

    .line 17
    .line 18
    if-nez v4, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    invoke-virtual {v4, v3}, Laq/a;->E(Ld8/f;)V

    .line 22
    .line 23
    .line 24
    :goto_0
    iput-object v3, p0, Lf8/s;->I:Laq/a;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 25
    .line 26
    iput-boolean v2, p0, Lm8/l;->d2:Z

    .line 27
    .line 28
    iput-wide v0, p0, Lm8/l;->C2:J

    .line 29
    .line 30
    iget-object v0, p0, Lm8/l;->h2:Lm8/n;

    .line 31
    .line 32
    if-eqz v0, :cond_1

    .line 33
    .line 34
    invoke-virtual {v0}, Lm8/n;->release()V

    .line 35
    .line 36
    .line 37
    iput-object v3, p0, Lm8/l;->h2:Lm8/n;

    .line 38
    .line 39
    :cond_1
    return-void

    .line 40
    :catchall_0
    move-exception v4

    .line 41
    goto :goto_1

    .line 42
    :catchall_1
    move-exception v4

    .line 43
    :try_start_2
    iget-object v5, p0, Lf8/s;->I:Laq/a;

    .line 44
    .line 45
    if-eqz v5, :cond_2

    .line 46
    .line 47
    invoke-virtual {v5, v3}, Laq/a;->E(Ld8/f;)V

    .line 48
    .line 49
    .line 50
    :cond_2
    iput-object v3, p0, Lf8/s;->I:Laq/a;

    .line 51
    .line 52
    throw v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 53
    :goto_1
    iput-boolean v2, p0, Lm8/l;->d2:Z

    .line 54
    .line 55
    iput-wide v0, p0, Lm8/l;->C2:J

    .line 56
    .line 57
    iget-object v0, p0, Lm8/l;->h2:Lm8/n;

    .line 58
    .line 59
    if-eqz v0, :cond_3

    .line 60
    .line 61
    invoke-virtual {v0}, Lm8/n;->release()V

    .line 62
    .line 63
    .line 64
    iput-object v3, p0, Lm8/l;->h2:Lm8/n;

    .line 65
    .line 66
    :cond_3
    throw v4
.end method

.method public final t0()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lf8/s;->V:Lf8/p;

    .line 2
    .line 3
    iget-object v1, p0, Lm8/l;->c2:Lm8/i0;

    .line 4
    .line 5
    if-eqz v1, :cond_1

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iget-object v0, v0, Lf8/p;->a:Ljava/lang/String;

    .line 10
    .line 11
    const-string v1, "c2.mtk.avc.decoder"

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    const-string v1, "c2.mtk.hevc.decoder"

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    :cond_0
    const/4 p0, 0x1

    .line 28
    return p0

    .line 29
    :cond_1
    invoke-super {p0}, Lf8/s;->t0()Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    return p0
.end method

.method public final u()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lm8/l;->n2:I

    .line 3
    .line 4
    iget-object v1, p0, La8/f;->j:Lw7/r;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 10
    .line 11
    .line 12
    move-result-wide v1

    .line 13
    iput-wide v1, p0, Lm8/l;->m2:J

    .line 14
    .line 15
    const-wide/16 v1, 0x0

    .line 16
    .line 17
    iput-wide v1, p0, Lm8/l;->s2:J

    .line 18
    .line 19
    iput v0, p0, Lm8/l;->t2:I

    .line 20
    .line 21
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    invoke-interface {v0}, Lm8/i0;->o()V

    .line 26
    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    iget-object p0, p0, Lm8/l;->V1:Lm8/y;

    .line 30
    .line 31
    invoke-virtual {p0}, Lm8/y;->d()V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final v()V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lm8/l;->G0()V

    .line 2
    .line 3
    .line 4
    iget v0, p0, Lm8/l;->t2:I

    .line 5
    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    iget-wide v1, p0, Lm8/l;->s2:J

    .line 9
    .line 10
    iget-object v3, p0, Lm8/l;->S1:Lb81/b;

    .line 11
    .line 12
    iget-object v4, v3, Lb81/b;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v4, Landroid/os/Handler;

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    new-instance v5, Lm8/e0;

    .line 19
    .line 20
    invoke-direct {v5, v3, v1, v2, v0}, Lm8/e0;-><init>(Lb81/b;JI)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v4, v5}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 24
    .line 25
    .line 26
    :cond_0
    const-wide/16 v0, 0x0

    .line 27
    .line 28
    iput-wide v0, p0, Lm8/l;->s2:J

    .line 29
    .line 30
    const/4 v0, 0x0

    .line 31
    iput v0, p0, Lm8/l;->t2:I

    .line 32
    .line 33
    :cond_1
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 34
    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    invoke-interface {v0}, Lm8/i0;->m()V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    iget-object p0, p0, Lm8/l;->V1:Lm8/y;

    .line 42
    .line 43
    invoke-virtual {p0}, Lm8/y;->e()V

    .line 44
    .line 45
    .line 46
    :goto_0
    return-void
.end method

.method public final v0(Lf8/k;Lt7/o;)I
    .locals 11

    .line 1
    iget-object v0, p2, Lt7/o;->n:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {v0}, Lt7/d0;->l(Ljava/lang/String;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    invoke-static {v1, v1, v1, v1}, La8/f;->f(IIII)I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :cond_0
    iget-object v0, p2, Lt7/o;->r:Lt7/k;

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_1
    move v0, v1

    .line 23
    :goto_0
    iget-object p0, p0, Lm8/l;->Q1:Landroid/content/Context;

    .line 24
    .line 25
    invoke-static {p0, p1, p2, v0, v1}, Lm8/l;->B0(Landroid/content/Context;Lf8/k;Lt7/o;ZZ)Ljava/util/List;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    if-eqz v0, :cond_2

    .line 30
    .line 31
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-eqz v4, :cond_2

    .line 36
    .line 37
    invoke-static {p0, p1, p2, v1, v1}, Lm8/l;->B0(Landroid/content/Context;Lf8/k;Lt7/o;ZZ)Ljava/util/List;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    :cond_2
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 42
    .line 43
    .line 44
    move-result v4

    .line 45
    if-eqz v4, :cond_3

    .line 46
    .line 47
    invoke-static {v2, v1, v1, v1}, La8/f;->f(IIII)I

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    return p0

    .line 52
    :cond_3
    iget v4, p2, Lt7/o;->O:I

    .line 53
    .line 54
    const/4 v5, 0x2

    .line 55
    if-eqz v4, :cond_5

    .line 56
    .line 57
    if-ne v4, v5, :cond_4

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_4
    invoke-static {v5, v1, v1, v1}, La8/f;->f(IIII)I

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    return p0

    .line 65
    :cond_5
    :goto_1
    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    check-cast v4, Lf8/p;

    .line 70
    .line 71
    invoke-virtual {v4, p2}, Lf8/p;->e(Lt7/o;)Z

    .line 72
    .line 73
    .line 74
    move-result v6

    .line 75
    if-nez v6, :cond_7

    .line 76
    .line 77
    move v7, v2

    .line 78
    :goto_2
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 79
    .line 80
    .line 81
    move-result v8

    .line 82
    if-ge v7, v8, :cond_7

    .line 83
    .line 84
    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v8

    .line 88
    check-cast v8, Lf8/p;

    .line 89
    .line 90
    invoke-virtual {v8, p2}, Lf8/p;->e(Lt7/o;)Z

    .line 91
    .line 92
    .line 93
    move-result v9

    .line 94
    if-eqz v9, :cond_6

    .line 95
    .line 96
    move v3, v1

    .line 97
    move v6, v2

    .line 98
    move-object v4, v8

    .line 99
    goto :goto_3

    .line 100
    :cond_6
    add-int/lit8 v7, v7, 0x1

    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_7
    move v3, v2

    .line 104
    :goto_3
    if-eqz v6, :cond_8

    .line 105
    .line 106
    const/4 v7, 0x4

    .line 107
    goto :goto_4

    .line 108
    :cond_8
    const/4 v7, 0x3

    .line 109
    :goto_4
    invoke-virtual {v4, p2}, Lf8/p;->f(Lt7/o;)Z

    .line 110
    .line 111
    .line 112
    move-result v8

    .line 113
    if-eqz v8, :cond_9

    .line 114
    .line 115
    const/16 v8, 0x10

    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_9
    const/16 v8, 0x8

    .line 119
    .line 120
    :goto_5
    iget-boolean v4, v4, Lf8/p;->g:Z

    .line 121
    .line 122
    if-eqz v4, :cond_a

    .line 123
    .line 124
    const/16 v4, 0x40

    .line 125
    .line 126
    goto :goto_6

    .line 127
    :cond_a
    move v4, v1

    .line 128
    :goto_6
    if-eqz v3, :cond_b

    .line 129
    .line 130
    const/16 v3, 0x80

    .line 131
    .line 132
    goto :goto_7

    .line 133
    :cond_b
    move v3, v1

    .line 134
    :goto_7
    const-string v9, "video/dolby-vision"

    .line 135
    .line 136
    iget-object v10, p2, Lt7/o;->n:Ljava/lang/String;

    .line 137
    .line 138
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v9

    .line 142
    if-eqz v9, :cond_c

    .line 143
    .line 144
    invoke-static {p0}, Ljp/t0;->b(Landroid/content/Context;)Z

    .line 145
    .line 146
    .line 147
    move-result v9

    .line 148
    if-nez v9, :cond_c

    .line 149
    .line 150
    const/16 v3, 0x100

    .line 151
    .line 152
    :cond_c
    if-eqz v6, :cond_d

    .line 153
    .line 154
    invoke-static {p0, p1, p2, v0, v2}, Lm8/l;->B0(Landroid/content/Context;Lf8/k;Lt7/o;ZZ)Ljava/util/List;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 159
    .line 160
    .line 161
    move-result p1

    .line 162
    if-nez p1, :cond_d

    .line 163
    .line 164
    sget-object p1, Lf8/w;->a:Ljava/util/HashMap;

    .line 165
    .line 166
    new-instance p1, Ljava/util/ArrayList;

    .line 167
    .line 168
    invoke-direct {p1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 169
    .line 170
    .line 171
    new-instance p0, La8/t;

    .line 172
    .line 173
    const/16 v0, 0x19

    .line 174
    .line 175
    invoke-direct {p0, p2, v0}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 176
    .line 177
    .line 178
    new-instance v0, Ld4/a0;

    .line 179
    .line 180
    invoke-direct {v0, p0, v5}, Ld4/a0;-><init>(Ljava/lang/Object;I)V

    .line 181
    .line 182
    .line 183
    invoke-static {p1, v0}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    check-cast p0, Lf8/p;

    .line 191
    .line 192
    invoke-virtual {p0, p2}, Lf8/p;->e(Lt7/o;)Z

    .line 193
    .line 194
    .line 195
    move-result p1

    .line 196
    if-eqz p1, :cond_d

    .line 197
    .line 198
    invoke-virtual {p0, p2}, Lf8/p;->f(Lt7/o;)Z

    .line 199
    .line 200
    .line 201
    move-result p0

    .line 202
    if-eqz p0, :cond_d

    .line 203
    .line 204
    const/16 v1, 0x20

    .line 205
    .line 206
    :cond_d
    or-int p0, v7, v8

    .line 207
    .line 208
    or-int/2addr p0, v1

    .line 209
    or-int/2addr p0, v4

    .line 210
    or-int/2addr p0, v3

    .line 211
    return p0
.end method

.method public final w([Lt7/o;JJLh8/b0;)V
    .locals 0

    .line 1
    invoke-super/range {p0 .. p6}, Lf8/s;->w([Lt7/o;JJLh8/b0;)V

    .line 2
    .line 3
    .line 4
    iget-object p1, p0, La8/f;->s:Lt7/p0;

    .line 5
    .line 6
    invoke-virtual {p1}, Lt7/p0;->p()Z

    .line 7
    .line 8
    .line 9
    move-result p2

    .line 10
    if-eqz p2, :cond_0

    .line 11
    .line 12
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 13
    .line 14
    .line 15
    .line 16
    .line 17
    iput-wide p1, p0, Lm8/l;->D2:J

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    invoke-virtual {p6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    iget-object p2, p6, Lh8/b0;->a:Ljava/lang/Object;

    .line 24
    .line 25
    new-instance p3, Lt7/n0;

    .line 26
    .line 27
    invoke-direct {p3}, Lt7/n0;-><init>()V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p1, p2, p3}, Lt7/p0;->g(Ljava/lang/Object;Lt7/n0;)Lt7/n0;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iget-wide p1, p1, Lt7/n0;->d:J

    .line 35
    .line 36
    iput-wide p1, p0, Lm8/l;->D2:J

    .line 37
    .line 38
    :goto_0
    return-void
.end method

.method public final y(JJ)V
    .locals 1

    .line 1
    iget-object v0, p0, Lm8/l;->c2:Lm8/i0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    :try_start_0
    invoke-interface {v0, p1, p2, p3, p4}, Lm8/i0;->v(JJ)V
    :try_end_0
    .catch Lm8/h0; {:try_start_0 .. :try_end_0} :catch_0

    .line 6
    .line 7
    .line 8
    goto :goto_0

    .line 9
    :catch_0
    move-exception p1

    .line 10
    const/16 p2, 0x1b59

    .line 11
    .line 12
    const/4 p3, 0x0

    .line 13
    iget-object p4, p1, Lm8/h0;->d:Lt7/o;

    .line 14
    .line 15
    invoke-virtual {p0, p1, p4, p3, p2}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    throw p0

    .line 20
    :cond_0
    :goto_0
    invoke-super {p0, p1, p2, p3, p4}, Lf8/s;->y(JJ)V

    .line 21
    .line 22
    .line 23
    return-void
.end method
