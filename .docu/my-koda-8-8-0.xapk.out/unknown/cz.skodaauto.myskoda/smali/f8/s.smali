.class public abstract Lf8/s;
.super La8/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final P1:[B


# instance fields
.field public final A:Lz7/e;

.field public A1:J

.field public final B:Lf8/i;

.field public B1:J

.field public final C:Landroid/media/MediaCodec$BufferInfo;

.field public C1:Z

.field public final D:Ljava/util/ArrayDeque;

.field public D1:Z

.field public final E:Lc8/b0;

.field public E1:Z

.field public F:Lt7/o;

.field public F1:Z

.field public G:Lt7/o;

.field public G1:La8/o;

.field public H:Laq/a;

.field public H1:La8/g;

.field public I:Laq/a;

.field public I1:Lf8/r;

.field public J:La8/l0;

.field public J1:J

.field public K:Landroid/media/MediaCrypto;

.field public K1:Z

.field public final L:J

.field public L1:Z

.field public M:F

.field public M1:Z

.field public N:F

.field public N1:J

.field public O:Lf8/m;

.field public O1:J

.field public P:Lt7/o;

.field public Q:Landroid/media/MediaFormat;

.field public R:Z

.field public S:F

.field public T:Ljava/util/ArrayDeque;

.field public U:Lf8/q;

.field public V:Lf8/p;

.field public W:Z

.field public X:Z

.field public Y:Z

.field public Z:Z

.field public a0:J

.field public b0:J

.field public c0:I

.field public d0:I

.field public e0:Ljava/nio/ByteBuffer;

.field public f0:Z

.field public g0:Z

.field public q1:Z

.field public r1:Z

.field public s1:Z

.field public t1:Z

.field public u1:I

.field public final v:Lf8/l;

.field public v1:I

.field public final w:Lf8/k;

.field public w1:I

.field public final x:F

.field public x1:Z

.field public final y:Lz7/e;

.field public y1:Z

.field public final z:Lz7/e;

.field public z1:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x26

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v0, Lf8/s;->P1:[B

    .line 9
    .line 10
    return-void

    .line 11
    :array_0
    .array-data 1
        0x0t
        0x0t
        0x1t
        0x67t
        0x42t
        -0x40t
        0xbt
        -0x26t
        0x25t
        -0x70t
        0x0t
        0x0t
        0x1t
        0x68t
        -0x32t
        0xft
        0x13t
        0x20t
        0x0t
        0x0t
        0x1t
        0x65t
        -0x78t
        -0x7ct
        0xdt
        -0x32t
        0x71t
        0x18t
        -0x60t
        0x0t
        0x2ft
        -0x41t
        0x1ct
        0x31t
        -0x3dt
        0x27t
        0x5dt
        0x78t
    .end array-data
.end method

.method public constructor <init>(ILf8/l;F)V
    .locals 3

    .line 1
    sget-object v0, Lf8/k;->e:Lf8/k;

    .line 2
    .line 3
    invoke-direct {p0, p1}, La8/f;-><init>(I)V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lf8/s;->v:Lf8/l;

    .line 7
    .line 8
    iput-object v0, p0, Lf8/s;->w:Lf8/k;

    .line 9
    .line 10
    iput p3, p0, Lf8/s;->x:F

    .line 11
    .line 12
    new-instance p1, Lz7/e;

    .line 13
    .line 14
    const/4 p2, 0x0

    .line 15
    invoke-direct {p1, p2}, Lz7/e;-><init>(I)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lf8/s;->y:Lz7/e;

    .line 19
    .line 20
    new-instance p1, Lz7/e;

    .line 21
    .line 22
    invoke-direct {p1, p2}, Lz7/e;-><init>(I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lf8/s;->z:Lz7/e;

    .line 26
    .line 27
    new-instance p1, Lz7/e;

    .line 28
    .line 29
    const/4 p3, 0x2

    .line 30
    invoke-direct {p1, p3}, Lz7/e;-><init>(I)V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lf8/s;->A:Lz7/e;

    .line 34
    .line 35
    new-instance p1, Lf8/i;

    .line 36
    .line 37
    invoke-direct {p1, p3}, Lz7/e;-><init>(I)V

    .line 38
    .line 39
    .line 40
    const/16 v0, 0x20

    .line 41
    .line 42
    iput v0, p1, Lf8/i;->o:I

    .line 43
    .line 44
    iput-object p1, p0, Lf8/s;->B:Lf8/i;

    .line 45
    .line 46
    new-instance v0, Landroid/media/MediaCodec$BufferInfo;

    .line 47
    .line 48
    invoke-direct {v0}, Landroid/media/MediaCodec$BufferInfo;-><init>()V

    .line 49
    .line 50
    .line 51
    iput-object v0, p0, Lf8/s;->C:Landroid/media/MediaCodec$BufferInfo;

    .line 52
    .line 53
    const/high16 v0, 0x3f800000    # 1.0f

    .line 54
    .line 55
    iput v0, p0, Lf8/s;->M:F

    .line 56
    .line 57
    iput v0, p0, Lf8/s;->N:F

    .line 58
    .line 59
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 60
    .line 61
    .line 62
    .line 63
    .line 64
    iput-wide v0, p0, Lf8/s;->L:J

    .line 65
    .line 66
    new-instance v2, Ljava/util/ArrayDeque;

    .line 67
    .line 68
    invoke-direct {v2}, Ljava/util/ArrayDeque;-><init>()V

    .line 69
    .line 70
    .line 71
    iput-object v2, p0, Lf8/s;->D:Ljava/util/ArrayDeque;

    .line 72
    .line 73
    sget-object v2, Lf8/r;->e:Lf8/r;

    .line 74
    .line 75
    iput-object v2, p0, Lf8/s;->I1:Lf8/r;

    .line 76
    .line 77
    invoke-virtual {p1, p2}, Lz7/e;->o(I)V

    .line 78
    .line 79
    .line 80
    iget-object p1, p1, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 81
    .line 82
    invoke-static {}, Ljava/nio/ByteOrder;->nativeOrder()Ljava/nio/ByteOrder;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    invoke-virtual {p1, v2}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 87
    .line 88
    .line 89
    new-instance p1, Lc8/b0;

    .line 90
    .line 91
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 92
    .line 93
    .line 94
    sget-object v2, Lu7/f;->a:Ljava/nio/ByteBuffer;

    .line 95
    .line 96
    iput-object v2, p1, Lc8/b0;->a:Ljava/nio/ByteBuffer;

    .line 97
    .line 98
    iput p2, p1, Lc8/b0;->c:I

    .line 99
    .line 100
    iput p3, p1, Lc8/b0;->b:I

    .line 101
    .line 102
    iput-object p1, p0, Lf8/s;->E:Lc8/b0;

    .line 103
    .line 104
    const/high16 p1, -0x40800000    # -1.0f

    .line 105
    .line 106
    iput p1, p0, Lf8/s;->S:F

    .line 107
    .line 108
    iput p2, p0, Lf8/s;->u1:I

    .line 109
    .line 110
    const/4 p1, -0x1

    .line 111
    iput p1, p0, Lf8/s;->c0:I

    .line 112
    .line 113
    iput p1, p0, Lf8/s;->d0:I

    .line 114
    .line 115
    iput-wide v0, p0, Lf8/s;->b0:J

    .line 116
    .line 117
    iput-wide v0, p0, Lf8/s;->A1:J

    .line 118
    .line 119
    iput-wide v0, p0, Lf8/s;->B1:J

    .line 120
    .line 121
    iput-wide v0, p0, Lf8/s;->J1:J

    .line 122
    .line 123
    iput-wide v0, p0, Lf8/s;->a0:J

    .line 124
    .line 125
    iput p2, p0, Lf8/s;->v1:I

    .line 126
    .line 127
    iput p2, p0, Lf8/s;->w1:I

    .line 128
    .line 129
    new-instance p1, La8/g;

    .line 130
    .line 131
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 132
    .line 133
    .line 134
    iput-object p1, p0, Lf8/s;->H1:La8/g;

    .line 135
    .line 136
    iput-wide v0, p0, Lf8/s;->N1:J

    .line 137
    .line 138
    iput-wide v0, p0, Lf8/s;->O1:J

    .line 139
    .line 140
    return-void
.end method


# virtual methods
.method public A(FF)V
    .locals 0

    .line 1
    iput p1, p0, Lf8/s;->M:F

    .line 2
    .line 3
    iput p2, p0, Lf8/s;->N:F

    .line 4
    .line 5
    iget-object p1, p0, Lf8/s;->P:Lt7/o;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lf8/s;->w0(Lt7/o;)Z

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final B(Lt7/o;)I
    .locals 3

    .line 1
    :try_start_0
    iget-object v0, p0, Lf8/s;->w:Lf8/k;

    .line 2
    .line 3
    invoke-virtual {p0, v0, p1}, Lf8/s;->v0(Lf8/k;Lt7/o;)I

    .line 4
    .line 5
    .line 6
    move-result p0
    :try_end_0
    .catch Lf8/u; {:try_start_0 .. :try_end_0} :catch_0

    .line 7
    return p0

    .line 8
    :catch_0
    move-exception v0

    .line 9
    const/16 v1, 0xfa2

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-virtual {p0, v0, p1, v2, v1}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    throw p0
.end method

.method public final C()I
    .locals 0

    .line 1
    const/16 p0, 0x8

    .line 2
    .line 3
    return p0
.end method

.method public final D(JJ)Z
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-boolean v1, v0, Lf8/s;->D1:Z

    .line 4
    .line 5
    const/4 v15, 0x1

    .line 6
    xor-int/2addr v1, v15

    .line 7
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 8
    .line 9
    .line 10
    iget-object v1, v0, Lf8/s;->B:Lf8/i;

    .line 11
    .line 12
    invoke-virtual {v1}, Lf8/i;->r()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    const/4 v3, 0x4

    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    iget-object v6, v1, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 20
    .line 21
    iget v7, v0, Lf8/s;->d0:I

    .line 22
    .line 23
    iget v9, v1, Lf8/i;->n:I

    .line 24
    .line 25
    iget-wide v10, v1, Lz7/e;->j:J

    .line 26
    .line 27
    iget-wide v12, v0, La8/f;->o:J

    .line 28
    .line 29
    iget-wide v4, v1, Lf8/i;->m:J

    .line 30
    .line 31
    invoke-virtual {v0, v12, v13, v4, v5}, Lf8/s;->T(JJ)Z

    .line 32
    .line 33
    .line 34
    move-result v12

    .line 35
    invoke-virtual {v1, v3}, Lkq/d;->c(I)Z

    .line 36
    .line 37
    .line 38
    move-result v13

    .line 39
    iget-object v14, v0, Lf8/s;->G:Lt7/o;

    .line 40
    .line 41
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    const/4 v5, 0x0

    .line 45
    const/4 v8, 0x0

    .line 46
    move-wide/from16 v3, p3

    .line 47
    .line 48
    move-object v15, v1

    .line 49
    move-wide/from16 v1, p1

    .line 50
    .line 51
    invoke-virtual/range {v0 .. v14}, Lf8/s;->h0(JJLf8/m;Ljava/nio/ByteBuffer;IIIJZZLt7/o;)Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_0

    .line 56
    .line 57
    iget-wide v1, v15, Lf8/i;->m:J

    .line 58
    .line 59
    invoke-virtual {v0, v1, v2}, Lf8/s;->d0(J)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v15}, Lf8/i;->m()V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    const/16 v16, 0x0

    .line 67
    .line 68
    goto/16 :goto_12

    .line 69
    .line 70
    :cond_1
    move-object v15, v1

    .line 71
    :goto_0
    iget-boolean v1, v0, Lf8/s;->C1:Z

    .line 72
    .line 73
    if-eqz v1, :cond_2

    .line 74
    .line 75
    const/4 v1, 0x1

    .line 76
    iput-boolean v1, v0, Lf8/s;->D1:Z

    .line 77
    .line 78
    const/4 v2, 0x0

    .line 79
    return v2

    .line 80
    :cond_2
    const/4 v2, 0x0

    .line 81
    iget-boolean v1, v0, Lf8/s;->r1:Z

    .line 82
    .line 83
    iget-object v3, v0, Lf8/s;->A:Lz7/e;

    .line 84
    .line 85
    if-eqz v1, :cond_3

    .line 86
    .line 87
    invoke-virtual {v15, v3}, Lf8/i;->q(Lz7/e;)Z

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 92
    .line 93
    .line 94
    iput-boolean v2, v0, Lf8/s;->r1:Z

    .line 95
    .line 96
    :cond_3
    iget-boolean v1, v0, Lf8/s;->s1:Z

    .line 97
    .line 98
    if-eqz v1, :cond_6

    .line 99
    .line 100
    invoke-virtual {v15}, Lf8/i;->r()Z

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    if-eqz v1, :cond_5

    .line 105
    .line 106
    :cond_4
    :goto_1
    const/16 v17, 0x1

    .line 107
    .line 108
    goto/16 :goto_13

    .line 109
    .line 110
    :cond_5
    iput-boolean v2, v0, Lf8/s;->q1:Z

    .line 111
    .line 112
    invoke-virtual {v0}, Lf8/s;->l0()V

    .line 113
    .line 114
    .line 115
    iput-boolean v2, v0, Lf8/s;->s1:Z

    .line 116
    .line 117
    invoke-virtual {v0}, Lf8/s;->U()V

    .line 118
    .line 119
    .line 120
    iget-boolean v1, v0, Lf8/s;->q1:Z

    .line 121
    .line 122
    if-nez v1, :cond_6

    .line 123
    .line 124
    move/from16 v16, v2

    .line 125
    .line 126
    goto/16 :goto_12

    .line 127
    .line 128
    :cond_6
    iget-boolean v1, v0, Lf8/s;->C1:Z

    .line 129
    .line 130
    const/16 v17, 0x1

    .line 131
    .line 132
    xor-int/lit8 v1, v1, 0x1

    .line 133
    .line 134
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 135
    .line 136
    .line 137
    iget-object v1, v0, La8/f;->f:Lb81/d;

    .line 138
    .line 139
    invoke-virtual {v1}, Lb81/d;->i()V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v3}, Lz7/e;->m()V

    .line 143
    .line 144
    .line 145
    :goto_2
    invoke-virtual {v3}, Lz7/e;->m()V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v0, v1, v3, v2}, La8/f;->x(Lb81/d;Lz7/e;I)I

    .line 149
    .line 150
    .line 151
    move-result v4

    .line 152
    const/4 v5, -0x5

    .line 153
    if-eq v4, v5, :cond_20

    .line 154
    .line 155
    const/4 v5, -0x4

    .line 156
    if-eq v4, v5, :cond_8

    .line 157
    .line 158
    const/4 v1, -0x3

    .line 159
    if-ne v4, v1, :cond_7

    .line 160
    .line 161
    invoke-virtual {v0}, La8/f;->l()Z

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    if-eqz v1, :cond_21

    .line 166
    .line 167
    iget-wide v3, v0, Lf8/s;->A1:J

    .line 168
    .line 169
    iput-wide v3, v0, Lf8/s;->B1:J

    .line 170
    .line 171
    goto/16 :goto_11

    .line 172
    .line 173
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 174
    .line 175
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 176
    .line 177
    .line 178
    throw v0

    .line 179
    :cond_8
    const/4 v4, 0x4

    .line 180
    invoke-virtual {v3, v4}, Lkq/d;->c(I)Z

    .line 181
    .line 182
    .line 183
    move-result v5

    .line 184
    if-eqz v5, :cond_9

    .line 185
    .line 186
    const/4 v5, 0x1

    .line 187
    iput-boolean v5, v0, Lf8/s;->C1:Z

    .line 188
    .line 189
    iget-wide v3, v0, Lf8/s;->A1:J

    .line 190
    .line 191
    iput-wide v3, v0, Lf8/s;->B1:J

    .line 192
    .line 193
    goto/16 :goto_11

    .line 194
    .line 195
    :cond_9
    iget-wide v5, v0, Lf8/s;->A1:J

    .line 196
    .line 197
    iget-wide v7, v3, Lz7/e;->j:J

    .line 198
    .line 199
    invoke-static {v5, v6, v7, v8}, Ljava/lang/Math;->max(JJ)J

    .line 200
    .line 201
    .line 202
    move-result-wide v5

    .line 203
    iput-wide v5, v0, Lf8/s;->A1:J

    .line 204
    .line 205
    invoke-virtual {v0}, La8/f;->l()Z

    .line 206
    .line 207
    .line 208
    move-result v5

    .line 209
    if-nez v5, :cond_a

    .line 210
    .line 211
    iget-object v5, v0, Lf8/s;->z:Lz7/e;

    .line 212
    .line 213
    const/high16 v6, 0x20000000

    .line 214
    .line 215
    invoke-virtual {v5, v6}, Lkq/d;->c(I)Z

    .line 216
    .line 217
    .line 218
    move-result v5

    .line 219
    if-eqz v5, :cond_b

    .line 220
    .line 221
    :cond_a
    iget-wide v5, v0, Lf8/s;->A1:J

    .line 222
    .line 223
    iput-wide v5, v0, Lf8/s;->B1:J

    .line 224
    .line 225
    :cond_b
    iget-boolean v5, v0, Lf8/s;->E1:Z

    .line 226
    .line 227
    const/16 v6, 0xff

    .line 228
    .line 229
    const/4 v7, 0x0

    .line 230
    const-string v8, "audio/opus"

    .line 231
    .line 232
    if-eqz v5, :cond_d

    .line 233
    .line 234
    iget-object v5, v0, Lf8/s;->F:Lt7/o;

    .line 235
    .line 236
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 237
    .line 238
    .line 239
    iput-object v5, v0, Lf8/s;->G:Lt7/o;

    .line 240
    .line 241
    iget-object v5, v5, Lt7/o;->n:Ljava/lang/String;

    .line 242
    .line 243
    invoke-static {v5, v8}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result v5

    .line 247
    if-eqz v5, :cond_c

    .line 248
    .line 249
    iget-object v5, v0, Lf8/s;->G:Lt7/o;

    .line 250
    .line 251
    iget-object v5, v5, Lt7/o;->q:Ljava/util/List;

    .line 252
    .line 253
    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    .line 254
    .line 255
    .line 256
    move-result v5

    .line 257
    if-nez v5, :cond_c

    .line 258
    .line 259
    iget-object v5, v0, Lf8/s;->G:Lt7/o;

    .line 260
    .line 261
    iget-object v5, v5, Lt7/o;->q:Ljava/util/List;

    .line 262
    .line 263
    invoke-interface {v5, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v5

    .line 267
    check-cast v5, [B

    .line 268
    .line 269
    const/16 v9, 0xb

    .line 270
    .line 271
    aget-byte v9, v5, v9

    .line 272
    .line 273
    and-int/2addr v9, v6

    .line 274
    shl-int/lit8 v9, v9, 0x8

    .line 275
    .line 276
    const/16 v10, 0xa

    .line 277
    .line 278
    aget-byte v5, v5, v10

    .line 279
    .line 280
    and-int/2addr v5, v6

    .line 281
    or-int/2addr v5, v9

    .line 282
    iget-object v9, v0, Lf8/s;->G:Lt7/o;

    .line 283
    .line 284
    invoke-virtual {v9}, Lt7/o;->a()Lt7/n;

    .line 285
    .line 286
    .line 287
    move-result-object v9

    .line 288
    iput v5, v9, Lt7/n;->H:I

    .line 289
    .line 290
    new-instance v5, Lt7/o;

    .line 291
    .line 292
    invoke-direct {v5, v9}, Lt7/o;-><init>(Lt7/n;)V

    .line 293
    .line 294
    .line 295
    iput-object v5, v0, Lf8/s;->G:Lt7/o;

    .line 296
    .line 297
    :cond_c
    iget-object v5, v0, Lf8/s;->G:Lt7/o;

    .line 298
    .line 299
    invoke-virtual {v0, v5, v7}, Lf8/s;->b0(Lt7/o;Landroid/media/MediaFormat;)V

    .line 300
    .line 301
    .line 302
    iput-boolean v2, v0, Lf8/s;->E1:Z

    .line 303
    .line 304
    :cond_d
    invoke-virtual {v3}, Lz7/e;->p()V

    .line 305
    .line 306
    .line 307
    iget-object v5, v0, Lf8/s;->G:Lt7/o;

    .line 308
    .line 309
    if-eqz v5, :cond_1c

    .line 310
    .line 311
    iget-object v5, v5, Lt7/o;->n:Ljava/lang/String;

    .line 312
    .line 313
    invoke-static {v5, v8}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 314
    .line 315
    .line 316
    move-result v5

    .line 317
    if-eqz v5, :cond_1c

    .line 318
    .line 319
    const/high16 v5, 0x10000000

    .line 320
    .line 321
    invoke-virtual {v3, v5}, Lkq/d;->c(I)Z

    .line 322
    .line 323
    .line 324
    move-result v5

    .line 325
    if-eqz v5, :cond_e

    .line 326
    .line 327
    iget-object v5, v0, Lf8/s;->G:Lt7/o;

    .line 328
    .line 329
    iput-object v5, v3, Lz7/e;->f:Lt7/o;

    .line 330
    .line 331
    invoke-virtual {v0, v3}, Lf8/s;->R(Lz7/e;)V

    .line 332
    .line 333
    .line 334
    :cond_e
    iget-wide v8, v0, La8/f;->o:J

    .line 335
    .line 336
    iget-wide v10, v3, Lz7/e;->j:J

    .line 337
    .line 338
    sub-long/2addr v8, v10

    .line 339
    const-wide/32 v10, 0x13880

    .line 340
    .line 341
    .line 342
    cmp-long v5, v8, v10

    .line 343
    .line 344
    if-gtz v5, :cond_1c

    .line 345
    .line 346
    iget-object v5, v0, Lf8/s;->G:Lt7/o;

    .line 347
    .line 348
    iget-object v5, v5, Lt7/o;->q:Ljava/util/List;

    .line 349
    .line 350
    iget-object v8, v0, Lf8/s;->E:Lc8/b0;

    .line 351
    .line 352
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 353
    .line 354
    .line 355
    iget-object v9, v3, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 356
    .line 357
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 358
    .line 359
    .line 360
    iget-object v9, v3, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 361
    .line 362
    invoke-virtual {v9}, Ljava/nio/Buffer;->limit()I

    .line 363
    .line 364
    .line 365
    move-result v9

    .line 366
    iget-object v10, v3, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 367
    .line 368
    invoke-virtual {v10}, Ljava/nio/Buffer;->position()I

    .line 369
    .line 370
    .line 371
    move-result v10

    .line 372
    sub-int/2addr v9, v10

    .line 373
    if-nez v9, :cond_f

    .line 374
    .line 375
    goto/16 :goto_e

    .line 376
    .line 377
    :cond_f
    iget v9, v8, Lc8/b0;->b:I

    .line 378
    .line 379
    const/4 v10, 0x2

    .line 380
    if-ne v9, v10, :cond_11

    .line 381
    .line 382
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 383
    .line 384
    .line 385
    move-result v9

    .line 386
    const/4 v11, 0x1

    .line 387
    if-eq v9, v11, :cond_10

    .line 388
    .line 389
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 390
    .line 391
    .line 392
    move-result v9

    .line 393
    const/4 v11, 0x3

    .line 394
    if-ne v9, v11, :cond_11

    .line 395
    .line 396
    :cond_10
    invoke-interface {v5, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 397
    .line 398
    .line 399
    move-result-object v5

    .line 400
    move-object v7, v5

    .line 401
    check-cast v7, [B

    .line 402
    .line 403
    :cond_11
    iget-object v5, v3, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 404
    .line 405
    invoke-virtual {v5}, Ljava/nio/Buffer;->position()I

    .line 406
    .line 407
    .line 408
    move-result v9

    .line 409
    invoke-virtual {v5}, Ljava/nio/Buffer;->limit()I

    .line 410
    .line 411
    .line 412
    move-result v11

    .line 413
    sub-int v12, v11, v9

    .line 414
    .line 415
    add-int/lit16 v13, v12, 0xff

    .line 416
    .line 417
    div-int/2addr v13, v6

    .line 418
    add-int/lit8 v14, v13, 0x1b

    .line 419
    .line 420
    add-int/2addr v14, v12

    .line 421
    iget v4, v8, Lc8/b0;->b:I

    .line 422
    .line 423
    if-ne v4, v10, :cond_13

    .line 424
    .line 425
    if-eqz v7, :cond_12

    .line 426
    .line 427
    array-length v4, v7

    .line 428
    add-int/lit8 v4, v4, 0x1c

    .line 429
    .line 430
    goto :goto_3

    .line 431
    :cond_12
    const/16 v4, 0x2f

    .line 432
    .line 433
    :goto_3
    add-int/lit8 v16, v4, 0x2c

    .line 434
    .line 435
    add-int v14, v16, v14

    .line 436
    .line 437
    goto :goto_4

    .line 438
    :cond_13
    move v4, v2

    .line 439
    :goto_4
    iget-object v6, v8, Lc8/b0;->a:Ljava/nio/ByteBuffer;

    .line 440
    .line 441
    invoke-virtual {v6}, Ljava/nio/Buffer;->capacity()I

    .line 442
    .line 443
    .line 444
    move-result v6

    .line 445
    if-ge v6, v14, :cond_14

    .line 446
    .line 447
    invoke-static {v14}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 448
    .line 449
    .line 450
    move-result-object v6

    .line 451
    sget-object v14, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 452
    .line 453
    invoke-virtual {v6, v14}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 454
    .line 455
    .line 456
    move-result-object v6

    .line 457
    iput-object v6, v8, Lc8/b0;->a:Ljava/nio/ByteBuffer;

    .line 458
    .line 459
    goto :goto_5

    .line 460
    :cond_14
    iget-object v6, v8, Lc8/b0;->a:Ljava/nio/ByteBuffer;

    .line 461
    .line 462
    invoke-virtual {v6}, Ljava/nio/ByteBuffer;->clear()Ljava/nio/Buffer;

    .line 463
    .line 464
    .line 465
    :goto_5
    iget-object v6, v8, Lc8/b0;->a:Ljava/nio/ByteBuffer;

    .line 466
    .line 467
    iget v14, v8, Lc8/b0;->b:I

    .line 468
    .line 469
    const/16 v2, 0x16

    .line 470
    .line 471
    if-ne v14, v10, :cond_16

    .line 472
    .line 473
    if-eqz v7, :cond_15

    .line 474
    .line 475
    const/16 v22, 0x1

    .line 476
    .line 477
    const/16 v23, 0x1

    .line 478
    .line 479
    const-wide/16 v19, 0x0

    .line 480
    .line 481
    const/16 v21, 0x0

    .line 482
    .line 483
    move-object/from16 v18, v6

    .line 484
    .line 485
    invoke-static/range {v18 .. v23}, Lc8/b0;->a(Ljava/nio/ByteBuffer;JIIZ)V

    .line 486
    .line 487
    .line 488
    array-length v14, v7

    .line 489
    move/from16 p3, v11

    .line 490
    .line 491
    int-to-long v10, v14

    .line 492
    invoke-static {v10, v11}, Llp/fe;->b(J)B

    .line 493
    .line 494
    .line 495
    move-result v10

    .line 496
    invoke-virtual {v6, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 497
    .line 498
    .line 499
    invoke-virtual {v6, v7}, Ljava/nio/ByteBuffer;->put([B)Ljava/nio/ByteBuffer;

    .line 500
    .line 501
    .line 502
    invoke-virtual {v6}, Ljava/nio/ByteBuffer;->array()[B

    .line 503
    .line 504
    .line 505
    move-result-object v10

    .line 506
    invoke-virtual {v6}, Ljava/nio/ByteBuffer;->arrayOffset()I

    .line 507
    .line 508
    .line 509
    move-result v11

    .line 510
    array-length v14, v7

    .line 511
    add-int/lit8 v14, v14, 0x1c

    .line 512
    .line 513
    move/from16 p4, v4

    .line 514
    .line 515
    const/4 v4, 0x0

    .line 516
    invoke-static {v11, v10, v14, v4}, Lw7/w;->j(I[BII)I

    .line 517
    .line 518
    .line 519
    move-result v10

    .line 520
    invoke-virtual {v6, v2, v10}, Ljava/nio/ByteBuffer;->putInt(II)Ljava/nio/ByteBuffer;

    .line 521
    .line 522
    .line 523
    array-length v4, v7

    .line 524
    add-int/lit8 v4, v4, 0x1c

    .line 525
    .line 526
    invoke-virtual {v6, v4}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 527
    .line 528
    .line 529
    goto :goto_6

    .line 530
    :cond_15
    move/from16 p4, v4

    .line 531
    .line 532
    move/from16 p3, v11

    .line 533
    .line 534
    sget-object v4, Lc8/b0;->d:[B

    .line 535
    .line 536
    invoke-virtual {v6, v4}, Ljava/nio/ByteBuffer;->put([B)Ljava/nio/ByteBuffer;

    .line 537
    .line 538
    .line 539
    :goto_6
    sget-object v4, Lc8/b0;->e:[B

    .line 540
    .line 541
    invoke-virtual {v6, v4}, Ljava/nio/ByteBuffer;->put([B)Ljava/nio/ByteBuffer;

    .line 542
    .line 543
    .line 544
    :goto_7
    const/4 v4, 0x0

    .line 545
    goto :goto_8

    .line 546
    :cond_16
    move/from16 p4, v4

    .line 547
    .line 548
    move/from16 p3, v11

    .line 549
    .line 550
    goto :goto_7

    .line 551
    :goto_8
    invoke-virtual {v5, v4}, Ljava/nio/ByteBuffer;->get(I)B

    .line 552
    .line 553
    .line 554
    move-result v7

    .line 555
    invoke-virtual {v5}, Ljava/nio/Buffer;->limit()I

    .line 556
    .line 557
    .line 558
    move-result v4

    .line 559
    const/4 v11, 0x1

    .line 560
    if-le v4, v11, :cond_17

    .line 561
    .line 562
    invoke-virtual {v5, v11}, Ljava/nio/ByteBuffer;->get(I)B

    .line 563
    .line 564
    .line 565
    move-result v4

    .line 566
    goto :goto_9

    .line 567
    :cond_17
    const/4 v4, 0x0

    .line 568
    :goto_9
    invoke-static {v7, v4}, Lo8/b;->k(BB)J

    .line 569
    .line 570
    .line 571
    move-result-wide v10

    .line 572
    const-wide/32 v18, 0xbb80

    .line 573
    .line 574
    .line 575
    mul-long v10, v10, v18

    .line 576
    .line 577
    const-wide/32 v18, 0xf4240

    .line 578
    .line 579
    .line 580
    div-long v10, v10, v18

    .line 581
    .line 582
    long-to-int v4, v10

    .line 583
    iget v7, v8, Lc8/b0;->c:I

    .line 584
    .line 585
    add-int/2addr v7, v4

    .line 586
    iput v7, v8, Lc8/b0;->c:I

    .line 587
    .line 588
    int-to-long v10, v7

    .line 589
    iget v4, v8, Lc8/b0;->b:I

    .line 590
    .line 591
    const/16 v23, 0x0

    .line 592
    .line 593
    move/from16 v21, v4

    .line 594
    .line 595
    move-object/from16 v18, v6

    .line 596
    .line 597
    move-wide/from16 v19, v10

    .line 598
    .line 599
    move/from16 v22, v13

    .line 600
    .line 601
    invoke-static/range {v18 .. v23}, Lc8/b0;->a(Ljava/nio/ByteBuffer;JIIZ)V

    .line 602
    .line 603
    .line 604
    const/4 v4, 0x0

    .line 605
    :goto_a
    if-ge v4, v13, :cond_19

    .line 606
    .line 607
    const/16 v7, 0xff

    .line 608
    .line 609
    if-lt v12, v7, :cond_18

    .line 610
    .line 611
    const/4 v10, -0x1

    .line 612
    invoke-virtual {v6, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 613
    .line 614
    .line 615
    add-int/lit16 v10, v12, -0xff

    .line 616
    .line 617
    move v12, v10

    .line 618
    goto :goto_b

    .line 619
    :cond_18
    int-to-byte v10, v12

    .line 620
    invoke-virtual {v6, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 621
    .line 622
    .line 623
    const/4 v12, 0x0

    .line 624
    :goto_b
    add-int/lit8 v4, v4, 0x1

    .line 625
    .line 626
    goto :goto_a

    .line 627
    :cond_19
    move/from16 v4, p3

    .line 628
    .line 629
    :goto_c
    if-ge v9, v4, :cond_1a

    .line 630
    .line 631
    invoke-virtual {v5, v9}, Ljava/nio/ByteBuffer;->get(I)B

    .line 632
    .line 633
    .line 634
    move-result v7

    .line 635
    invoke-virtual {v6, v7}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 636
    .line 637
    .line 638
    add-int/lit8 v9, v9, 0x1

    .line 639
    .line 640
    goto :goto_c

    .line 641
    :cond_1a
    invoke-virtual {v5}, Ljava/nio/Buffer;->limit()I

    .line 642
    .line 643
    .line 644
    move-result v4

    .line 645
    invoke-virtual {v5, v4}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 646
    .line 647
    .line 648
    invoke-virtual {v6}, Ljava/nio/ByteBuffer;->flip()Ljava/nio/Buffer;

    .line 649
    .line 650
    .line 651
    iget v4, v8, Lc8/b0;->b:I

    .line 652
    .line 653
    const/4 v5, 0x2

    .line 654
    if-ne v4, v5, :cond_1b

    .line 655
    .line 656
    invoke-virtual {v6}, Ljava/nio/ByteBuffer;->array()[B

    .line 657
    .line 658
    .line 659
    move-result-object v2

    .line 660
    invoke-virtual {v6}, Ljava/nio/ByteBuffer;->arrayOffset()I

    .line 661
    .line 662
    .line 663
    move-result v4

    .line 664
    add-int v4, v4, p4

    .line 665
    .line 666
    add-int/lit8 v4, v4, 0x2c

    .line 667
    .line 668
    invoke-virtual {v6}, Ljava/nio/Buffer;->limit()I

    .line 669
    .line 670
    .line 671
    move-result v5

    .line 672
    invoke-virtual {v6}, Ljava/nio/Buffer;->position()I

    .line 673
    .line 674
    .line 675
    move-result v7

    .line 676
    sub-int/2addr v5, v7

    .line 677
    const/4 v7, 0x0

    .line 678
    invoke-static {v4, v2, v5, v7}, Lw7/w;->j(I[BII)I

    .line 679
    .line 680
    .line 681
    move-result v2

    .line 682
    add-int/lit8 v4, p4, 0x42

    .line 683
    .line 684
    invoke-virtual {v6, v4, v2}, Ljava/nio/ByteBuffer;->putInt(II)Ljava/nio/ByteBuffer;

    .line 685
    .line 686
    .line 687
    goto :goto_d

    .line 688
    :cond_1b
    const/4 v7, 0x0

    .line 689
    invoke-virtual {v6}, Ljava/nio/ByteBuffer;->array()[B

    .line 690
    .line 691
    .line 692
    move-result-object v4

    .line 693
    invoke-virtual {v6}, Ljava/nio/ByteBuffer;->arrayOffset()I

    .line 694
    .line 695
    .line 696
    move-result v5

    .line 697
    invoke-virtual {v6}, Ljava/nio/Buffer;->limit()I

    .line 698
    .line 699
    .line 700
    move-result v9

    .line 701
    invoke-virtual {v6}, Ljava/nio/Buffer;->position()I

    .line 702
    .line 703
    .line 704
    move-result v10

    .line 705
    sub-int/2addr v9, v10

    .line 706
    invoke-static {v5, v4, v9, v7}, Lw7/w;->j(I[BII)I

    .line 707
    .line 708
    .line 709
    move-result v4

    .line 710
    invoke-virtual {v6, v2, v4}, Ljava/nio/ByteBuffer;->putInt(II)Ljava/nio/ByteBuffer;

    .line 711
    .line 712
    .line 713
    :goto_d
    iget v2, v8, Lc8/b0;->b:I

    .line 714
    .line 715
    const/16 v17, 0x1

    .line 716
    .line 717
    add-int/lit8 v2, v2, 0x1

    .line 718
    .line 719
    iput v2, v8, Lc8/b0;->b:I

    .line 720
    .line 721
    iput-object v6, v8, Lc8/b0;->a:Ljava/nio/ByteBuffer;

    .line 722
    .line 723
    invoke-virtual {v3}, Lz7/e;->m()V

    .line 724
    .line 725
    .line 726
    iget-object v2, v8, Lc8/b0;->a:Ljava/nio/ByteBuffer;

    .line 727
    .line 728
    invoke-virtual {v2}, Ljava/nio/Buffer;->remaining()I

    .line 729
    .line 730
    .line 731
    move-result v2

    .line 732
    invoke-virtual {v3, v2}, Lz7/e;->o(I)V

    .line 733
    .line 734
    .line 735
    iget-object v2, v3, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 736
    .line 737
    iget-object v4, v8, Lc8/b0;->a:Ljava/nio/ByteBuffer;

    .line 738
    .line 739
    invoke-virtual {v2, v4}, Ljava/nio/ByteBuffer;->put(Ljava/nio/ByteBuffer;)Ljava/nio/ByteBuffer;

    .line 740
    .line 741
    .line 742
    invoke-virtual {v3}, Lz7/e;->p()V

    .line 743
    .line 744
    .line 745
    :cond_1c
    :goto_e
    invoke-virtual {v15}, Lf8/i;->r()Z

    .line 746
    .line 747
    .line 748
    move-result v2

    .line 749
    if-nez v2, :cond_1d

    .line 750
    .line 751
    goto :goto_f

    .line 752
    :cond_1d
    iget-wide v4, v0, La8/f;->o:J

    .line 753
    .line 754
    iget-wide v6, v15, Lf8/i;->m:J

    .line 755
    .line 756
    invoke-virtual {v0, v4, v5, v6, v7}, Lf8/s;->T(JJ)Z

    .line 757
    .line 758
    .line 759
    move-result v2

    .line 760
    iget-wide v6, v3, Lz7/e;->j:J

    .line 761
    .line 762
    invoke-virtual {v0, v4, v5, v6, v7}, Lf8/s;->T(JJ)Z

    .line 763
    .line 764
    .line 765
    move-result v4

    .line 766
    if-ne v2, v4, :cond_1e

    .line 767
    .line 768
    :goto_f
    invoke-virtual {v15, v3}, Lf8/i;->q(Lz7/e;)Z

    .line 769
    .line 770
    .line 771
    move-result v2

    .line 772
    if-nez v2, :cond_1f

    .line 773
    .line 774
    :cond_1e
    const/4 v11, 0x1

    .line 775
    goto :goto_10

    .line 776
    :cond_1f
    const/4 v2, 0x0

    .line 777
    goto/16 :goto_2

    .line 778
    .line 779
    :goto_10
    iput-boolean v11, v0, Lf8/s;->r1:Z

    .line 780
    .line 781
    goto :goto_11

    .line 782
    :cond_20
    invoke-virtual {v0, v1}, Lf8/s;->a0(Lb81/d;)La8/h;

    .line 783
    .line 784
    .line 785
    :cond_21
    :goto_11
    invoke-virtual {v15}, Lf8/i;->r()Z

    .line 786
    .line 787
    .line 788
    move-result v1

    .line 789
    if-eqz v1, :cond_22

    .line 790
    .line 791
    invoke-virtual {v15}, Lz7/e;->p()V

    .line 792
    .line 793
    .line 794
    :cond_22
    invoke-virtual {v15}, Lf8/i;->r()Z

    .line 795
    .line 796
    .line 797
    move-result v1

    .line 798
    if-nez v1, :cond_4

    .line 799
    .line 800
    iget-boolean v1, v0, Lf8/s;->C1:Z

    .line 801
    .line 802
    if-nez v1, :cond_4

    .line 803
    .line 804
    iget-boolean v0, v0, Lf8/s;->s1:Z

    .line 805
    .line 806
    if-eqz v0, :cond_0

    .line 807
    .line 808
    goto/16 :goto_1

    .line 809
    .line 810
    :goto_12
    return v16

    .line 811
    :goto_13
    return v17
.end method

.method public abstract E(Lf8/p;Lt7/o;Lt7/o;)La8/h;
.end method

.method public F(Ljava/lang/IllegalStateException;Lf8/p;)Lf8/o;
    .locals 0

    .line 1
    new-instance p0, Lf8/o;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2}, Lf8/o;-><init>(Ljava/lang/IllegalStateException;Lf8/p;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final G()Z
    .locals 2

    .line 1
    iget-boolean v0, p0, Lf8/s;->x1:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iput v1, p0, Lf8/s;->v1:I

    .line 7
    .line 8
    const/4 v0, 0x2

    .line 9
    iput v0, p0, Lf8/s;->w1:I

    .line 10
    .line 11
    return v1

    .line 12
    :cond_0
    invoke-virtual {p0}, Lf8/s;->x0()V

    .line 13
    .line 14
    .line 15
    return v1
.end method

.method public final H(JJ)Z
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v5, v0, Lf8/s;->O:Lf8/m;

    .line 4
    .line 5
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    iget v1, v0, Lf8/s;->d0:I

    .line 9
    .line 10
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    const/4 v15, 0x1

    .line 16
    iget-object v4, v0, Lf8/s;->C:Landroid/media/MediaCodec$BufferInfo;

    .line 17
    .line 18
    const/4 v6, 0x0

    .line 19
    if-ltz v1, :cond_0

    .line 20
    .line 21
    goto/16 :goto_0

    .line 22
    .line 23
    :cond_0
    invoke-interface {v5, v4}, Lf8/m;->t(Landroid/media/MediaCodec$BufferInfo;)I

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-gez v1, :cond_5

    .line 28
    .line 29
    const/4 v4, -0x2

    .line 30
    if-ne v1, v4, :cond_1

    .line 31
    .line 32
    iput-boolean v15, v0, Lf8/s;->z1:Z

    .line 33
    .line 34
    iget-object v1, v0, Lf8/s;->O:Lf8/m;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    invoke-interface {v1}, Lf8/m;->g()Landroid/media/MediaFormat;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    iput-object v1, v0, Lf8/s;->Q:Landroid/media/MediaFormat;

    .line 44
    .line 45
    iput-boolean v15, v0, Lf8/s;->R:Z

    .line 46
    .line 47
    return v15

    .line 48
    :cond_1
    iget-boolean v1, v0, Lf8/s;->Z:Z

    .line 49
    .line 50
    if-eqz v1, :cond_3

    .line 51
    .line 52
    iget-boolean v1, v0, Lf8/s;->C1:Z

    .line 53
    .line 54
    if-nez v1, :cond_2

    .line 55
    .line 56
    iget v1, v0, Lf8/s;->v1:I

    .line 57
    .line 58
    const/4 v4, 0x2

    .line 59
    if-ne v1, v4, :cond_3

    .line 60
    .line 61
    :cond_2
    invoke-virtual {v0}, Lf8/s;->g0()V

    .line 62
    .line 63
    .line 64
    :cond_3
    iget-wide v4, v0, Lf8/s;->a0:J

    .line 65
    .line 66
    cmp-long v1, v4, v2

    .line 67
    .line 68
    if-eqz v1, :cond_4

    .line 69
    .line 70
    const-wide/16 v1, 0x64

    .line 71
    .line 72
    add-long/2addr v4, v1

    .line 73
    iget-object v1, v0, La8/f;->j:Lw7/r;

    .line 74
    .line 75
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 79
    .line 80
    .line 81
    move-result-wide v1

    .line 82
    cmp-long v1, v4, v1

    .line 83
    .line 84
    if-gez v1, :cond_4

    .line 85
    .line 86
    invoke-virtual {v0}, Lf8/s;->g0()V

    .line 87
    .line 88
    .line 89
    return v6

    .line 90
    :cond_4
    move/from16 v16, v6

    .line 91
    .line 92
    goto/16 :goto_6

    .line 93
    .line 94
    :cond_5
    iget-boolean v7, v0, Lf8/s;->Y:Z

    .line 95
    .line 96
    if-eqz v7, :cond_6

    .line 97
    .line 98
    iput-boolean v6, v0, Lf8/s;->Y:Z

    .line 99
    .line 100
    invoke-interface {v5, v1}, Lf8/m;->n(I)V

    .line 101
    .line 102
    .line 103
    return v15

    .line 104
    :cond_6
    iget v7, v4, Landroid/media/MediaCodec$BufferInfo;->size:I

    .line 105
    .line 106
    if-nez v7, :cond_7

    .line 107
    .line 108
    iget v7, v4, Landroid/media/MediaCodec$BufferInfo;->flags:I

    .line 109
    .line 110
    and-int/lit8 v7, v7, 0x4

    .line 111
    .line 112
    if-eqz v7, :cond_7

    .line 113
    .line 114
    invoke-virtual {v0}, Lf8/s;->g0()V

    .line 115
    .line 116
    .line 117
    return v6

    .line 118
    :cond_7
    iput v1, v0, Lf8/s;->d0:I

    .line 119
    .line 120
    invoke-interface {v5, v1}, Lf8/m;->z(I)Ljava/nio/ByteBuffer;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    iput-object v1, v0, Lf8/s;->e0:Ljava/nio/ByteBuffer;

    .line 125
    .line 126
    if-eqz v1, :cond_8

    .line 127
    .line 128
    iget v7, v4, Landroid/media/MediaCodec$BufferInfo;->offset:I

    .line 129
    .line 130
    invoke-virtual {v1, v7}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 131
    .line 132
    .line 133
    iget-object v1, v0, Lf8/s;->e0:Ljava/nio/ByteBuffer;

    .line 134
    .line 135
    iget v7, v4, Landroid/media/MediaCodec$BufferInfo;->offset:I

    .line 136
    .line 137
    iget v8, v4, Landroid/media/MediaCodec$BufferInfo;->size:I

    .line 138
    .line 139
    add-int/2addr v7, v8

    .line 140
    invoke-virtual {v1, v7}, Ljava/nio/ByteBuffer;->limit(I)Ljava/nio/Buffer;

    .line 141
    .line 142
    .line 143
    :cond_8
    iget-wide v7, v4, Landroid/media/MediaCodec$BufferInfo;->presentationTimeUs:J

    .line 144
    .line 145
    invoke-virtual {v0, v7, v8}, Lf8/s;->y0(J)V

    .line 146
    .line 147
    .line 148
    :goto_0
    iget-wide v10, v4, Landroid/media/MediaCodec$BufferInfo;->presentationTimeUs:J

    .line 149
    .line 150
    iget-wide v7, v0, La8/f;->o:J

    .line 151
    .line 152
    cmp-long v1, v10, v7

    .line 153
    .line 154
    if-gez v1, :cond_9

    .line 155
    .line 156
    move v1, v15

    .line 157
    goto :goto_1

    .line 158
    :cond_9
    move v1, v6

    .line 159
    :goto_1
    iput-boolean v1, v0, Lf8/s;->f0:Z

    .line 160
    .line 161
    iget-wide v7, v0, Lf8/s;->B1:J

    .line 162
    .line 163
    cmp-long v1, v7, v2

    .line 164
    .line 165
    if-eqz v1, :cond_a

    .line 166
    .line 167
    cmp-long v1, v7, v10

    .line 168
    .line 169
    if-gtz v1, :cond_a

    .line 170
    .line 171
    move v1, v15

    .line 172
    goto :goto_2

    .line 173
    :cond_a
    move v1, v6

    .line 174
    :goto_2
    iput-boolean v1, v0, Lf8/s;->g0:Z

    .line 175
    .line 176
    iget-boolean v1, v0, Lf8/s;->M1:Z

    .line 177
    .line 178
    if-eqz v1, :cond_b

    .line 179
    .line 180
    iget-wide v7, v0, Lf8/s;->N1:J

    .line 181
    .line 182
    cmp-long v1, v7, v2

    .line 183
    .line 184
    if-eqz v1, :cond_c

    .line 185
    .line 186
    cmp-long v1, v10, v7

    .line 187
    .line 188
    if-gtz v1, :cond_c

    .line 189
    .line 190
    iput-boolean v6, v0, Lf8/s;->M1:Z

    .line 191
    .line 192
    iput-wide v2, v0, Lf8/s;->N1:J

    .line 193
    .line 194
    :cond_b
    :goto_3
    move v1, v6

    .line 195
    goto :goto_4

    .line 196
    :cond_c
    iput-wide v10, v0, Lf8/s;->N1:J

    .line 197
    .line 198
    iput-boolean v15, v0, Lf8/s;->f0:Z

    .line 199
    .line 200
    iput-boolean v6, v0, Lf8/s;->g0:Z

    .line 201
    .line 202
    goto :goto_3

    .line 203
    :goto_4
    iget-object v6, v0, Lf8/s;->e0:Ljava/nio/ByteBuffer;

    .line 204
    .line 205
    iget v7, v0, Lf8/s;->d0:I

    .line 206
    .line 207
    iget v8, v4, Landroid/media/MediaCodec$BufferInfo;->flags:I

    .line 208
    .line 209
    iget-boolean v12, v0, Lf8/s;->f0:Z

    .line 210
    .line 211
    iget-boolean v13, v0, Lf8/s;->g0:Z

    .line 212
    .line 213
    iget-object v14, v0, Lf8/s;->G:Lt7/o;

    .line 214
    .line 215
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 216
    .line 217
    .line 218
    const/4 v9, 0x1

    .line 219
    move/from16 v16, v1

    .line 220
    .line 221
    move/from16 v17, v15

    .line 222
    .line 223
    move-wide/from16 v1, p1

    .line 224
    .line 225
    move-object v15, v4

    .line 226
    move-wide/from16 v3, p3

    .line 227
    .line 228
    invoke-virtual/range {v0 .. v14}, Lf8/s;->h0(JJLf8/m;Ljava/nio/ByteBuffer;IIIJZZLt7/o;)Z

    .line 229
    .line 230
    .line 231
    move-result v1

    .line 232
    if-eqz v1, :cond_10

    .line 233
    .line 234
    iget-wide v1, v15, Landroid/media/MediaCodec$BufferInfo;->presentationTimeUs:J

    .line 235
    .line 236
    invoke-virtual {v0, v1, v2}, Lf8/s;->d0(J)V

    .line 237
    .line 238
    .line 239
    iget v1, v15, Landroid/media/MediaCodec$BufferInfo;->flags:I

    .line 240
    .line 241
    and-int/lit8 v1, v1, 0x4

    .line 242
    .line 243
    if-eqz v1, :cond_d

    .line 244
    .line 245
    move/from16 v6, v17

    .line 246
    .line 247
    goto :goto_5

    .line 248
    :cond_d
    move/from16 v6, v16

    .line 249
    .line 250
    :goto_5
    if-nez v6, :cond_e

    .line 251
    .line 252
    iget-boolean v1, v0, Lf8/s;->y1:Z

    .line 253
    .line 254
    if-eqz v1, :cond_e

    .line 255
    .line 256
    iget-boolean v1, v0, Lf8/s;->g0:Z

    .line 257
    .line 258
    if-eqz v1, :cond_e

    .line 259
    .line 260
    iget-object v1, v0, La8/f;->j:Lw7/r;

    .line 261
    .line 262
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 263
    .line 264
    .line 265
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 266
    .line 267
    .line 268
    move-result-wide v1

    .line 269
    iput-wide v1, v0, Lf8/s;->a0:J

    .line 270
    .line 271
    :cond_e
    const/4 v1, -0x1

    .line 272
    iput v1, v0, Lf8/s;->d0:I

    .line 273
    .line 274
    const/4 v1, 0x0

    .line 275
    iput-object v1, v0, Lf8/s;->e0:Ljava/nio/ByteBuffer;

    .line 276
    .line 277
    if-nez v6, :cond_f

    .line 278
    .line 279
    return v17

    .line 280
    :cond_f
    invoke-virtual {v0}, Lf8/s;->g0()V

    .line 281
    .line 282
    .line 283
    :cond_10
    :goto_6
    return v16
.end method

.method public final I()Z
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v2, v1, Lf8/s;->O:Lf8/m;

    .line 4
    .line 5
    const/4 v8, 0x0

    .line 6
    if-eqz v2, :cond_0

    .line 7
    .line 8
    iget v0, v1, Lf8/s;->v1:I

    .line 9
    .line 10
    const/4 v9, 0x2

    .line 11
    if-eq v0, v9, :cond_0

    .line 12
    .line 13
    iget-boolean v0, v1, Lf8/s;->C1:Z

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    :cond_0
    :goto_0
    move v2, v8

    .line 18
    goto/16 :goto_6

    .line 19
    .line 20
    :cond_1
    iget v0, v1, Lf8/s;->c0:I

    .line 21
    .line 22
    iget-object v10, v1, Lf8/s;->z:Lz7/e;

    .line 23
    .line 24
    if-gez v0, :cond_3

    .line 25
    .line 26
    invoke-interface {v2}, Lf8/m;->q()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iput v0, v1, Lf8/s;->c0:I

    .line 31
    .line 32
    if-gez v0, :cond_2

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_2
    invoke-interface {v2, v0}, Lf8/m;->k(I)Ljava/nio/ByteBuffer;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    iput-object v0, v10, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 40
    .line 41
    invoke-virtual {v10}, Lz7/e;->m()V

    .line 42
    .line 43
    .line 44
    :cond_3
    iget v0, v1, Lf8/s;->v1:I

    .line 45
    .line 46
    const/4 v11, 0x0

    .line 47
    const/4 v12, -0x1

    .line 48
    const/4 v13, 0x1

    .line 49
    if-ne v0, v13, :cond_5

    .line 50
    .line 51
    iget-boolean v0, v1, Lf8/s;->Z:Z

    .line 52
    .line 53
    if-eqz v0, :cond_4

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_4
    iput-boolean v13, v1, Lf8/s;->y1:Z

    .line 57
    .line 58
    iget v5, v1, Lf8/s;->c0:I

    .line 59
    .line 60
    const-wide/16 v3, 0x0

    .line 61
    .line 62
    const/4 v7, 0x4

    .line 63
    const/4 v6, 0x0

    .line 64
    invoke-interface/range {v2 .. v7}, Lf8/m;->d(JIII)V

    .line 65
    .line 66
    .line 67
    iput v12, v1, Lf8/s;->c0:I

    .line 68
    .line 69
    iput-object v11, v10, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 70
    .line 71
    :goto_1
    iput v9, v1, Lf8/s;->v1:I

    .line 72
    .line 73
    return v8

    .line 74
    :cond_5
    iget-boolean v0, v1, Lf8/s;->X:Z

    .line 75
    .line 76
    if-eqz v0, :cond_6

    .line 77
    .line 78
    iput-boolean v8, v1, Lf8/s;->X:Z

    .line 79
    .line 80
    iget-object v0, v10, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 81
    .line 82
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    sget-object v3, Lf8/s;->P1:[B

    .line 86
    .line 87
    invoke-virtual {v0, v3}, Ljava/nio/ByteBuffer;->put([B)Ljava/nio/ByteBuffer;

    .line 88
    .line 89
    .line 90
    iget v5, v1, Lf8/s;->c0:I

    .line 91
    .line 92
    const-wide/16 v3, 0x0

    .line 93
    .line 94
    const/4 v7, 0x0

    .line 95
    const/16 v6, 0x26

    .line 96
    .line 97
    invoke-interface/range {v2 .. v7}, Lf8/m;->d(JIII)V

    .line 98
    .line 99
    .line 100
    iput v12, v1, Lf8/s;->c0:I

    .line 101
    .line 102
    iput-object v11, v10, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 103
    .line 104
    iput-boolean v13, v1, Lf8/s;->x1:Z

    .line 105
    .line 106
    return v13

    .line 107
    :cond_6
    iget v0, v1, Lf8/s;->u1:I

    .line 108
    .line 109
    if-ne v0, v13, :cond_8

    .line 110
    .line 111
    move v0, v8

    .line 112
    :goto_2
    iget-object v3, v1, Lf8/s;->P:Lt7/o;

    .line 113
    .line 114
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 115
    .line 116
    .line 117
    iget-object v3, v3, Lt7/o;->q:Ljava/util/List;

    .line 118
    .line 119
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 120
    .line 121
    .line 122
    move-result v3

    .line 123
    if-ge v0, v3, :cond_7

    .line 124
    .line 125
    iget-object v3, v1, Lf8/s;->P:Lt7/o;

    .line 126
    .line 127
    iget-object v3, v3, Lt7/o;->q:Ljava/util/List;

    .line 128
    .line 129
    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v3

    .line 133
    check-cast v3, [B

    .line 134
    .line 135
    iget-object v4, v10, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 136
    .line 137
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 138
    .line 139
    .line 140
    invoke-virtual {v4, v3}, Ljava/nio/ByteBuffer;->put([B)Ljava/nio/ByteBuffer;

    .line 141
    .line 142
    .line 143
    add-int/lit8 v0, v0, 0x1

    .line 144
    .line 145
    goto :goto_2

    .line 146
    :cond_7
    iput v9, v1, Lf8/s;->u1:I

    .line 147
    .line 148
    :cond_8
    iget-object v0, v10, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 149
    .line 150
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    invoke-virtual {v0}, Ljava/nio/Buffer;->position()I

    .line 154
    .line 155
    .line 156
    move-result v0

    .line 157
    iget-object v3, v1, La8/f;->f:Lb81/d;

    .line 158
    .line 159
    invoke-virtual {v3}, Lb81/d;->i()V

    .line 160
    .line 161
    .line 162
    :try_start_0
    invoke-virtual {v1, v3, v10, v8}, La8/f;->x(Lb81/d;Lz7/e;I)I

    .line 163
    .line 164
    .line 165
    move-result v4
    :try_end_0
    .catch Lz7/d; {:try_start_0 .. :try_end_0} :catch_0

    .line 166
    const/4 v5, -0x3

    .line 167
    if-ne v4, v5, :cond_9

    .line 168
    .line 169
    invoke-virtual {v1}, La8/f;->l()Z

    .line 170
    .line 171
    .line 172
    move-result v0

    .line 173
    if-eqz v0, :cond_0

    .line 174
    .line 175
    iget-wide v2, v1, Lf8/s;->A1:J

    .line 176
    .line 177
    iput-wide v2, v1, Lf8/s;->B1:J

    .line 178
    .line 179
    return v8

    .line 180
    :cond_9
    const/4 v5, -0x5

    .line 181
    if-ne v4, v5, :cond_b

    .line 182
    .line 183
    iget v0, v1, Lf8/s;->u1:I

    .line 184
    .line 185
    if-ne v0, v9, :cond_a

    .line 186
    .line 187
    invoke-virtual {v10}, Lz7/e;->m()V

    .line 188
    .line 189
    .line 190
    iput v13, v1, Lf8/s;->u1:I

    .line 191
    .line 192
    :cond_a
    invoke-virtual {v1, v3}, Lf8/s;->a0(Lb81/d;)La8/h;

    .line 193
    .line 194
    .line 195
    return v13

    .line 196
    :cond_b
    const/4 v3, 0x4

    .line 197
    invoke-virtual {v10, v3}, Lkq/d;->c(I)Z

    .line 198
    .line 199
    .line 200
    move-result v3

    .line 201
    if-eqz v3, :cond_f

    .line 202
    .line 203
    iget-wide v3, v1, Lf8/s;->A1:J

    .line 204
    .line 205
    iput-wide v3, v1, Lf8/s;->B1:J

    .line 206
    .line 207
    iget v0, v1, Lf8/s;->u1:I

    .line 208
    .line 209
    if-ne v0, v9, :cond_c

    .line 210
    .line 211
    invoke-virtual {v10}, Lz7/e;->m()V

    .line 212
    .line 213
    .line 214
    iput v13, v1, Lf8/s;->u1:I

    .line 215
    .line 216
    :cond_c
    iput-boolean v13, v1, Lf8/s;->C1:Z

    .line 217
    .line 218
    iget-boolean v0, v1, Lf8/s;->x1:Z

    .line 219
    .line 220
    if-nez v0, :cond_d

    .line 221
    .line 222
    invoke-virtual {v1}, Lf8/s;->g0()V

    .line 223
    .line 224
    .line 225
    return v8

    .line 226
    :cond_d
    iget-boolean v0, v1, Lf8/s;->Z:Z

    .line 227
    .line 228
    if-eqz v0, :cond_e

    .line 229
    .line 230
    goto/16 :goto_0

    .line 231
    .line 232
    :cond_e
    iput-boolean v13, v1, Lf8/s;->y1:Z

    .line 233
    .line 234
    iget v5, v1, Lf8/s;->c0:I

    .line 235
    .line 236
    const-wide/16 v3, 0x0

    .line 237
    .line 238
    const/4 v7, 0x4

    .line 239
    const/4 v6, 0x0

    .line 240
    invoke-interface/range {v2 .. v7}, Lf8/m;->d(JIII)V

    .line 241
    .line 242
    .line 243
    iput v12, v1, Lf8/s;->c0:I

    .line 244
    .line 245
    iput-object v11, v10, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 246
    .line 247
    return v8

    .line 248
    :cond_f
    iget-boolean v3, v1, Lf8/s;->x1:Z

    .line 249
    .line 250
    if-nez v3, :cond_10

    .line 251
    .line 252
    invoke-virtual {v10, v13}, Lkq/d;->c(I)Z

    .line 253
    .line 254
    .line 255
    move-result v3

    .line 256
    if-nez v3, :cond_10

    .line 257
    .line 258
    invoke-virtual {v10}, Lz7/e;->m()V

    .line 259
    .line 260
    .line 261
    iget v0, v1, Lf8/s;->u1:I

    .line 262
    .line 263
    if-ne v0, v9, :cond_11

    .line 264
    .line 265
    iput v13, v1, Lf8/s;->u1:I

    .line 266
    .line 267
    return v13

    .line 268
    :cond_10
    invoke-virtual {v1, v10}, Lf8/s;->q0(Lz7/e;)Z

    .line 269
    .line 270
    .line 271
    move-result v3

    .line 272
    if-eqz v3, :cond_12

    .line 273
    .line 274
    :cond_11
    return v13

    .line 275
    :cond_12
    const/high16 v3, 0x40000000    # 2.0f

    .line 276
    .line 277
    invoke-virtual {v10, v3}, Lkq/d;->c(I)Z

    .line 278
    .line 279
    .line 280
    move-result v3

    .line 281
    if-eqz v3, :cond_15

    .line 282
    .line 283
    iget-object v4, v10, Lz7/e;->g:Lz7/b;

    .line 284
    .line 285
    if-nez v0, :cond_13

    .line 286
    .line 287
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 288
    .line 289
    .line 290
    goto :goto_3

    .line 291
    :cond_13
    iget-object v5, v4, Lz7/b;->d:[I

    .line 292
    .line 293
    if-nez v5, :cond_14

    .line 294
    .line 295
    new-array v5, v13, [I

    .line 296
    .line 297
    iput-object v5, v4, Lz7/b;->d:[I

    .line 298
    .line 299
    iget-object v6, v4, Lz7/b;->i:Landroid/media/MediaCodec$CryptoInfo;

    .line 300
    .line 301
    iput-object v5, v6, Landroid/media/MediaCodec$CryptoInfo;->numBytesOfClearData:[I

    .line 302
    .line 303
    :cond_14
    iget-object v4, v4, Lz7/b;->d:[I

    .line 304
    .line 305
    aget v5, v4, v8

    .line 306
    .line 307
    add-int/2addr v5, v0

    .line 308
    aput v5, v4, v8

    .line 309
    .line 310
    :cond_15
    :goto_3
    iget-wide v5, v10, Lz7/e;->j:J

    .line 311
    .line 312
    iget-boolean v0, v1, Lf8/s;->E1:Z

    .line 313
    .line 314
    if-eqz v0, :cond_17

    .line 315
    .line 316
    iget-object v0, v1, Lf8/s;->D:Ljava/util/ArrayDeque;

    .line 317
    .line 318
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 319
    .line 320
    .line 321
    move-result v4

    .line 322
    if-nez v4, :cond_16

    .line 323
    .line 324
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->peekLast()Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v0

    .line 328
    check-cast v0, Lf8/r;

    .line 329
    .line 330
    iget-object v0, v0, Lf8/r;->d:Li4/c;

    .line 331
    .line 332
    iget-object v4, v1, Lf8/s;->F:Lt7/o;

    .line 333
    .line 334
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 335
    .line 336
    .line 337
    invoke-virtual {v0, v5, v6, v4}, Li4/c;->f(JLjava/lang/Object;)V

    .line 338
    .line 339
    .line 340
    goto :goto_4

    .line 341
    :cond_16
    iget-object v0, v1, Lf8/s;->I1:Lf8/r;

    .line 342
    .line 343
    iget-object v0, v0, Lf8/r;->d:Li4/c;

    .line 344
    .line 345
    iget-object v4, v1, Lf8/s;->F:Lt7/o;

    .line 346
    .line 347
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 348
    .line 349
    .line 350
    invoke-virtual {v0, v5, v6, v4}, Li4/c;->f(JLjava/lang/Object;)V

    .line 351
    .line 352
    .line 353
    :goto_4
    iput-boolean v8, v1, Lf8/s;->E1:Z

    .line 354
    .line 355
    :cond_17
    iget-wide v14, v1, Lf8/s;->A1:J

    .line 356
    .line 357
    invoke-static {v14, v15, v5, v6}, Ljava/lang/Math;->max(JJ)J

    .line 358
    .line 359
    .line 360
    move-result-wide v14

    .line 361
    iput-wide v14, v1, Lf8/s;->A1:J

    .line 362
    .line 363
    invoke-virtual {v1}, La8/f;->l()Z

    .line 364
    .line 365
    .line 366
    move-result v0

    .line 367
    if-nez v0, :cond_18

    .line 368
    .line 369
    const/high16 v0, 0x20000000

    .line 370
    .line 371
    invoke-virtual {v10, v0}, Lkq/d;->c(I)Z

    .line 372
    .line 373
    .line 374
    move-result v0

    .line 375
    if-eqz v0, :cond_19

    .line 376
    .line 377
    :cond_18
    iget-wide v14, v1, Lf8/s;->A1:J

    .line 378
    .line 379
    iput-wide v14, v1, Lf8/s;->B1:J

    .line 380
    .line 381
    :cond_19
    invoke-virtual {v10}, Lz7/e;->p()V

    .line 382
    .line 383
    .line 384
    const/high16 v0, 0x10000000

    .line 385
    .line 386
    invoke-virtual {v10, v0}, Lkq/d;->c(I)Z

    .line 387
    .line 388
    .line 389
    move-result v0

    .line 390
    if-eqz v0, :cond_1a

    .line 391
    .line 392
    invoke-virtual {v1, v10}, Lf8/s;->R(Lz7/e;)V

    .line 393
    .line 394
    .line 395
    :cond_1a
    invoke-virtual {v1, v10}, Lf8/s;->f0(Lz7/e;)V

    .line 396
    .line 397
    .line 398
    invoke-virtual {v1, v10}, Lf8/s;->M(Lz7/e;)I

    .line 399
    .line 400
    .line 401
    move-result v7

    .line 402
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 403
    .line 404
    const/16 v4, 0x22

    .line 405
    .line 406
    if-lt v0, v4, :cond_1b

    .line 407
    .line 408
    and-int/lit8 v0, v7, 0x20

    .line 409
    .line 410
    if-nez v0, :cond_1c

    .line 411
    .line 412
    :cond_1b
    iget-object v0, v1, La8/f;->g:La8/o1;

    .line 413
    .line 414
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 415
    .line 416
    .line 417
    iget-boolean v0, v0, La8/o1;->b:Z

    .line 418
    .line 419
    if-nez v0, :cond_1c

    .line 420
    .line 421
    iget-wide v14, v1, Lf8/s;->O1:J

    .line 422
    .line 423
    iget-wide v8, v10, Lz7/e;->j:J

    .line 424
    .line 425
    invoke-static {v14, v15, v8, v9}, Ljava/lang/Math;->max(JJ)J

    .line 426
    .line 427
    .line 428
    move-result-wide v8

    .line 429
    iput-wide v8, v1, Lf8/s;->O1:J

    .line 430
    .line 431
    :cond_1c
    if-eqz v3, :cond_1d

    .line 432
    .line 433
    iget v3, v1, Lf8/s;->c0:I

    .line 434
    .line 435
    iget-object v4, v10, Lz7/e;->g:Lz7/b;

    .line 436
    .line 437
    invoke-interface/range {v2 .. v7}, Lf8/m;->e(ILz7/b;JI)V

    .line 438
    .line 439
    .line 440
    goto :goto_5

    .line 441
    :cond_1d
    move-wide v3, v5

    .line 442
    iget v5, v1, Lf8/s;->c0:I

    .line 443
    .line 444
    iget-object v0, v10, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 445
    .line 446
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 447
    .line 448
    .line 449
    invoke-virtual {v0}, Ljava/nio/Buffer;->limit()I

    .line 450
    .line 451
    .line 452
    move-result v6

    .line 453
    invoke-interface/range {v2 .. v7}, Lf8/m;->d(JIII)V

    .line 454
    .line 455
    .line 456
    :goto_5
    iput v12, v1, Lf8/s;->c0:I

    .line 457
    .line 458
    iput-object v11, v10, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 459
    .line 460
    iput-boolean v13, v1, Lf8/s;->x1:Z

    .line 461
    .line 462
    const/4 v2, 0x0

    .line 463
    iput v2, v1, Lf8/s;->u1:I

    .line 464
    .line 465
    iget-object v0, v1, Lf8/s;->H1:La8/g;

    .line 466
    .line 467
    iget v1, v0, La8/g;->c:I

    .line 468
    .line 469
    add-int/2addr v1, v13

    .line 470
    iput v1, v0, La8/g;->c:I

    .line 471
    .line 472
    return v13

    .line 473
    :catch_0
    move-exception v0

    .line 474
    move v2, v8

    .line 475
    invoke-virtual {v1, v0}, Lf8/s;->X(Ljava/lang/Exception;)V

    .line 476
    .line 477
    .line 478
    invoke-virtual {v1, v2}, Lf8/s;->i0(I)Z

    .line 479
    .line 480
    .line 481
    invoke-virtual {v1}, Lf8/s;->J()V

    .line 482
    .line 483
    .line 484
    return v13

    .line 485
    :goto_6
    return v2
.end method

.method public final J()V
    .locals 1

    .line 1
    :try_start_0
    iget-object v0, p0, Lf8/s;->O:Lf8/m;

    .line 2
    .line 3
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {v0}, Lf8/m;->flush()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Lf8/s;->m0()V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :catchall_0
    move-exception v0

    .line 14
    invoke-virtual {p0}, Lf8/s;->m0()V

    .line 15
    .line 16
    .line 17
    throw v0
.end method

.method public final K()Z
    .locals 9

    .line 1
    iget-object v0, p0, Lf8/s;->O:Lf8/m;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    invoke-virtual {p0}, Lf8/s;->t0()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v2, 0x1

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0}, Lf8/s;->j0()V

    .line 15
    .line 16
    .line 17
    return v2

    .line 18
    :cond_1
    invoke-virtual {p0}, Lf8/s;->r0()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    invoke-virtual {p0}, Lf8/s;->J()V

    .line 25
    .line 26
    .line 27
    return v1

    .line 28
    :cond_2
    iget-wide v3, p0, Lf8/s;->O1:J

    .line 29
    .line 30
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    cmp-long v0, v3, v5

    .line 36
    .line 37
    if-eqz v0, :cond_3

    .line 38
    .line 39
    iget-wide v7, p0, La8/f;->o:J

    .line 40
    .line 41
    cmp-long v0, v7, v3

    .line 42
    .line 43
    if-gtz v0, :cond_3

    .line 44
    .line 45
    iget-wide v7, p0, Lf8/s;->J1:J

    .line 46
    .line 47
    cmp-long v0, v7, v3

    .line 48
    .line 49
    if-gez v0, :cond_3

    .line 50
    .line 51
    iput-boolean v2, p0, Lf8/s;->M1:Z

    .line 52
    .line 53
    iput-wide v5, p0, Lf8/s;->O1:J

    .line 54
    .line 55
    :cond_3
    :goto_0
    return v1
.end method

.method public final L(Z)Ljava/util/List;
    .locals 4

    .line 1
    iget-object v0, p0, Lf8/s;->F:Lt7/o;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lf8/s;->w:Lf8/k;

    .line 7
    .line 8
    invoke-virtual {p0, v1, v0, p1}, Lf8/s;->O(Lf8/k;Lt7/o;Z)Ljava/util/ArrayList;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 13
    .line 14
    .line 15
    move-result v3

    .line 16
    if-eqz v3, :cond_1

    .line 17
    .line 18
    if-eqz p1, :cond_1

    .line 19
    .line 20
    const/4 p1, 0x0

    .line 21
    invoke-virtual {p0, v1, v0, p1}, Lf8/s;->O(Lf8/k;Lt7/o;Z)Ljava/util/ArrayList;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    if-nez p1, :cond_0

    .line 30
    .line 31
    new-instance p1, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    const-string v1, "Drm session requires secure decoder for "

    .line 34
    .line 35
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget-object v0, v0, Lt7/o;->n:Ljava/lang/String;

    .line 39
    .line 40
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v0, ", but no secure decoder available. Trying to proceed with "

    .line 44
    .line 45
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v0, "."

    .line 52
    .line 53
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    const-string v0, "MediaCodecRenderer"

    .line 61
    .line 62
    invoke-static {v0, p1}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    :cond_0
    return-object p0

    .line 66
    :cond_1
    return-object v2
.end method

.method public M(Lz7/e;)I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public abstract N(FLt7/o;[Lt7/o;)F
.end method

.method public abstract O(Lf8/k;Lt7/o;Z)Ljava/util/ArrayList;
.end method

.method public P(JJ)J
    .locals 0

    .line 1
    invoke-super {p0, p1, p2, p3, p4}, La8/f;->i(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public abstract Q(Lf8/p;Lt7/o;Landroid/media/MediaCrypto;F)Lu/x0;
.end method

.method public abstract R(Lz7/e;)V
.end method

.method public final S(Lf8/p;Landroid/media/MediaCrypto;)V
    .locals 11

    .line 1
    const-string v0, "createCodec:"

    .line 2
    .line 3
    iput-object p1, p0, Lf8/s;->V:Lf8/p;

    .line 4
    .line 5
    iget-object v1, p0, Lf8/s;->F:Lt7/o;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object v5, p1, Lf8/p;->a:Ljava/lang/String;

    .line 11
    .line 12
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 13
    .line 14
    iget v3, p0, Lf8/s;->N:F

    .line 15
    .line 16
    iget-object v4, p0, La8/f;->m:[Lt7/o;

    .line 17
    .line 18
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, v3, v1, v4}, Lf8/s;->N(FLt7/o;[Lt7/o;)F

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    iget v4, p0, Lf8/s;->x:F

    .line 26
    .line 27
    cmpg-float v4, v3, v4

    .line 28
    .line 29
    if-gtz v4, :cond_0

    .line 30
    .line 31
    const/high16 v3, -0x40800000    # -1.0f

    .line 32
    .line 33
    :cond_0
    iget-object v4, p0, La8/f;->j:Lw7/r;

    .line 34
    .line 35
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 39
    .line 40
    .line 41
    move-result-wide v6

    .line 42
    invoke-virtual {p0, p1, v1, p2, v3}, Lf8/s;->Q(Lf8/p;Lt7/o;Landroid/media/MediaCrypto;F)Lu/x0;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    const/16 v4, 0x1f

    .line 47
    .line 48
    if-lt v2, v4, :cond_1

    .line 49
    .line 50
    iget-object v4, p0, La8/f;->i:Lb8/k;

    .line 51
    .line 52
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v4}, Lb8/k;->a()Landroid/media/metrics/LogSessionId;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    invoke-static {}, Lb8/h;->a()Landroid/media/metrics/LogSessionId;

    .line 60
    .line 61
    .line 62
    invoke-static {v4}, Lb8/h;->y(Landroid/media/metrics/LogSessionId;)Z

    .line 63
    .line 64
    .line 65
    move-result v8

    .line 66
    if-nez v8, :cond_1

    .line 67
    .line 68
    iget-object v8, p2, Lu/x0;->b:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v8, Landroid/media/MediaFormat;

    .line 71
    .line 72
    const-string v9, "log-session-id"

    .line 73
    .line 74
    invoke-static {v4}, Lc4/a;->r(Landroid/media/metrics/LogSessionId;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    invoke-virtual {v8, v9, v4}, Landroid/media/MediaFormat;->setString(Ljava/lang/String;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    :cond_1
    :try_start_0
    new-instance v4, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    invoke-direct {v4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    iget-object v0, p0, Lf8/s;->v:Lf8/l;

    .line 97
    .line 98
    invoke-interface {v0, p2}, Lf8/l;->l(Lu/x0;)Lf8/m;

    .line 99
    .line 100
    .line 101
    move-result-object p2

    .line 102
    iput-object p2, p0, Lf8/s;->O:Lf8/m;

    .line 103
    .line 104
    new-instance v0, Lbu/c;

    .line 105
    .line 106
    const/16 v4, 0x14

    .line 107
    .line 108
    invoke-direct {v0, p0, v4}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 109
    .line 110
    .line 111
    invoke-interface {p2, v0}, Lf8/m;->i(Lbu/c;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 112
    .line 113
    .line 114
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 115
    .line 116
    .line 117
    iget-object p2, p0, La8/f;->j:Lw7/r;

    .line 118
    .line 119
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 120
    .line 121
    .line 122
    move p2, v3

    .line 123
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 124
    .line 125
    .line 126
    move-result-wide v3

    .line 127
    invoke-virtual {p1, v1}, Lf8/p;->e(Lt7/o;)Z

    .line 128
    .line 129
    .line 130
    move-result v0

    .line 131
    if-nez v0, :cond_2

    .line 132
    .line 133
    invoke-static {v1}, Lt7/o;->c(Lt7/o;)Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    sget-object v8, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 138
    .line 139
    const-string v8, ", "

    .line 140
    .line 141
    const-string v9, "]"

    .line 142
    .line 143
    const-string v10, "Format exceeds selected codec\'s capabilities ["

    .line 144
    .line 145
    invoke-static {v10, v0, v8, v5, v9}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    const-string v8, "MediaCodecRenderer"

    .line 150
    .line 151
    invoke-static {v8, v0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 152
    .line 153
    .line 154
    :cond_2
    iput p2, p0, Lf8/s;->S:F

    .line 155
    .line 156
    iput-object v1, p0, Lf8/s;->P:Lt7/o;

    .line 157
    .line 158
    const/16 p2, 0x1d

    .line 159
    .line 160
    const/4 v0, 0x1

    .line 161
    const/4 v1, 0x0

    .line 162
    if-ne v2, p2, :cond_3

    .line 163
    .line 164
    const-string v8, "c2.android.aac.decoder"

    .line 165
    .line 166
    invoke-virtual {v8, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v8

    .line 170
    if-eqz v8, :cond_3

    .line 171
    .line 172
    move v8, v0

    .line 173
    goto :goto_0

    .line 174
    :cond_3
    move v8, v1

    .line 175
    :goto_0
    iput-boolean v8, p0, Lf8/s;->W:Z

    .line 176
    .line 177
    iget-object v8, p1, Lf8/p;->a:Ljava/lang/String;

    .line 178
    .line 179
    if-gt v2, p2, :cond_4

    .line 180
    .line 181
    const-string p2, "OMX.broadcom.video_decoder.tunnel"

    .line 182
    .line 183
    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    move-result p2

    .line 187
    if-nez p2, :cond_5

    .line 188
    .line 189
    const-string p2, "OMX.broadcom.video_decoder.tunnel.secure"

    .line 190
    .line 191
    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    move-result p2

    .line 195
    if-nez p2, :cond_5

    .line 196
    .line 197
    const-string p2, "OMX.bcm.vdec.avc.tunnel"

    .line 198
    .line 199
    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result p2

    .line 203
    if-nez p2, :cond_5

    .line 204
    .line 205
    const-string p2, "OMX.bcm.vdec.avc.tunnel.secure"

    .line 206
    .line 207
    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-result p2

    .line 211
    if-nez p2, :cond_5

    .line 212
    .line 213
    const-string p2, "OMX.bcm.vdec.hevc.tunnel"

    .line 214
    .line 215
    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result p2

    .line 219
    if-nez p2, :cond_5

    .line 220
    .line 221
    const-string p2, "OMX.bcm.vdec.hevc.tunnel.secure"

    .line 222
    .line 223
    invoke-virtual {p2, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result p2

    .line 227
    if-nez p2, :cond_5

    .line 228
    .line 229
    :cond_4
    const-string p2, "Amazon"

    .line 230
    .line 231
    sget-object v2, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    .line 232
    .line 233
    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result p2

    .line 237
    if-eqz p2, :cond_6

    .line 238
    .line 239
    const-string p2, "AFTS"

    .line 240
    .line 241
    sget-object v2, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 242
    .line 243
    invoke-virtual {p2, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result p2

    .line 247
    if-eqz p2, :cond_6

    .line 248
    .line 249
    iget-boolean p1, p1, Lf8/p;->f:Z

    .line 250
    .line 251
    if-eqz p1, :cond_6

    .line 252
    .line 253
    :cond_5
    move v1, v0

    .line 254
    :cond_6
    iput-boolean v1, p0, Lf8/s;->Z:Z

    .line 255
    .line 256
    iget-object p1, p0, Lf8/s;->O:Lf8/m;

    .line 257
    .line 258
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 259
    .line 260
    .line 261
    iget p1, p0, La8/f;->k:I

    .line 262
    .line 263
    const/4 p2, 0x2

    .line 264
    if-ne p1, p2, :cond_7

    .line 265
    .line 266
    iget-object p1, p0, La8/f;->j:Lw7/r;

    .line 267
    .line 268
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 269
    .line 270
    .line 271
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 272
    .line 273
    .line 274
    move-result-wide p1

    .line 275
    const-wide/16 v1, 0x3e8

    .line 276
    .line 277
    add-long/2addr p1, v1

    .line 278
    iput-wide p1, p0, Lf8/s;->b0:J

    .line 279
    .line 280
    :cond_7
    iget-object p1, p0, Lf8/s;->H1:La8/g;

    .line 281
    .line 282
    iget p2, p1, La8/g;->a:I

    .line 283
    .line 284
    add-int/2addr p2, v0

    .line 285
    iput p2, p1, La8/g;->a:I

    .line 286
    .line 287
    sub-long v6, v3, v6

    .line 288
    .line 289
    move-object v2, p0

    .line 290
    invoke-virtual/range {v2 .. v7}, Lf8/s;->Y(JLjava/lang/String;J)V

    .line 291
    .line 292
    .line 293
    return-void

    .line 294
    :catchall_0
    move-exception v0

    .line 295
    move-object p0, v0

    .line 296
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 297
    .line 298
    .line 299
    throw p0
.end method

.method public final T(JJ)Z
    .locals 1

    .line 1
    cmp-long v0, p3, p1

    .line 2
    .line 3
    if-gez v0, :cond_1

    .line 4
    .line 5
    iget-object p0, p0, Lf8/s;->G:Lt7/o;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lt7/o;->n:Ljava/lang/String;

    .line 10
    .line 11
    const-string v0, "audio/opus"

    .line 12
    .line 13
    invoke-static {p0, v0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    sub-long/2addr p1, p3

    .line 20
    const-wide/32 p3, 0x13880

    .line 21
    .line 22
    .line 23
    cmp-long p0, p1, p3

    .line 24
    .line 25
    if-gtz p0, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p0, 0x1

    .line 29
    return p0

    .line 30
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 31
    return p0
.end method

.method public final U()V
    .locals 9

    .line 1
    iget-object v0, p0, Lf8/s;->O:Lf8/m;

    .line 2
    .line 3
    if-nez v0, :cond_b

    .line 4
    .line 5
    iget-boolean v0, p0, Lf8/s;->q1:Z

    .line 6
    .line 7
    if-nez v0, :cond_b

    .line 8
    .line 9
    iget-object v0, p0, Lf8/s;->F:Lt7/o;

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    goto/16 :goto_7

    .line 14
    .line 15
    :cond_0
    iget-object v1, v0, Lt7/o;->n:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v2, p0, Lf8/s;->I:Laq/a;

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    const/4 v4, 0x1

    .line 21
    if-nez v2, :cond_2

    .line 22
    .line 23
    invoke-virtual {p0, v0}, Lf8/s;->u0(Lt7/o;)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-eqz v2, :cond_2

    .line 28
    .line 29
    iput-boolean v3, p0, Lf8/s;->q1:Z

    .line 30
    .line 31
    invoke-virtual {p0}, Lf8/s;->l0()V

    .line 32
    .line 33
    .line 34
    const-string v0, "audio/mp4a-latm"

    .line 35
    .line 36
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-object v2, p0, Lf8/s;->B:Lf8/i;

    .line 41
    .line 42
    if-nez v0, :cond_1

    .line 43
    .line 44
    const-string v0, "audio/mpeg"

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-nez v0, :cond_1

    .line 51
    .line 52
    const-string v0, "audio/opus"

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-nez v0, :cond_1

    .line 59
    .line 60
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    iput v4, v2, Lf8/i;->o:I

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_1
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    const/16 v0, 0x20

    .line 70
    .line 71
    iput v0, v2, Lf8/i;->o:I

    .line 72
    .line 73
    :goto_0
    iput-boolean v4, p0, Lf8/s;->q1:Z

    .line 74
    .line 75
    return-void

    .line 76
    :cond_2
    iget-object v2, p0, Lf8/s;->I:Laq/a;

    .line 77
    .line 78
    invoke-virtual {p0, v2}, Lf8/s;->o0(Laq/a;)V

    .line 79
    .line 80
    .line 81
    iget-object v2, p0, Lf8/s;->H:Laq/a;

    .line 82
    .line 83
    const/4 v5, 0x0

    .line 84
    const/4 v6, 0x4

    .line 85
    if-eqz v2, :cond_7

    .line 86
    .line 87
    iget-object v2, p0, Lf8/s;->K:Landroid/media/MediaCrypto;

    .line 88
    .line 89
    if-nez v2, :cond_3

    .line 90
    .line 91
    move v2, v4

    .line 92
    goto :goto_1

    .line 93
    :cond_3
    move v2, v3

    .line 94
    :goto_1
    invoke-static {v2}, Lw7/a;->j(Z)V

    .line 95
    .line 96
    .line 97
    iget-object v2, p0, Lf8/s;->H:Laq/a;

    .line 98
    .line 99
    invoke-virtual {v2}, Laq/a;->m()Lz7/a;

    .line 100
    .line 101
    .line 102
    move-result-object v7

    .line 103
    sget-boolean v8, Ld8/k;->a:Z

    .line 104
    .line 105
    if-eqz v8, :cond_5

    .line 106
    .line 107
    instance-of v8, v7, Ld8/k;

    .line 108
    .line 109
    if-eqz v8, :cond_5

    .line 110
    .line 111
    invoke-virtual {v2}, Laq/a;->w()I

    .line 112
    .line 113
    .line 114
    move-result v8

    .line 115
    if-eq v8, v4, :cond_4

    .line 116
    .line 117
    if-eq v8, v6, :cond_5

    .line 118
    .line 119
    goto :goto_5

    .line 120
    :cond_4
    invoke-virtual {v2}, Laq/a;->n()Ld8/d;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 125
    .line 126
    .line 127
    iget-object v1, p0, Lf8/s;->F:Lt7/o;

    .line 128
    .line 129
    iget v2, v0, Ld8/d;->d:I

    .line 130
    .line 131
    invoke-virtual {p0, v0, v1, v3, v2}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    throw p0

    .line 136
    :cond_5
    if-nez v7, :cond_6

    .line 137
    .line 138
    invoke-virtual {v2}, Laq/a;->n()Ld8/d;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    if-eqz v2, :cond_a

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_6
    instance-of v2, v7, Ld8/k;

    .line 146
    .line 147
    if-eqz v2, :cond_7

    .line 148
    .line 149
    check-cast v7, Ld8/k;

    .line 150
    .line 151
    :try_start_0
    new-instance v2, Landroid/media/MediaCrypto;

    .line 152
    .line 153
    const/4 v7, 0x0

    .line 154
    invoke-direct {v2, v5, v7}, Landroid/media/MediaCrypto;-><init>(Ljava/util/UUID;[B)V

    .line 155
    .line 156
    .line 157
    iput-object v2, p0, Lf8/s;->K:Landroid/media/MediaCrypto;
    :try_end_0
    .catch Landroid/media/MediaCryptoException; {:try_start_0 .. :try_end_0} :catch_0

    .line 158
    .line 159
    goto :goto_2

    .line 160
    :catch_0
    move-exception v0

    .line 161
    iget-object v1, p0, Lf8/s;->F:Lt7/o;

    .line 162
    .line 163
    const/16 v2, 0x1776

    .line 164
    .line 165
    invoke-virtual {p0, v0, v1, v3, v2}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    throw p0

    .line 170
    :cond_7
    :goto_2
    :try_start_1
    iget-object v2, p0, Lf8/s;->H:Laq/a;

    .line 171
    .line 172
    if-eqz v2, :cond_9

    .line 173
    .line 174
    invoke-virtual {v2}, Laq/a;->w()I

    .line 175
    .line 176
    .line 177
    move-result v2

    .line 178
    const/4 v7, 0x3

    .line 179
    if-eq v2, v7, :cond_8

    .line 180
    .line 181
    iget-object v2, p0, Lf8/s;->H:Laq/a;

    .line 182
    .line 183
    invoke-virtual {v2}, Laq/a;->w()I

    .line 184
    .line 185
    .line 186
    move-result v2

    .line 187
    if-ne v2, v6, :cond_9

    .line 188
    .line 189
    goto :goto_3

    .line 190
    :catch_1
    move-exception v1

    .line 191
    goto :goto_6

    .line 192
    :cond_8
    :goto_3
    iget-object v2, p0, Lf8/s;->H:Laq/a;

    .line 193
    .line 194
    invoke-static {v1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v2, v1}, Laq/a;->F(Ljava/lang/String;)Z

    .line 198
    .line 199
    .line 200
    move-result v1

    .line 201
    if-eqz v1, :cond_9

    .line 202
    .line 203
    goto :goto_4

    .line 204
    :cond_9
    move v4, v3

    .line 205
    :goto_4
    iget-object v1, p0, Lf8/s;->K:Landroid/media/MediaCrypto;

    .line 206
    .line 207
    invoke-virtual {p0, v1, v4}, Lf8/s;->V(Landroid/media/MediaCrypto;Z)V
    :try_end_1
    .catch Lf8/q; {:try_start_1 .. :try_end_1} :catch_1

    .line 208
    .line 209
    .line 210
    :cond_a
    :goto_5
    iget-object v0, p0, Lf8/s;->K:Landroid/media/MediaCrypto;

    .line 211
    .line 212
    if-eqz v0, :cond_b

    .line 213
    .line 214
    iget-object v1, p0, Lf8/s;->O:Lf8/m;

    .line 215
    .line 216
    if-nez v1, :cond_b

    .line 217
    .line 218
    invoke-virtual {v0}, Landroid/media/MediaCrypto;->release()V

    .line 219
    .line 220
    .line 221
    iput-object v5, p0, Lf8/s;->K:Landroid/media/MediaCrypto;

    .line 222
    .line 223
    return-void

    .line 224
    :goto_6
    const/16 v2, 0xfa1

    .line 225
    .line 226
    invoke-virtual {p0, v1, v0, v3, v2}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    throw p0

    .line 231
    :cond_b
    :goto_7
    return-void
.end method

.method public final V(Landroid/media/MediaCrypto;Z)V
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v6, p2

    .line 4
    .line 5
    iget-object v9, v1, Lf8/s;->F:Lt7/o;

    .line 6
    .line 7
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object v0, v1, Lf8/s;->T:Ljava/util/ArrayDeque;

    .line 11
    .line 12
    const/4 v10, 0x0

    .line 13
    if-nez v0, :cond_1

    .line 14
    .line 15
    :try_start_0
    invoke-virtual {v1, v6}, Lf8/s;->L(Z)Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    new-instance v2, Ljava/util/ArrayDeque;

    .line 20
    .line 21
    invoke-direct {v2}, Ljava/util/ArrayDeque;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object v2, v1, Lf8/s;->T:Ljava/util/ArrayDeque;

    .line 25
    .line 26
    check-cast v0, Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-nez v2, :cond_0

    .line 33
    .line 34
    iget-object v2, v1, Lf8/s;->T:Ljava/util/ArrayDeque;

    .line 35
    .line 36
    const/4 v3, 0x0

    .line 37
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    check-cast v0, Lf8/p;

    .line 42
    .line 43
    invoke-virtual {v2, v0}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :catch_0
    move-exception v0

    .line 48
    goto :goto_1

    .line 49
    :cond_0
    :goto_0
    iput-object v10, v1, Lf8/s;->U:Lf8/q;
    :try_end_0
    .catch Lf8/u; {:try_start_0 .. :try_end_0} :catch_0

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :goto_1
    new-instance v1, Lf8/q;

    .line 53
    .line 54
    const v2, -0xc34e

    .line 55
    .line 56
    .line 57
    invoke-direct {v1, v9, v0, v6, v2}, Lf8/q;-><init>(Lt7/o;Lf8/u;ZI)V

    .line 58
    .line 59
    .line 60
    throw v1

    .line 61
    :cond_1
    :goto_2
    iget-object v0, v1, Lf8/s;->T:Ljava/util/ArrayDeque;

    .line 62
    .line 63
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-nez v0, :cond_8

    .line 68
    .line 69
    iget-object v11, v1, Lf8/s;->T:Ljava/util/ArrayDeque;

    .line 70
    .line 71
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    :goto_3
    iget-object v0, v1, Lf8/s;->O:Lf8/m;

    .line 75
    .line 76
    if-nez v0, :cond_7

    .line 77
    .line 78
    invoke-virtual {v11}, Ljava/util/ArrayDeque;->peekFirst()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    move-object v7, v0

    .line 83
    check-cast v7, Lf8/p;

    .line 84
    .line 85
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v1, v9}, Lf8/s;->W(Lt7/o;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-nez v0, :cond_2

    .line 93
    .line 94
    goto :goto_4

    .line 95
    :cond_2
    invoke-virtual {v1, v7}, Lf8/s;->s0(Lf8/p;)Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-nez v0, :cond_3

    .line 100
    .line 101
    :goto_4
    return-void

    .line 102
    :cond_3
    move-object/from16 v12, p1

    .line 103
    .line 104
    :try_start_1
    invoke-virtual {v1, v7, v12}, Lf8/s;->S(Lf8/p;Landroid/media/MediaCrypto;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 105
    .line 106
    .line 107
    goto :goto_3

    .line 108
    :catch_1
    move-exception v0

    .line 109
    move-object v4, v0

    .line 110
    new-instance v0, Ljava/lang/StringBuilder;

    .line 111
    .line 112
    const-string v2, "Failed to initialize decoder: "

    .line 113
    .line 114
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    const-string v2, "MediaCodecRenderer"

    .line 125
    .line 126
    invoke-static {v2, v0, v4}, Lw7/a;->z(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v11}, Ljava/util/ArrayDeque;->removeFirst()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    new-instance v2, Lf8/q;

    .line 133
    .line 134
    new-instance v0, Ljava/lang/StringBuilder;

    .line 135
    .line 136
    const-string v3, "Decoder init failed: "

    .line 137
    .line 138
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    iget-object v3, v7, Lf8/p;->a:Ljava/lang/String;

    .line 142
    .line 143
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    const-string v3, ", "

    .line 147
    .line 148
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    iget-object v5, v9, Lt7/o;->n:Ljava/lang/String;

    .line 159
    .line 160
    instance-of v0, v4, Landroid/media/MediaCodec$CodecException;

    .line 161
    .line 162
    if-eqz v0, :cond_4

    .line 163
    .line 164
    move-object v0, v4

    .line 165
    check-cast v0, Landroid/media/MediaCodec$CodecException;

    .line 166
    .line 167
    invoke-virtual {v0}, Landroid/media/MediaCodec$CodecException;->getDiagnosticInfo()Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    move-object v8, v0

    .line 172
    goto :goto_5

    .line 173
    :cond_4
    move-object v8, v10

    .line 174
    :goto_5
    invoke-direct/range {v2 .. v8}, Lf8/q;-><init>(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;ZLf8/p;Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v1, v2}, Lf8/s;->X(Ljava/lang/Exception;)V

    .line 178
    .line 179
    .line 180
    iget-object v0, v1, Lf8/s;->U:Lf8/q;

    .line 181
    .line 182
    if-nez v0, :cond_5

    .line 183
    .line 184
    iput-object v2, v1, Lf8/s;->U:Lf8/q;

    .line 185
    .line 186
    goto :goto_6

    .line 187
    :cond_5
    new-instance v13, Lf8/q;

    .line 188
    .line 189
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v14

    .line 193
    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 194
    .line 195
    .line 196
    move-result-object v15

    .line 197
    iget-object v2, v0, Lf8/q;->d:Ljava/lang/String;

    .line 198
    .line 199
    iget-boolean v3, v0, Lf8/q;->e:Z

    .line 200
    .line 201
    iget-object v4, v0, Lf8/q;->f:Lf8/p;

    .line 202
    .line 203
    iget-object v0, v0, Lf8/q;->g:Ljava/lang/String;

    .line 204
    .line 205
    move-object/from16 v19, v0

    .line 206
    .line 207
    move-object/from16 v16, v2

    .line 208
    .line 209
    move/from16 v17, v3

    .line 210
    .line 211
    move-object/from16 v18, v4

    .line 212
    .line 213
    invoke-direct/range {v13 .. v19}, Lf8/q;-><init>(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;ZLf8/p;Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    iput-object v13, v1, Lf8/s;->U:Lf8/q;

    .line 217
    .line 218
    :goto_6
    invoke-virtual {v11}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 219
    .line 220
    .line 221
    move-result v0

    .line 222
    if-nez v0, :cond_6

    .line 223
    .line 224
    goto/16 :goto_3

    .line 225
    .line 226
    :cond_6
    iget-object v0, v1, Lf8/s;->U:Lf8/q;

    .line 227
    .line 228
    throw v0

    .line 229
    :cond_7
    iput-object v10, v1, Lf8/s;->T:Ljava/util/ArrayDeque;

    .line 230
    .line 231
    return-void

    .line 232
    :cond_8
    new-instance v0, Lf8/q;

    .line 233
    .line 234
    const v1, -0xc34f

    .line 235
    .line 236
    .line 237
    invoke-direct {v0, v9, v10, v6, v1}, Lf8/q;-><init>(Lt7/o;Lf8/u;ZI)V

    .line 238
    .line 239
    .line 240
    throw v0
.end method

.method public W(Lt7/o;)Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public abstract X(Ljava/lang/Exception;)V
.end method

.method public abstract Y(JLjava/lang/String;J)V
.end method

.method public abstract Z(Ljava/lang/String;)V
.end method

.method public a0(Lb81/d;)La8/h;
    .locals 12

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lf8/s;->E1:Z

    .line 3
    .line 4
    iget-object v1, p1, Lb81/d;->f:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v1, Lt7/o;

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget-object v2, v1, Lt7/o;->n:Ljava/lang/String;

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    if-eqz v2, :cond_1f

    .line 15
    .line 16
    const-string v4, "video/av01"

    .line 17
    .line 18
    invoke-virtual {v2, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v4

    .line 22
    const/4 v5, 0x0

    .line 23
    if-nez v4, :cond_0

    .line 24
    .line 25
    const-string v4, "video/x-vnd.on2.vp9"

    .line 26
    .line 27
    invoke-virtual {v2, v4}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_1

    .line 32
    .line 33
    :cond_0
    iget-object v2, v1, Lt7/o;->q:Ljava/util/List;

    .line 34
    .line 35
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-nez v2, :cond_1

    .line 40
    .line 41
    invoke-virtual {v1}, Lt7/o;->a()Lt7/n;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    iput-object v5, v1, Lt7/n;->p:Ljava/util/List;

    .line 46
    .line 47
    new-instance v2, Lt7/o;

    .line 48
    .line 49
    invoke-direct {v2, v1}, Lt7/o;-><init>(Lt7/n;)V

    .line 50
    .line 51
    .line 52
    move-object v9, v2

    .line 53
    goto :goto_0

    .line 54
    :cond_1
    move-object v9, v1

    .line 55
    :goto_0
    iget-object p1, p1, Lb81/d;->e:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p1, Laq/a;

    .line 58
    .line 59
    iget-object v1, p0, Lf8/s;->I:Laq/a;

    .line 60
    .line 61
    if-ne v1, p1, :cond_2

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    if-eqz p1, :cond_3

    .line 65
    .line 66
    invoke-virtual {p1, v5}, Laq/a;->i(Ld8/f;)V

    .line 67
    .line 68
    .line 69
    :cond_3
    if-eqz v1, :cond_4

    .line 70
    .line 71
    invoke-virtual {v1, v5}, Laq/a;->E(Ld8/f;)V

    .line 72
    .line 73
    .line 74
    :cond_4
    :goto_1
    iput-object p1, p0, Lf8/s;->I:Laq/a;

    .line 75
    .line 76
    iput-object v9, p0, Lf8/s;->F:Lt7/o;

    .line 77
    .line 78
    iget-boolean p1, p0, Lf8/s;->q1:Z

    .line 79
    .line 80
    if-eqz p1, :cond_5

    .line 81
    .line 82
    iput-boolean v0, p0, Lf8/s;->s1:Z

    .line 83
    .line 84
    return-object v5

    .line 85
    :cond_5
    iget-object p1, p0, Lf8/s;->O:Lf8/m;

    .line 86
    .line 87
    if-nez p1, :cond_6

    .line 88
    .line 89
    iput-object v5, p0, Lf8/s;->T:Ljava/util/ArrayDeque;

    .line 90
    .line 91
    invoke-virtual {p0}, Lf8/s;->U()V

    .line 92
    .line 93
    .line 94
    return-object v5

    .line 95
    :cond_6
    iget-object v1, p0, Lf8/s;->V:Lf8/p;

    .line 96
    .line 97
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 98
    .line 99
    .line 100
    iget-object v8, p0, Lf8/s;->P:Lt7/o;

    .line 101
    .line 102
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    iget-object v2, p0, Lf8/s;->H:Laq/a;

    .line 106
    .line 107
    iget-object v4, p0, Lf8/s;->I:Laq/a;

    .line 108
    .line 109
    const/4 v5, 0x3

    .line 110
    const/4 v6, 0x2

    .line 111
    if-ne v2, v4, :cond_7

    .line 112
    .line 113
    goto/16 :goto_2

    .line 114
    .line 115
    :cond_7
    if-eqz v4, :cond_1d

    .line 116
    .line 117
    if-nez v2, :cond_8

    .line 118
    .line 119
    goto/16 :goto_7

    .line 120
    .line 121
    :cond_8
    invoke-virtual {v4}, Laq/a;->m()Lz7/a;

    .line 122
    .line 123
    .line 124
    move-result-object v7

    .line 125
    if-nez v7, :cond_9

    .line 126
    .line 127
    goto/16 :goto_7

    .line 128
    .line 129
    :cond_9
    invoke-virtual {v2}, Laq/a;->m()Lz7/a;

    .line 130
    .line 131
    .line 132
    move-result-object v10

    .line 133
    if-eqz v10, :cond_1d

    .line 134
    .line 135
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 136
    .line 137
    .line 138
    move-result-object v11

    .line 139
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    move-result-object v10

    .line 143
    invoke-virtual {v11, v10}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v10

    .line 147
    if-nez v10, :cond_a

    .line 148
    .line 149
    goto/16 :goto_7

    .line 150
    .line 151
    :cond_a
    instance-of v7, v7, Ld8/k;

    .line 152
    .line 153
    if-nez v7, :cond_b

    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_b
    invoke-virtual {v4}, Laq/a;->v()Ljava/util/UUID;

    .line 157
    .line 158
    .line 159
    move-result-object v7

    .line 160
    invoke-virtual {v2}, Laq/a;->v()Ljava/util/UUID;

    .line 161
    .line 162
    .line 163
    move-result-object v10

    .line 164
    invoke-virtual {v7, v10}, Ljava/util/UUID;->equals(Ljava/lang/Object;)Z

    .line 165
    .line 166
    .line 167
    move-result v7

    .line 168
    if-nez v7, :cond_c

    .line 169
    .line 170
    goto/16 :goto_7

    .line 171
    .line 172
    :cond_c
    sget-object v7, Lt7/e;->e:Ljava/util/UUID;

    .line 173
    .line 174
    invoke-virtual {v2}, Laq/a;->v()Ljava/util/UUID;

    .line 175
    .line 176
    .line 177
    move-result-object v2

    .line 178
    invoke-virtual {v7, v2}, Ljava/util/UUID;->equals(Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v2

    .line 182
    if-nez v2, :cond_1d

    .line 183
    .line 184
    invoke-virtual {v4}, Laq/a;->v()Ljava/util/UUID;

    .line 185
    .line 186
    .line 187
    move-result-object v2

    .line 188
    invoke-virtual {v7, v2}, Ljava/util/UUID;->equals(Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result v2

    .line 192
    if-eqz v2, :cond_d

    .line 193
    .line 194
    goto/16 :goto_7

    .line 195
    .line 196
    :cond_d
    iget-boolean v2, v1, Lf8/p;->f:Z

    .line 197
    .line 198
    if-nez v2, :cond_f

    .line 199
    .line 200
    invoke-virtual {v4}, Laq/a;->w()I

    .line 201
    .line 202
    .line 203
    move-result v2

    .line 204
    if-eq v2, v6, :cond_1d

    .line 205
    .line 206
    invoke-virtual {v4}, Laq/a;->w()I

    .line 207
    .line 208
    .line 209
    move-result v2

    .line 210
    if-eq v2, v5, :cond_e

    .line 211
    .line 212
    invoke-virtual {v4}, Laq/a;->w()I

    .line 213
    .line 214
    .line 215
    move-result v2

    .line 216
    const/4 v7, 0x4

    .line 217
    if-ne v2, v7, :cond_f

    .line 218
    .line 219
    :cond_e
    iget-object v2, v9, Lt7/o;->n:Ljava/lang/String;

    .line 220
    .line 221
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 222
    .line 223
    .line 224
    invoke-virtual {v4, v2}, Laq/a;->F(Ljava/lang/String;)Z

    .line 225
    .line 226
    .line 227
    move-result v2

    .line 228
    if-eqz v2, :cond_f

    .line 229
    .line 230
    goto/16 :goto_7

    .line 231
    .line 232
    :cond_f
    :goto_2
    iget-object v2, p0, Lf8/s;->I:Laq/a;

    .line 233
    .line 234
    iget-object v4, p0, Lf8/s;->H:Laq/a;

    .line 235
    .line 236
    if-eq v2, v4, :cond_10

    .line 237
    .line 238
    move v2, v0

    .line 239
    goto :goto_3

    .line 240
    :cond_10
    move v2, v3

    .line 241
    :goto_3
    invoke-virtual {p0, v1, v8, v9}, Lf8/s;->E(Lf8/p;Lt7/o;Lt7/o;)La8/h;

    .line 242
    .line 243
    .line 244
    move-result-object v4

    .line 245
    iget v7, v4, La8/h;->d:I

    .line 246
    .line 247
    if-eqz v7, :cond_18

    .line 248
    .line 249
    const/16 v10, 0x10

    .line 250
    .line 251
    if-eq v7, v0, :cond_15

    .line 252
    .line 253
    if-eq v7, v6, :cond_13

    .line 254
    .line 255
    if-ne v7, v5, :cond_12

    .line 256
    .line 257
    invoke-virtual {p0, v9}, Lf8/s;->w0(Lt7/o;)Z

    .line 258
    .line 259
    .line 260
    move-result v0

    .line 261
    if-nez v0, :cond_11

    .line 262
    .line 263
    :goto_4
    move v11, v10

    .line 264
    goto :goto_6

    .line 265
    :cond_11
    iput-object v9, p0, Lf8/s;->P:Lt7/o;

    .line 266
    .line 267
    if-eqz v2, :cond_1a

    .line 268
    .line 269
    invoke-virtual {p0}, Lf8/s;->G()Z

    .line 270
    .line 271
    .line 272
    goto :goto_5

    .line 273
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 274
    .line 275
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 276
    .line 277
    .line 278
    throw p0

    .line 279
    :cond_13
    invoke-virtual {p0, v9}, Lf8/s;->w0(Lt7/o;)Z

    .line 280
    .line 281
    .line 282
    move-result v6

    .line 283
    if-nez v6, :cond_14

    .line 284
    .line 285
    goto :goto_4

    .line 286
    :cond_14
    iput-boolean v0, p0, Lf8/s;->t1:Z

    .line 287
    .line 288
    iput v0, p0, Lf8/s;->u1:I

    .line 289
    .line 290
    iput-boolean v3, p0, Lf8/s;->X:Z

    .line 291
    .line 292
    iput-object v9, p0, Lf8/s;->P:Lt7/o;

    .line 293
    .line 294
    if-eqz v2, :cond_1a

    .line 295
    .line 296
    invoke-virtual {p0}, Lf8/s;->G()Z

    .line 297
    .line 298
    .line 299
    goto :goto_5

    .line 300
    :cond_15
    invoke-virtual {p0, v9}, Lf8/s;->w0(Lt7/o;)Z

    .line 301
    .line 302
    .line 303
    move-result v6

    .line 304
    if-nez v6, :cond_16

    .line 305
    .line 306
    goto :goto_4

    .line 307
    :cond_16
    iput-object v9, p0, Lf8/s;->P:Lt7/o;

    .line 308
    .line 309
    if-eqz v2, :cond_17

    .line 310
    .line 311
    invoke-virtual {p0}, Lf8/s;->G()Z

    .line 312
    .line 313
    .line 314
    goto :goto_5

    .line 315
    :cond_17
    iget-boolean v2, p0, Lf8/s;->x1:Z

    .line 316
    .line 317
    if-eqz v2, :cond_1a

    .line 318
    .line 319
    iput v0, p0, Lf8/s;->v1:I

    .line 320
    .line 321
    iput v0, p0, Lf8/s;->w1:I

    .line 322
    .line 323
    goto :goto_5

    .line 324
    :cond_18
    iget-boolean v2, p0, Lf8/s;->x1:Z

    .line 325
    .line 326
    if-eqz v2, :cond_19

    .line 327
    .line 328
    iput v0, p0, Lf8/s;->v1:I

    .line 329
    .line 330
    iput v5, p0, Lf8/s;->w1:I

    .line 331
    .line 332
    goto :goto_5

    .line 333
    :cond_19
    invoke-virtual {p0}, Lf8/s;->j0()V

    .line 334
    .line 335
    .line 336
    invoke-virtual {p0}, Lf8/s;->U()V

    .line 337
    .line 338
    .line 339
    :cond_1a
    :goto_5
    move v11, v3

    .line 340
    :goto_6
    if-eqz v7, :cond_1c

    .line 341
    .line 342
    iget-object v0, p0, Lf8/s;->O:Lf8/m;

    .line 343
    .line 344
    if-ne v0, p1, :cond_1b

    .line 345
    .line 346
    iget p0, p0, Lf8/s;->w1:I

    .line 347
    .line 348
    if-ne p0, v5, :cond_1c

    .line 349
    .line 350
    :cond_1b
    new-instance v6, La8/h;

    .line 351
    .line 352
    iget-object v7, v1, Lf8/p;->a:Ljava/lang/String;

    .line 353
    .line 354
    const/4 v10, 0x0

    .line 355
    invoke-direct/range {v6 .. v11}, La8/h;-><init>(Ljava/lang/String;Lt7/o;Lt7/o;II)V

    .line 356
    .line 357
    .line 358
    return-object v6

    .line 359
    :cond_1c
    return-object v4

    .line 360
    :cond_1d
    :goto_7
    iget-boolean p1, p0, Lf8/s;->x1:Z

    .line 361
    .line 362
    if-eqz p1, :cond_1e

    .line 363
    .line 364
    iput v0, p0, Lf8/s;->v1:I

    .line 365
    .line 366
    iput v5, p0, Lf8/s;->w1:I

    .line 367
    .line 368
    goto :goto_8

    .line 369
    :cond_1e
    invoke-virtual {p0}, Lf8/s;->j0()V

    .line 370
    .line 371
    .line 372
    invoke-virtual {p0}, Lf8/s;->U()V

    .line 373
    .line 374
    .line 375
    :goto_8
    new-instance v6, La8/h;

    .line 376
    .line 377
    iget-object v7, v1, Lf8/p;->a:Ljava/lang/String;

    .line 378
    .line 379
    const/4 v10, 0x0

    .line 380
    const/16 v11, 0x80

    .line 381
    .line 382
    invoke-direct/range {v6 .. v11}, La8/h;-><init>(Ljava/lang/String;Lt7/o;Lt7/o;II)V

    .line 383
    .line 384
    .line 385
    return-object v6

    .line 386
    :cond_1f
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 387
    .line 388
    const-string v0, "Sample MIME type is null."

    .line 389
    .line 390
    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    const/16 v0, 0xfa5

    .line 394
    .line 395
    invoke-virtual {p0, p1, v1, v3, v0}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 396
    .line 397
    .line 398
    move-result-object p0

    .line 399
    throw p0
.end method

.method public abstract b0(Lt7/o;Landroid/media/MediaFormat;)V
.end method

.method public c0()V
    .locals 0

    .line 1
    return-void
.end method

.method public d0(J)V
    .locals 3

    .line 1
    iput-wide p1, p0, Lf8/s;->J1:J

    .line 2
    .line 3
    :goto_0
    iget-object v0, p0, Lf8/s;->D:Ljava/util/ArrayDeque;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lf8/r;

    .line 16
    .line 17
    iget-wide v1, v1, Lf8/r;->a:J

    .line 18
    .line 19
    cmp-long v1, p1, v1

    .line 20
    .line 21
    if-ltz v1, :cond_0

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->poll()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    check-cast v0, Lf8/r;

    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, v0}, Lf8/s;->p0(Lf8/r;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0}, Lf8/s;->e0()V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    return-void
.end method

.method public abstract e0()V
.end method

.method public f0(Lz7/e;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final g0()V
    .locals 3

    .line 1
    iget v0, p0, Lf8/s;->w1:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eq v0, v1, :cond_2

    .line 5
    .line 6
    const/4 v2, 0x2

    .line 7
    if-eq v0, v2, :cond_1

    .line 8
    .line 9
    const/4 v2, 0x3

    .line 10
    if-eq v0, v2, :cond_0

    .line 11
    .line 12
    iput-boolean v1, p0, Lf8/s;->D1:Z

    .line 13
    .line 14
    invoke-virtual {p0}, Lf8/s;->k0()V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    invoke-virtual {p0}, Lf8/s;->j0()V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Lf8/s;->U()V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_1
    invoke-virtual {p0}, Lf8/s;->J()V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Lf8/s;->x0()V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_2
    invoke-virtual {p0}, Lf8/s;->J()V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public abstract h0(JJLf8/m;Ljava/nio/ByteBuffer;IIIJZZLt7/o;)Z
.end method

.method public final i(JJ)J
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2, p3, p4}, Lf8/s;->P(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public final i0(I)Z
    .locals 5

    .line 1
    iget-object v0, p0, La8/f;->f:Lb81/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Lb81/d;->i()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lf8/s;->y:Lz7/e;

    .line 7
    .line 8
    invoke-virtual {v1}, Lz7/e;->m()V

    .line 9
    .line 10
    .line 11
    const/4 v2, 0x4

    .line 12
    or-int/2addr p1, v2

    .line 13
    invoke-virtual {p0, v0, v1, p1}, La8/f;->x(Lb81/d;Lz7/e;I)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    const/4 v3, -0x5

    .line 18
    const/4 v4, 0x1

    .line 19
    if-ne p1, v3, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0, v0}, Lf8/s;->a0(Lb81/d;)La8/h;

    .line 22
    .line 23
    .line 24
    return v4

    .line 25
    :cond_0
    const/4 v0, -0x4

    .line 26
    if-ne p1, v0, :cond_1

    .line 27
    .line 28
    invoke-virtual {v1, v2}, Lkq/d;->c(I)Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_1

    .line 33
    .line 34
    iput-boolean v4, p0, Lf8/s;->C1:Z

    .line 35
    .line 36
    invoke-virtual {p0}, Lf8/s;->g0()V

    .line 37
    .line 38
    .line 39
    :cond_1
    const/4 p0, 0x0

    .line 40
    return p0
.end method

.method public final j0()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    iget-object v1, p0, Lf8/s;->O:Lf8/m;

    .line 3
    .line 4
    if-eqz v1, :cond_0

    .line 5
    .line 6
    invoke-interface {v1}, Lf8/m;->b()V

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lf8/s;->H1:La8/g;

    .line 10
    .line 11
    iget v2, v1, La8/g;->b:I

    .line 12
    .line 13
    add-int/lit8 v2, v2, 0x1

    .line 14
    .line 15
    iput v2, v1, La8/g;->b:I

    .line 16
    .line 17
    iget-object v1, p0, Lf8/s;->V:Lf8/p;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    iget-object v1, v1, Lf8/p;->a:Ljava/lang/String;

    .line 23
    .line 24
    invoke-virtual {p0, v1}, Lf8/s;->Z(Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :catchall_0
    move-exception v1

    .line 29
    goto :goto_3

    .line 30
    :cond_0
    :goto_0
    iput-object v0, p0, Lf8/s;->O:Lf8/m;

    .line 31
    .line 32
    :try_start_1
    iget-object v1, p0, Lf8/s;->K:Landroid/media/MediaCrypto;

    .line 33
    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    invoke-virtual {v1}, Landroid/media/MediaCrypto;->release()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :catchall_1
    move-exception v1

    .line 41
    goto :goto_2

    .line 42
    :cond_1
    :goto_1
    iput-object v0, p0, Lf8/s;->K:Landroid/media/MediaCrypto;

    .line 43
    .line 44
    invoke-virtual {p0, v0}, Lf8/s;->o0(Laq/a;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0}, Lf8/s;->n0()V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :goto_2
    iput-object v0, p0, Lf8/s;->K:Landroid/media/MediaCrypto;

    .line 52
    .line 53
    invoke-virtual {p0, v0}, Lf8/s;->o0(Laq/a;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Lf8/s;->n0()V

    .line 57
    .line 58
    .line 59
    throw v1

    .line 60
    :goto_3
    iput-object v0, p0, Lf8/s;->O:Lf8/m;

    .line 61
    .line 62
    :try_start_2
    iget-object v2, p0, Lf8/s;->K:Landroid/media/MediaCrypto;

    .line 63
    .line 64
    if-eqz v2, :cond_2

    .line 65
    .line 66
    invoke-virtual {v2}, Landroid/media/MediaCrypto;->release()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 67
    .line 68
    .line 69
    goto :goto_4

    .line 70
    :catchall_2
    move-exception v1

    .line 71
    goto :goto_5

    .line 72
    :cond_2
    :goto_4
    iput-object v0, p0, Lf8/s;->K:Landroid/media/MediaCrypto;

    .line 73
    .line 74
    invoke-virtual {p0, v0}, Lf8/s;->o0(Laq/a;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p0}, Lf8/s;->n0()V

    .line 78
    .line 79
    .line 80
    throw v1

    .line 81
    :goto_5
    iput-object v0, p0, Lf8/s;->K:Landroid/media/MediaCrypto;

    .line 82
    .line 83
    invoke-virtual {p0, v0}, Lf8/s;->o0(Laq/a;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p0}, Lf8/s;->n0()V

    .line 87
    .line 88
    .line 89
    throw v1
.end method

.method public abstract k0()V
.end method

.method public final l0()V
    .locals 2

    .line 1
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    iput-wide v0, p0, Lf8/s;->A1:J

    .line 7
    .line 8
    iput-wide v0, p0, Lf8/s;->B1:J

    .line 9
    .line 10
    iput-wide v0, p0, Lf8/s;->J1:J

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    iput-boolean v0, p0, Lf8/s;->s1:Z

    .line 14
    .line 15
    iget-object v1, p0, Lf8/s;->B:Lf8/i;

    .line 16
    .line 17
    invoke-virtual {v1}, Lf8/i;->m()V

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lf8/s;->A:Lz7/e;

    .line 21
    .line 22
    invoke-virtual {v1}, Lz7/e;->m()V

    .line 23
    .line 24
    .line 25
    iput-boolean v0, p0, Lf8/s;->r1:Z

    .line 26
    .line 27
    iget-object p0, p0, Lf8/s;->E:Lc8/b0;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    sget-object v1, Lu7/f;->a:Ljava/nio/ByteBuffer;

    .line 33
    .line 34
    iput-object v1, p0, Lc8/b0;->a:Ljava/nio/ByteBuffer;

    .line 35
    .line 36
    iput v0, p0, Lc8/b0;->c:I

    .line 37
    .line 38
    const/4 v0, 0x2

    .line 39
    iput v0, p0, Lc8/b0;->b:I

    .line 40
    .line 41
    return-void
.end method

.method public m0()V
    .locals 4

    .line 1
    const/4 v0, -0x1

    .line 2
    iput v0, p0, Lf8/s;->c0:I

    .line 3
    .line 4
    iget-object v1, p0, Lf8/s;->z:Lz7/e;

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    iput-object v2, v1, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 8
    .line 9
    iput v0, p0, Lf8/s;->d0:I

    .line 10
    .line 11
    iput-object v2, p0, Lf8/s;->e0:Ljava/nio/ByteBuffer;

    .line 12
    .line 13
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    iput-wide v0, p0, Lf8/s;->A1:J

    .line 19
    .line 20
    iput-wide v0, p0, Lf8/s;->B1:J

    .line 21
    .line 22
    iput-wide v0, p0, Lf8/s;->J1:J

    .line 23
    .line 24
    iput-wide v0, p0, Lf8/s;->b0:J

    .line 25
    .line 26
    const/4 v2, 0x0

    .line 27
    iput-boolean v2, p0, Lf8/s;->y1:Z

    .line 28
    .line 29
    iput-wide v0, p0, Lf8/s;->a0:J

    .line 30
    .line 31
    iput-boolean v2, p0, Lf8/s;->x1:Z

    .line 32
    .line 33
    iput-boolean v2, p0, Lf8/s;->X:Z

    .line 34
    .line 35
    iput-boolean v2, p0, Lf8/s;->Y:Z

    .line 36
    .line 37
    iput-boolean v2, p0, Lf8/s;->f0:Z

    .line 38
    .line 39
    iput-boolean v2, p0, Lf8/s;->g0:Z

    .line 40
    .line 41
    iput v2, p0, Lf8/s;->v1:I

    .line 42
    .line 43
    iput v2, p0, Lf8/s;->w1:I

    .line 44
    .line 45
    iget-boolean v3, p0, Lf8/s;->t1:Z

    .line 46
    .line 47
    iput v3, p0, Lf8/s;->u1:I

    .line 48
    .line 49
    iput-boolean v2, p0, Lf8/s;->M1:Z

    .line 50
    .line 51
    iput-wide v0, p0, Lf8/s;->N1:J

    .line 52
    .line 53
    iput-wide v0, p0, Lf8/s;->O1:J

    .line 54
    .line 55
    return-void
.end method

.method public final n0()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lf8/s;->m0()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lf8/s;->G1:La8/o;

    .line 6
    .line 7
    iput-object v0, p0, Lf8/s;->T:Ljava/util/ArrayDeque;

    .line 8
    .line 9
    iput-object v0, p0, Lf8/s;->V:Lf8/p;

    .line 10
    .line 11
    iput-object v0, p0, Lf8/s;->P:Lt7/o;

    .line 12
    .line 13
    iput-object v0, p0, Lf8/s;->Q:Landroid/media/MediaFormat;

    .line 14
    .line 15
    const/4 v0, 0x0

    .line 16
    iput-boolean v0, p0, Lf8/s;->R:Z

    .line 17
    .line 18
    iput-boolean v0, p0, Lf8/s;->z1:Z

    .line 19
    .line 20
    const/high16 v1, -0x40800000    # -1.0f

    .line 21
    .line 22
    iput v1, p0, Lf8/s;->S:F

    .line 23
    .line 24
    iput-boolean v0, p0, Lf8/s;->W:Z

    .line 25
    .line 26
    iput-boolean v0, p0, Lf8/s;->Z:Z

    .line 27
    .line 28
    iput-boolean v0, p0, Lf8/s;->t1:Z

    .line 29
    .line 30
    iput v0, p0, Lf8/s;->u1:I

    .line 31
    .line 32
    return-void
.end method

.method public o()Z
    .locals 7

    .line 1
    iget-object v0, p0, Lf8/s;->F:Lt7/o;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_3

    .line 5
    .line 6
    invoke-virtual {p0}, La8/f;->l()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-boolean v0, p0, La8/f;->q:Z

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    iget-object v0, p0, La8/f;->l:Lh8/y0;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    invoke-interface {v0}, Lh8/y0;->a()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    :goto_0
    const/4 v2, 0x1

    .line 25
    if-nez v0, :cond_2

    .line 26
    .line 27
    iget v0, p0, Lf8/s;->d0:I

    .line 28
    .line 29
    if-ltz v0, :cond_1

    .line 30
    .line 31
    move v0, v2

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v0, v1

    .line 34
    :goto_1
    if-nez v0, :cond_2

    .line 35
    .line 36
    iget-wide v3, p0, Lf8/s;->b0:J

    .line 37
    .line 38
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    cmp-long v0, v3, v5

    .line 44
    .line 45
    if-eqz v0, :cond_3

    .line 46
    .line 47
    iget-object v0, p0, La8/f;->j:Lw7/r;

    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 53
    .line 54
    .line 55
    move-result-wide v3

    .line 56
    iget-wide v5, p0, Lf8/s;->b0:J

    .line 57
    .line 58
    cmp-long p0, v3, v5

    .line 59
    .line 60
    if-gez p0, :cond_3

    .line 61
    .line 62
    :cond_2
    return v2

    .line 63
    :cond_3
    return v1
.end method

.method public final o0(Laq/a;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lf8/s;->H:Laq/a;

    .line 2
    .line 3
    if-ne v0, p1, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    const/4 v1, 0x0

    .line 7
    if-eqz p1, :cond_1

    .line 8
    .line 9
    invoke-virtual {p1, v1}, Laq/a;->i(Ld8/f;)V

    .line 10
    .line 11
    .line 12
    :cond_1
    if-eqz v0, :cond_2

    .line 13
    .line 14
    invoke-virtual {v0, v1}, Laq/a;->E(Ld8/f;)V

    .line 15
    .line 16
    .line 17
    :cond_2
    :goto_0
    iput-object p1, p0, Lf8/s;->H:Laq/a;

    .line 18
    .line 19
    return-void
.end method

.method public p()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lf8/s;->F:Lt7/o;

    .line 3
    .line 4
    sget-object v0, Lf8/r;->e:Lf8/r;

    .line 5
    .line 6
    invoke-virtual {p0, v0}, Lf8/s;->p0(Lf8/r;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lf8/s;->D:Ljava/util/ArrayDeque;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->clear()V

    .line 12
    .line 13
    .line 14
    iget-boolean v0, p0, Lf8/s;->q1:Z

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    iput-boolean v0, p0, Lf8/s;->q1:Z

    .line 20
    .line 21
    invoke-virtual {p0}, Lf8/s;->l0()V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    invoke-virtual {p0}, Lf8/s;->K()Z

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public final p0(Lf8/r;)V
    .locals 4

    .line 1
    iput-object p1, p0, Lf8/s;->I1:Lf8/r;

    .line 2
    .line 3
    iget-wide v0, p1, Lf8/r;->c:J

    .line 4
    .line 5
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    cmp-long p1, v0, v2

    .line 11
    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    iput-boolean p1, p0, Lf8/s;->K1:Z

    .line 16
    .line 17
    invoke-virtual {p0}, Lf8/s;->c0()V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public q0(Lz7/e;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public r(JZ)V
    .locals 0

    .line 1
    const/4 p1, 0x0

    .line 2
    iput-boolean p1, p0, Lf8/s;->C1:Z

    .line 3
    .line 4
    iput-boolean p1, p0, Lf8/s;->D1:Z

    .line 5
    .line 6
    iput-boolean p1, p0, Lf8/s;->F1:Z

    .line 7
    .line 8
    iget-boolean p1, p0, Lf8/s;->q1:Z

    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Lf8/s;->l0()V

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {p0}, Lf8/s;->K()Z

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    if-eqz p1, :cond_1

    .line 21
    .line 22
    invoke-virtual {p0}, Lf8/s;->U()V

    .line 23
    .line 24
    .line 25
    :cond_1
    :goto_0
    iget-object p1, p0, Lf8/s;->I1:Lf8/r;

    .line 26
    .line 27
    iget-object p1, p1, Lf8/r;->d:Li4/c;

    .line 28
    .line 29
    invoke-virtual {p1}, Li4/c;->P()I

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-lez p1, :cond_2

    .line 34
    .line 35
    const/4 p1, 0x1

    .line 36
    iput-boolean p1, p0, Lf8/s;->E1:Z

    .line 37
    .line 38
    :cond_2
    iget-object p1, p0, Lf8/s;->I1:Lf8/r;

    .line 39
    .line 40
    iget-object p1, p1, Lf8/r;->d:Li4/c;

    .line 41
    .line 42
    invoke-virtual {p1}, Li4/c;->l()V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lf8/s;->D:Ljava/util/ArrayDeque;

    .line 46
    .line 47
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->clear()V

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method public r0()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public s0(Lf8/p;)Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public t0()Z
    .locals 3

    .line 1
    iget v0, p0, Lf8/s;->w1:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x1

    .line 5
    if-eq v0, v1, :cond_2

    .line 6
    .line 7
    iget-boolean v1, p0, Lf8/s;->W:Z

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-boolean v1, p0, Lf8/s;->z1:Z

    .line 12
    .line 13
    if-eqz v1, :cond_2

    .line 14
    .line 15
    :cond_0
    const/4 v1, 0x2

    .line 16
    if-ne v0, v1, :cond_1

    .line 17
    .line 18
    :try_start_0
    invoke-virtual {p0}, Lf8/s;->x0()V
    :try_end_0
    .catch La8/o; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catch_0
    move-exception p0

    .line 23
    const-string v0, "MediaCodecRenderer"

    .line 24
    .line 25
    const-string v1, "Failed to update the DRM session, releasing the codec instead."

    .line 26
    .line 27
    invoke-static {v0, v1, p0}, Lw7/a;->z(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    return v2

    .line 31
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 32
    return p0

    .line 33
    :cond_2
    return v2
.end method

.method public u0(Lt7/o;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public abstract v0(Lf8/k;Lt7/o;)I
.end method

.method public w([Lt7/o;JJLh8/b0;)V
    .locals 11

    .line 1
    iget-object p1, p0, Lf8/s;->I1:Lf8/r;

    .line 2
    .line 3
    iget-wide v0, p1, Lf8/r;->c:J

    .line 4
    .line 5
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    cmp-long p1, v0, v2

    .line 11
    .line 12
    if-nez p1, :cond_0

    .line 13
    .line 14
    new-instance v4, Lf8/r;

    .line 15
    .line 16
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    move-wide v7, p2

    .line 22
    move-wide v9, p4

    .line 23
    invoke-direct/range {v4 .. v10}, Lf8/r;-><init>(JJJ)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, v4}, Lf8/s;->p0(Lf8/r;)V

    .line 27
    .line 28
    .line 29
    iget-boolean p1, p0, Lf8/s;->L1:Z

    .line 30
    .line 31
    if-eqz p1, :cond_2

    .line 32
    .line 33
    invoke-virtual {p0}, Lf8/s;->e0()V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_0
    iget-object p1, p0, Lf8/s;->D:Ljava/util/ArrayDeque;

    .line 38
    .line 39
    invoke-virtual {p1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_3

    .line 44
    .line 45
    iget-wide v0, p0, Lf8/s;->A1:J

    .line 46
    .line 47
    cmp-long v4, v0, v2

    .line 48
    .line 49
    if-eqz v4, :cond_1

    .line 50
    .line 51
    iget-wide v4, p0, Lf8/s;->J1:J

    .line 52
    .line 53
    cmp-long v6, v4, v2

    .line 54
    .line 55
    if-eqz v6, :cond_3

    .line 56
    .line 57
    cmp-long v0, v4, v0

    .line 58
    .line 59
    if-ltz v0, :cond_3

    .line 60
    .line 61
    :cond_1
    new-instance v4, Lf8/r;

    .line 62
    .line 63
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 64
    .line 65
    .line 66
    .line 67
    .line 68
    move-wide v7, p2

    .line 69
    move-wide v9, p4

    .line 70
    invoke-direct/range {v4 .. v10}, Lf8/r;-><init>(JJJ)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0, v4}, Lf8/s;->p0(Lf8/r;)V

    .line 74
    .line 75
    .line 76
    iget-object p1, p0, Lf8/s;->I1:Lf8/r;

    .line 77
    .line 78
    iget-wide p1, p1, Lf8/r;->c:J

    .line 79
    .line 80
    cmp-long p1, p1, v2

    .line 81
    .line 82
    if-eqz p1, :cond_2

    .line 83
    .line 84
    invoke-virtual {p0}, Lf8/s;->e0()V

    .line 85
    .line 86
    .line 87
    :cond_2
    return-void

    .line 88
    :cond_3
    new-instance v0, Lf8/r;

    .line 89
    .line 90
    iget-wide v1, p0, Lf8/s;->A1:J

    .line 91
    .line 92
    move-wide v3, p2

    .line 93
    move-wide v5, p4

    .line 94
    invoke-direct/range {v0 .. v6}, Lf8/r;-><init>(JJJ)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p1, v0}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    return-void
.end method

.method public final w0(Lt7/o;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Lf8/s;->O:Lf8/m;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_5

    .line 5
    .line 6
    iget v0, p0, Lf8/s;->w1:I

    .line 7
    .line 8
    const/4 v2, 0x3

    .line 9
    if-eq v0, v2, :cond_5

    .line 10
    .line 11
    iget v0, p0, La8/f;->k:I

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    iget v0, p0, Lf8/s;->N:F

    .line 17
    .line 18
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    iget-object v3, p0, La8/f;->m:[Lt7/o;

    .line 22
    .line 23
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, v0, p1, v3}, Lf8/s;->N(FLt7/o;[Lt7/o;)F

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    iget v0, p0, Lf8/s;->S:F

    .line 31
    .line 32
    cmpl-float v3, v0, p1

    .line 33
    .line 34
    if-nez v3, :cond_1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/high16 v3, -0x40800000    # -1.0f

    .line 38
    .line 39
    cmpl-float v4, p1, v3

    .line 40
    .line 41
    if-nez v4, :cond_3

    .line 42
    .line 43
    iget-boolean p1, p0, Lf8/s;->x1:Z

    .line 44
    .line 45
    if-eqz p1, :cond_2

    .line 46
    .line 47
    iput v1, p0, Lf8/s;->v1:I

    .line 48
    .line 49
    iput v2, p0, Lf8/s;->w1:I

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    invoke-virtual {p0}, Lf8/s;->j0()V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0}, Lf8/s;->U()V

    .line 56
    .line 57
    .line 58
    :goto_0
    const/4 p0, 0x0

    .line 59
    return p0

    .line 60
    :cond_3
    cmpl-float v0, v0, v3

    .line 61
    .line 62
    if-nez v0, :cond_4

    .line 63
    .line 64
    iget v0, p0, Lf8/s;->x:F

    .line 65
    .line 66
    cmpl-float v0, p1, v0

    .line 67
    .line 68
    if-lez v0, :cond_5

    .line 69
    .line 70
    :cond_4
    new-instance v0, Landroid/os/Bundle;

    .line 71
    .line 72
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 73
    .line 74
    .line 75
    const-string v2, "operating-rate"

    .line 76
    .line 77
    invoke-virtual {v0, v2, p1}, Landroid/os/Bundle;->putFloat(Ljava/lang/String;F)V

    .line 78
    .line 79
    .line 80
    iget-object v2, p0, Lf8/s;->O:Lf8/m;

    .line 81
    .line 82
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    invoke-interface {v2, v0}, Lf8/m;->a(Landroid/os/Bundle;)V

    .line 86
    .line 87
    .line 88
    iput p1, p0, Lf8/s;->S:F

    .line 89
    .line 90
    :cond_5
    :goto_1
    return v1
.end method

.method public final x0()V
    .locals 4

    .line 1
    iget-object v0, p0, Lf8/s;->I:Laq/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Laq/a;->m()Lz7/a;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    instance-of v0, v0, Ld8/k;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    :try_start_0
    iget-object v0, p0, Lf8/s;->K:Landroid/media/MediaCrypto;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    invoke-virtual {v0, v2}, Landroid/media/MediaCrypto;->setMediaDrmSession([B)V
    :try_end_0
    .catch Landroid/media/MediaCryptoException; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catch_0
    move-exception v0

    .line 26
    iget-object v2, p0, Lf8/s;->F:Lt7/o;

    .line 27
    .line 28
    const/16 v3, 0x1776

    .line 29
    .line 30
    invoke-virtual {p0, v0, v2, v1, v3}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    throw p0

    .line 35
    :cond_0
    :goto_0
    iget-object v0, p0, Lf8/s;->I:Laq/a;

    .line 36
    .line 37
    invoke-virtual {p0, v0}, Lf8/s;->o0(Laq/a;)V

    .line 38
    .line 39
    .line 40
    iput v1, p0, Lf8/s;->v1:I

    .line 41
    .line 42
    iput v1, p0, Lf8/s;->w1:I

    .line 43
    .line 44
    return-void
.end method

.method public y(JJ)V
    .locals 11

    .line 1
    iget-boolean v0, p0, Lf8/s;->F1:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iput-boolean v1, p0, Lf8/s;->F1:Z

    .line 7
    .line 8
    invoke-virtual {p0}, Lf8/s;->g0()V

    .line 9
    .line 10
    .line 11
    :cond_0
    iget-object v0, p0, Lf8/s;->G1:La8/o;

    .line 12
    .line 13
    if-nez v0, :cond_11

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    :try_start_0
    iget-boolean v2, p0, Lf8/s;->D1:Z

    .line 17
    .line 18
    if-eqz v2, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0}, Lf8/s;->k0()V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :catch_0
    move-exception p1

    .line 25
    goto/16 :goto_8

    .line 26
    .line 27
    :catch_1
    move-exception p1

    .line 28
    goto/16 :goto_b

    .line 29
    .line 30
    :cond_1
    iget-object v2, p0, Lf8/s;->F:Lt7/o;

    .line 31
    .line 32
    if-nez v2, :cond_2

    .line 33
    .line 34
    const/4 v2, 0x2

    .line 35
    invoke-virtual {p0, v2}, Lf8/s;->i0(I)Z

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    if-nez v2, :cond_2

    .line 40
    .line 41
    return-void

    .line 42
    :cond_2
    invoke-virtual {p0}, Lf8/s;->U()V

    .line 43
    .line 44
    .line 45
    iget-boolean v2, p0, Lf8/s;->q1:Z

    .line 46
    .line 47
    if-eqz v2, :cond_4

    .line 48
    .line 49
    const-string v2, "bypassRender"

    .line 50
    .line 51
    invoke-static {v2}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    :goto_0
    invoke-virtual {p0, p1, p2, p3, p4}, Lf8/s;->D(JJ)Z

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-eqz v2, :cond_3

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_3
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 62
    .line 63
    .line 64
    goto/16 :goto_7

    .line 65
    .line 66
    :cond_4
    iget-object v2, p0, Lf8/s;->O:Lf8/m;

    .line 67
    .line 68
    if-eqz v2, :cond_b

    .line 69
    .line 70
    iget-object v2, p0, La8/f;->j:Lw7/r;

    .line 71
    .line 72
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 76
    .line 77
    .line 78
    move-result-wide v2

    .line 79
    const-string v4, "drainAndFeed"

    .line 80
    .line 81
    invoke-static {v4}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    :goto_1
    invoke-virtual {p0, p1, p2, p3, p4}, Lf8/s;->H(JJ)Z

    .line 85
    .line 86
    .line 87
    move-result v4

    .line 88
    const-wide v5, -0x7fffffffffffffffL    # -4.9E-324

    .line 89
    .line 90
    .line 91
    .line 92
    .line 93
    if-eqz v4, :cond_7

    .line 94
    .line 95
    iget-wide v7, p0, Lf8/s;->L:J

    .line 96
    .line 97
    cmp-long v4, v7, v5

    .line 98
    .line 99
    if-eqz v4, :cond_6

    .line 100
    .line 101
    iget-object v4, p0, La8/f;->j:Lw7/r;

    .line 102
    .line 103
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 107
    .line 108
    .line 109
    move-result-wide v9

    .line 110
    sub-long/2addr v9, v2

    .line 111
    cmp-long v4, v9, v7

    .line 112
    .line 113
    if-gez v4, :cond_5

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_5
    move v4, v1

    .line 117
    goto :goto_3

    .line 118
    :cond_6
    :goto_2
    move v4, v0

    .line 119
    :goto_3
    if-eqz v4, :cond_7

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_7
    :goto_4
    invoke-virtual {p0}, Lf8/s;->I()Z

    .line 123
    .line 124
    .line 125
    move-result p1

    .line 126
    if-eqz p1, :cond_a

    .line 127
    .line 128
    iget-wide p1, p0, Lf8/s;->L:J

    .line 129
    .line 130
    cmp-long p3, p1, v5

    .line 131
    .line 132
    if-eqz p3, :cond_9

    .line 133
    .line 134
    iget-object p3, p0, La8/f;->j:Lw7/r;

    .line 135
    .line 136
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 137
    .line 138
    .line 139
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 140
    .line 141
    .line 142
    move-result-wide p3

    .line 143
    sub-long/2addr p3, v2

    .line 144
    cmp-long p1, p3, p1

    .line 145
    .line 146
    if-gez p1, :cond_8

    .line 147
    .line 148
    goto :goto_5

    .line 149
    :cond_8
    move p1, v1

    .line 150
    goto :goto_6

    .line 151
    :cond_9
    :goto_5
    move p1, v0

    .line 152
    :goto_6
    if-eqz p1, :cond_a

    .line 153
    .line 154
    goto :goto_4

    .line 155
    :cond_a
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 156
    .line 157
    .line 158
    goto :goto_7

    .line 159
    :cond_b
    iget-object p3, p0, Lf8/s;->H1:La8/g;

    .line 160
    .line 161
    iget p4, p3, La8/g;->d:I

    .line 162
    .line 163
    iget-object v2, p0, La8/f;->l:Lh8/y0;

    .line 164
    .line 165
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 166
    .line 167
    .line 168
    iget-wide v3, p0, La8/f;->n:J

    .line 169
    .line 170
    sub-long/2addr p1, v3

    .line 171
    invoke-interface {v2, p1, p2}, Lh8/y0;->l(J)I

    .line 172
    .line 173
    .line 174
    move-result p1

    .line 175
    add-int/2addr p4, p1

    .line 176
    iput p4, p3, La8/g;->d:I

    .line 177
    .line 178
    invoke-virtual {p0, v0}, Lf8/s;->i0(I)Z

    .line 179
    .line 180
    .line 181
    :goto_7
    iget-object p1, p0, Lf8/s;->H1:La8/g;

    .line 182
    .line 183
    monitor-enter p1

    .line 184
    monitor-exit p1
    :try_end_0
    .catch Landroid/media/MediaCodec$CryptoException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 185
    return-void

    .line 186
    :goto_8
    instance-of p2, p1, Landroid/media/MediaCodec$CodecException;

    .line 187
    .line 188
    if-eqz p2, :cond_c

    .line 189
    .line 190
    goto :goto_9

    .line 191
    :cond_c
    invoke-virtual {p1}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 192
    .line 193
    .line 194
    move-result-object p3

    .line 195
    array-length p4, p3

    .line 196
    if-lez p4, :cond_10

    .line 197
    .line 198
    aget-object p3, p3, v1

    .line 199
    .line 200
    invoke-virtual {p3}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object p3

    .line 204
    const-string p4, "android.media.MediaCodec"

    .line 205
    .line 206
    invoke-virtual {p3, p4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result p3

    .line 210
    if-eqz p3, :cond_10

    .line 211
    .line 212
    :goto_9
    invoke-virtual {p0, p1}, Lf8/s;->X(Ljava/lang/Exception;)V

    .line 213
    .line 214
    .line 215
    if-eqz p2, :cond_d

    .line 216
    .line 217
    move-object p2, p1

    .line 218
    check-cast p2, Landroid/media/MediaCodec$CodecException;

    .line 219
    .line 220
    invoke-virtual {p2}, Landroid/media/MediaCodec$CodecException;->isRecoverable()Z

    .line 221
    .line 222
    .line 223
    move-result p2

    .line 224
    if-eqz p2, :cond_d

    .line 225
    .line 226
    move v1, v0

    .line 227
    :cond_d
    if-eqz v1, :cond_e

    .line 228
    .line 229
    invoke-virtual {p0}, Lf8/s;->j0()V

    .line 230
    .line 231
    .line 232
    :cond_e
    iget-object p2, p0, Lf8/s;->V:Lf8/p;

    .line 233
    .line 234
    invoke-virtual {p0, p1, p2}, Lf8/s;->F(Ljava/lang/IllegalStateException;Lf8/p;)Lf8/o;

    .line 235
    .line 236
    .line 237
    move-result-object p1

    .line 238
    iget p2, p1, Lf8/o;->d:I

    .line 239
    .line 240
    const/16 p3, 0x44d

    .line 241
    .line 242
    if-ne p2, p3, :cond_f

    .line 243
    .line 244
    const/16 p2, 0xfa6

    .line 245
    .line 246
    goto :goto_a

    .line 247
    :cond_f
    const/16 p2, 0xfa3

    .line 248
    .line 249
    :goto_a
    iget-object p3, p0, Lf8/s;->F:Lt7/o;

    .line 250
    .line 251
    invoke-virtual {p0, p1, p3, v1, p2}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    throw p0

    .line 256
    :cond_10
    throw p1

    .line 257
    :goto_b
    iget-object p2, p0, Lf8/s;->F:Lt7/o;

    .line 258
    .line 259
    invoke-virtual {p1}, Landroid/media/MediaCodec$CryptoException;->getErrorCode()I

    .line 260
    .line 261
    .line 262
    move-result p3

    .line 263
    invoke-static {p3}, Lw7/w;->p(I)I

    .line 264
    .line 265
    .line 266
    move-result p3

    .line 267
    invoke-virtual {p0, p1, p2, v1, p3}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 268
    .line 269
    .line 270
    move-result-object p0

    .line 271
    throw p0

    .line 272
    :cond_11
    const/4 p1, 0x0

    .line 273
    iput-object p1, p0, Lf8/s;->G1:La8/o;

    .line 274
    .line 275
    throw v0
.end method

.method public final y0(J)V
    .locals 1

    .line 1
    iget-object v0, p0, Lf8/s;->I1:Lf8/r;

    .line 2
    .line 3
    iget-object v0, v0, Lf8/r;->d:Li4/c;

    .line 4
    .line 5
    invoke-virtual {v0, p1, p2}, Li4/c;->K(J)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    check-cast p1, Lt7/o;

    .line 10
    .line 11
    if-nez p1, :cond_0

    .line 12
    .line 13
    iget-boolean p2, p0, Lf8/s;->K1:Z

    .line 14
    .line 15
    if-eqz p2, :cond_0

    .line 16
    .line 17
    iget-object p2, p0, Lf8/s;->Q:Landroid/media/MediaFormat;

    .line 18
    .line 19
    if-eqz p2, :cond_0

    .line 20
    .line 21
    iget-object p1, p0, Lf8/s;->I1:Lf8/r;

    .line 22
    .line 23
    iget-object p1, p1, Lf8/r;->d:Li4/c;

    .line 24
    .line 25
    invoke-virtual {p1}, Li4/c;->J()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    check-cast p1, Lt7/o;

    .line 30
    .line 31
    :cond_0
    if-eqz p1, :cond_1

    .line 32
    .line 33
    iput-object p1, p0, Lf8/s;->G:Lt7/o;

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    iget-boolean p1, p0, Lf8/s;->R:Z

    .line 37
    .line 38
    if-eqz p1, :cond_2

    .line 39
    .line 40
    iget-object p1, p0, Lf8/s;->G:Lt7/o;

    .line 41
    .line 42
    if-eqz p1, :cond_2

    .line 43
    .line 44
    :goto_0
    iget-object p1, p0, Lf8/s;->G:Lt7/o;

    .line 45
    .line 46
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    iget-object p2, p0, Lf8/s;->Q:Landroid/media/MediaFormat;

    .line 50
    .line 51
    invoke-virtual {p0, p1, p2}, Lf8/s;->b0(Lt7/o;Landroid/media/MediaFormat;)V

    .line 52
    .line 53
    .line 54
    const/4 p1, 0x0

    .line 55
    iput-boolean p1, p0, Lf8/s;->R:Z

    .line 56
    .line 57
    iput-boolean p1, p0, Lf8/s;->K1:Z

    .line 58
    .line 59
    :cond_2
    return-void
.end method
