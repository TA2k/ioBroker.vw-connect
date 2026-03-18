.class public final Li9/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# static fields
.field public static final M:[B

.field public static final N:Lt7/o;


# instance fields
.field public A:Li9/i;

.field public B:I

.field public C:I

.field public D:I

.field public E:Z

.field public F:Z

.field public G:Lo8/q;

.field public H:[Lo8/i0;

.field public I:[Lo8/i0;

.field public J:Z

.field public K:Z

.field public L:J

.field public final a:Ll9/h;

.field public final b:I

.field public final c:Ljava/util/List;

.field public final d:Landroid/util/SparseArray;

.field public final e:Lw7/p;

.field public final f:Lw7/p;

.field public final g:Lw7/p;

.field public final h:[B

.field public final i:Lw7/p;

.field public final j:Ly/a;

.field public final k:Lw7/p;

.field public final l:Ljava/util/ArrayDeque;

.field public final m:Ljava/util/ArrayDeque;

.field public final n:Lca/j;

.field public final o:Lfb/k;

.field public p:Lhr/x0;

.field public q:I

.field public r:I

.field public s:J

.field public t:I

.field public u:Lw7/p;

.field public v:J

.field public w:I

.field public x:J

.field public y:J

.field public z:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v0, Li9/j;->M:[B

    .line 9
    .line 10
    new-instance v0, Lt7/n;

    .line 11
    .line 12
    invoke-direct {v0}, Lt7/n;-><init>()V

    .line 13
    .line 14
    .line 15
    const-string v1, "application/x-emsg"

    .line 16
    .line 17
    invoke-static {v1}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    iput-object v1, v0, Lt7/n;->m:Ljava/lang/String;

    .line 22
    .line 23
    new-instance v1, Lt7/o;

    .line 24
    .line 25
    invoke-direct {v1, v0}, Lt7/o;-><init>(Lt7/n;)V

    .line 26
    .line 27
    .line 28
    sput-object v1, Li9/j;->N:Lt7/o;

    .line 29
    .line 30
    return-void

    .line 31
    :array_0
    .array-data 1
        -0x5et
        0x39t
        0x4ft
        0x52t
        0x5at
        -0x65t
        0x4ft
        0x14t
        -0x5et
        0x44t
        0x6ct
        0x42t
        0x7ct
        0x64t
        -0x73t
        -0xct
    .end array-data
.end method

.method public constructor <init>(Ll9/h;I)V
    .locals 2

    .line 1
    sget-object v0, Lhr/h0;->e:Lhr/f0;

    .line 2
    .line 3
    sget-object v0, Lhr/x0;->h:Lhr/x0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    iput-object p1, p0, Li9/j;->a:Ll9/h;

    .line 9
    .line 10
    iput p2, p0, Li9/j;->b:I

    .line 11
    .line 12
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    iput-object p1, p0, Li9/j;->c:Ljava/util/List;

    .line 17
    .line 18
    new-instance p1, Ly/a;

    .line 19
    .line 20
    invoke-direct {p1}, Ly/a;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, Li9/j;->j:Ly/a;

    .line 24
    .line 25
    new-instance p1, Lw7/p;

    .line 26
    .line 27
    const/16 p2, 0x10

    .line 28
    .line 29
    invoke-direct {p1, p2}, Lw7/p;-><init>(I)V

    .line 30
    .line 31
    .line 32
    iput-object p1, p0, Li9/j;->k:Lw7/p;

    .line 33
    .line 34
    new-instance p1, Lw7/p;

    .line 35
    .line 36
    sget-object v1, Lx7/n;->a:[B

    .line 37
    .line 38
    invoke-direct {p1, v1}, Lw7/p;-><init>([B)V

    .line 39
    .line 40
    .line 41
    iput-object p1, p0, Li9/j;->e:Lw7/p;

    .line 42
    .line 43
    new-instance p1, Lw7/p;

    .line 44
    .line 45
    const/4 v1, 0x6

    .line 46
    invoke-direct {p1, v1}, Lw7/p;-><init>(I)V

    .line 47
    .line 48
    .line 49
    iput-object p1, p0, Li9/j;->f:Lw7/p;

    .line 50
    .line 51
    new-instance p1, Lw7/p;

    .line 52
    .line 53
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 54
    .line 55
    .line 56
    iput-object p1, p0, Li9/j;->g:Lw7/p;

    .line 57
    .line 58
    new-array p1, p2, [B

    .line 59
    .line 60
    iput-object p1, p0, Li9/j;->h:[B

    .line 61
    .line 62
    new-instance p2, Lw7/p;

    .line 63
    .line 64
    invoke-direct {p2, p1}, Lw7/p;-><init>([B)V

    .line 65
    .line 66
    .line 67
    iput-object p2, p0, Li9/j;->i:Lw7/p;

    .line 68
    .line 69
    new-instance p1, Ljava/util/ArrayDeque;

    .line 70
    .line 71
    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    .line 72
    .line 73
    .line 74
    iput-object p1, p0, Li9/j;->l:Ljava/util/ArrayDeque;

    .line 75
    .line 76
    new-instance p1, Ljava/util/ArrayDeque;

    .line 77
    .line 78
    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    .line 79
    .line 80
    .line 81
    iput-object p1, p0, Li9/j;->m:Ljava/util/ArrayDeque;

    .line 82
    .line 83
    new-instance p1, Landroid/util/SparseArray;

    .line 84
    .line 85
    invoke-direct {p1}, Landroid/util/SparseArray;-><init>()V

    .line 86
    .line 87
    .line 88
    iput-object p1, p0, Li9/j;->d:Landroid/util/SparseArray;

    .line 89
    .line 90
    iput-object v0, p0, Li9/j;->p:Lhr/x0;

    .line 91
    .line 92
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 93
    .line 94
    .line 95
    .line 96
    .line 97
    iput-wide p1, p0, Li9/j;->y:J

    .line 98
    .line 99
    iput-wide p1, p0, Li9/j;->x:J

    .line 100
    .line 101
    iput-wide p1, p0, Li9/j;->z:J

    .line 102
    .line 103
    sget-object p1, Lo8/q;->l1:Lrb0/a;

    .line 104
    .line 105
    iput-object p1, p0, Li9/j;->G:Lo8/q;

    .line 106
    .line 107
    const/4 p1, 0x0

    .line 108
    new-array p2, p1, [Lo8/i0;

    .line 109
    .line 110
    iput-object p2, p0, Li9/j;->H:[Lo8/i0;

    .line 111
    .line 112
    new-array p1, p1, [Lo8/i0;

    .line 113
    .line 114
    iput-object p1, p0, Li9/j;->I:[Lo8/i0;

    .line 115
    .line 116
    new-instance p1, Lca/j;

    .line 117
    .line 118
    new-instance p2, Li9/g;

    .line 119
    .line 120
    invoke-direct {p2, p0}, Li9/g;-><init>(Li9/j;)V

    .line 121
    .line 122
    .line 123
    invoke-direct {p1, p2}, Lca/j;-><init>(Lx7/r;)V

    .line 124
    .line 125
    .line 126
    iput-object p1, p0, Li9/j;->n:Lca/j;

    .line 127
    .line 128
    new-instance p1, Lfb/k;

    .line 129
    .line 130
    const/4 p2, 0x3

    .line 131
    invoke-direct {p1, p2}, Lfb/k;-><init>(I)V

    .line 132
    .line 133
    .line 134
    iput-object p1, p0, Li9/j;->o:Lfb/k;

    .line 135
    .line 136
    const-wide/16 p1, -0x1

    .line 137
    .line 138
    iput-wide p1, p0, Li9/j;->L:J

    .line 139
    .line 140
    return-void
.end method

.method public static f(Ljava/util/List;)Lt7/k;
    .locals 19

    .line 1
    invoke-interface/range {p0 .. p0}, Ljava/util/List;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v3, 0x0

    .line 6
    const/4 v4, 0x0

    .line 7
    :goto_0
    if-ge v3, v0, :cond_b

    .line 8
    .line 9
    move-object/from16 v5, p0

    .line 10
    .line 11
    invoke-interface {v5, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v6

    .line 15
    check-cast v6, Lx7/d;

    .line 16
    .line 17
    iget v7, v6, Lkq/d;->e:I

    .line 18
    .line 19
    const v8, 0x70737368    # 3.013775E29f

    .line 20
    .line 21
    .line 22
    if-ne v7, v8, :cond_a

    .line 23
    .line 24
    if-nez v4, :cond_0

    .line 25
    .line 26
    new-instance v4, Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 29
    .line 30
    .line 31
    :cond_0
    iget-object v6, v6, Lx7/d;->f:Lw7/p;

    .line 32
    .line 33
    iget-object v6, v6, Lw7/p;->a:[B

    .line 34
    .line 35
    new-instance v7, Lw7/p;

    .line 36
    .line 37
    invoke-direct {v7, v6}, Lw7/p;-><init>([B)V

    .line 38
    .line 39
    .line 40
    iget v8, v7, Lw7/p;->c:I

    .line 41
    .line 42
    const/16 v9, 0x20

    .line 43
    .line 44
    if-ge v8, v9, :cond_1

    .line 45
    .line 46
    :goto_1
    move/from16 v16, v3

    .line 47
    .line 48
    :goto_2
    const/4 v10, 0x0

    .line 49
    goto/16 :goto_4

    .line 50
    .line 51
    :cond_1
    const/4 v8, 0x0

    .line 52
    invoke-virtual {v7, v8}, Lw7/p;->I(I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v7}, Lw7/p;->a()I

    .line 56
    .line 57
    .line 58
    move-result v9

    .line 59
    invoke-virtual {v7}, Lw7/p;->j()I

    .line 60
    .line 61
    .line 62
    move-result v11

    .line 63
    const-string v12, "PsshAtomUtil"

    .line 64
    .line 65
    if-eq v11, v9, :cond_2

    .line 66
    .line 67
    new-instance v7, Ljava/lang/StringBuilder;

    .line 68
    .line 69
    const-string v8, "Advertised atom size ("

    .line 70
    .line 71
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v7, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v8, ") does not match buffer size: "

    .line 78
    .line 79
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v7, v9}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v7

    .line 89
    invoke-static {v12, v7}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_2
    invoke-virtual {v7}, Lw7/p;->j()I

    .line 94
    .line 95
    .line 96
    move-result v9

    .line 97
    const v11, 0x70737368    # 3.013775E29f

    .line 98
    .line 99
    .line 100
    if-eq v9, v11, :cond_3

    .line 101
    .line 102
    const-string v7, "Atom type is not pssh: "

    .line 103
    .line 104
    invoke-static {v7, v9, v12}, Lvj/b;->w(Ljava/lang/String;ILjava/lang/String;)V

    .line 105
    .line 106
    .line 107
    goto :goto_1

    .line 108
    :cond_3
    invoke-virtual {v7}, Lw7/p;->j()I

    .line 109
    .line 110
    .line 111
    move-result v9

    .line 112
    invoke-static {v9}, Li9/e;->e(I)I

    .line 113
    .line 114
    .line 115
    move-result v9

    .line 116
    const/4 v11, 0x1

    .line 117
    if-le v9, v11, :cond_4

    .line 118
    .line 119
    const-string v7, "Unsupported pssh version: "

    .line 120
    .line 121
    invoke-static {v7, v9, v12}, Lvj/b;->w(Ljava/lang/String;ILjava/lang/String;)V

    .line 122
    .line 123
    .line 124
    goto :goto_1

    .line 125
    :cond_4
    new-instance v13, Ljava/util/UUID;

    .line 126
    .line 127
    invoke-virtual {v7}, Lw7/p;->q()J

    .line 128
    .line 129
    .line 130
    move-result-wide v14

    .line 131
    move/from16 v16, v3

    .line 132
    .line 133
    invoke-virtual {v7}, Lw7/p;->q()J

    .line 134
    .line 135
    .line 136
    move-result-wide v2

    .line 137
    invoke-direct {v13, v14, v15, v2, v3}, Ljava/util/UUID;-><init>(JJ)V

    .line 138
    .line 139
    .line 140
    if-ne v9, v11, :cond_5

    .line 141
    .line 142
    invoke-virtual {v7}, Lw7/p;->A()I

    .line 143
    .line 144
    .line 145
    move-result v2

    .line 146
    new-array v3, v2, [Ljava/util/UUID;

    .line 147
    .line 148
    move v11, v8

    .line 149
    :goto_3
    if-ge v11, v2, :cond_6

    .line 150
    .line 151
    new-instance v14, Ljava/util/UUID;

    .line 152
    .line 153
    move/from16 v17, v11

    .line 154
    .line 155
    invoke-virtual {v7}, Lw7/p;->q()J

    .line 156
    .line 157
    .line 158
    move-result-wide v10

    .line 159
    move/from16 v18, v2

    .line 160
    .line 161
    invoke-virtual {v7}, Lw7/p;->q()J

    .line 162
    .line 163
    .line 164
    move-result-wide v1

    .line 165
    invoke-direct {v14, v10, v11, v1, v2}, Ljava/util/UUID;-><init>(JJ)V

    .line 166
    .line 167
    .line 168
    aput-object v14, v3, v17

    .line 169
    .line 170
    add-int/lit8 v11, v17, 0x1

    .line 171
    .line 172
    move/from16 v2, v18

    .line 173
    .line 174
    goto :goto_3

    .line 175
    :cond_5
    const/4 v3, 0x0

    .line 176
    :cond_6
    invoke-virtual {v7}, Lw7/p;->A()I

    .line 177
    .line 178
    .line 179
    move-result v1

    .line 180
    invoke-virtual {v7}, Lw7/p;->a()I

    .line 181
    .line 182
    .line 183
    move-result v2

    .line 184
    if-eq v1, v2, :cond_7

    .line 185
    .line 186
    new-instance v3, Ljava/lang/StringBuilder;

    .line 187
    .line 188
    const-string v7, "Atom data size ("

    .line 189
    .line 190
    invoke-direct {v3, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    const-string v1, ") does not match the bytes left: "

    .line 197
    .line 198
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 202
    .line 203
    .line 204
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v1

    .line 208
    invoke-static {v12, v1}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    goto/16 :goto_2

    .line 212
    .line 213
    :cond_7
    new-array v2, v1, [B

    .line 214
    .line 215
    invoke-virtual {v7, v2, v8, v1}, Lw7/p;->h([BII)V

    .line 216
    .line 217
    .line 218
    new-instance v10, Lhu/q;

    .line 219
    .line 220
    invoke-direct {v10, v13, v9, v2, v3}, Lhu/q;-><init>(Ljava/util/UUID;I[B[Ljava/util/UUID;)V

    .line 221
    .line 222
    .line 223
    :goto_4
    if-nez v10, :cond_8

    .line 224
    .line 225
    const/4 v1, 0x0

    .line 226
    goto :goto_5

    .line 227
    :cond_8
    iget-object v1, v10, Lhu/q;->e:Ljava/lang/Object;

    .line 228
    .line 229
    check-cast v1, Ljava/util/UUID;

    .line 230
    .line 231
    :goto_5
    if-nez v1, :cond_9

    .line 232
    .line 233
    const-string v1, "FragmentedMp4Extractor"

    .line 234
    .line 235
    const-string v2, "Skipped pssh atom (failed to extract uuid)"

    .line 236
    .line 237
    invoke-static {v1, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 238
    .line 239
    .line 240
    goto :goto_6

    .line 241
    :cond_9
    new-instance v2, Lt7/j;

    .line 242
    .line 243
    const-string v3, "video/mp4"

    .line 244
    .line 245
    const/4 v7, 0x0

    .line 246
    invoke-direct {v2, v1, v7, v3, v6}, Lt7/j;-><init>(Ljava/util/UUID;Ljava/lang/String;Ljava/lang/String;[B)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 250
    .line 251
    .line 252
    goto :goto_7

    .line 253
    :cond_a
    move/from16 v16, v3

    .line 254
    .line 255
    :goto_6
    const/4 v7, 0x0

    .line 256
    :goto_7
    add-int/lit8 v3, v16, 0x1

    .line 257
    .line 258
    goto/16 :goto_0

    .line 259
    .line 260
    :cond_b
    const/4 v7, 0x0

    .line 261
    if-nez v4, :cond_c

    .line 262
    .line 263
    return-object v7

    .line 264
    :cond_c
    new-instance v0, Lt7/k;

    .line 265
    .line 266
    const/4 v1, 0x0

    .line 267
    new-array v2, v1, [Lt7/j;

    .line 268
    .line 269
    invoke-interface {v4, v2}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v2

    .line 273
    check-cast v2, [Lt7/j;

    .line 274
    .line 275
    invoke-direct {v0, v7, v1, v2}, Lt7/k;-><init>(Ljava/lang/String;Z[Lt7/j;)V

    .line 276
    .line 277
    .line 278
    return-object v0
.end method

.method public static g(Lw7/p;ILi9/s;)V
    .locals 5

    .line 1
    add-int/lit8 p1, p1, 0x8

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lw7/p;->I(I)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    sget-object v0, Li9/e;->a:[B

    .line 11
    .line 12
    and-int/lit8 v0, p1, 0x1

    .line 13
    .line 14
    if-nez v0, :cond_3

    .line 15
    .line 16
    and-int/lit8 p1, p1, 0x2

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    const/4 v1, 0x1

    .line 20
    if-eqz p1, :cond_0

    .line 21
    .line 22
    move p1, v1

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move p1, v0

    .line 25
    :goto_0
    invoke-virtual {p0}, Lw7/p;->A()I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-nez v2, :cond_1

    .line 30
    .line 31
    iget-object p0, p2, Li9/s;->l:[Z

    .line 32
    .line 33
    iget p1, p2, Li9/s;->e:I

    .line 34
    .line 35
    invoke-static {p0, v0, p1, v0}, Ljava/util/Arrays;->fill([ZIIZ)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_1
    iget v3, p2, Li9/s;->e:I

    .line 40
    .line 41
    iget-object v4, p2, Li9/s;->n:Lw7/p;

    .line 42
    .line 43
    if-ne v2, v3, :cond_2

    .line 44
    .line 45
    iget-object v3, p2, Li9/s;->l:[Z

    .line 46
    .line 47
    invoke-static {v3, v0, v2, p1}, Ljava/util/Arrays;->fill([ZIIZ)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    invoke-virtual {v4, p1}, Lw7/p;->F(I)V

    .line 55
    .line 56
    .line 57
    iput-boolean v1, p2, Li9/s;->k:Z

    .line 58
    .line 59
    iput-boolean v1, p2, Li9/s;->o:Z

    .line 60
    .line 61
    iget-object p1, v4, Lw7/p;->a:[B

    .line 62
    .line 63
    iget v1, v4, Lw7/p;->c:I

    .line 64
    .line 65
    invoke-virtual {p0, p1, v0, v1}, Lw7/p;->h([BII)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v4, v0}, Lw7/p;->I(I)V

    .line 69
    .line 70
    .line 71
    iput-boolean v0, p2, Li9/s;->o:Z

    .line 72
    .line 73
    return-void

    .line 74
    :cond_2
    const-string p0, "Senc sample count "

    .line 75
    .line 76
    const-string p1, " is different from fragment sample count"

    .line 77
    .line 78
    invoke-static {p0, v2, p1}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    iget p1, p2, Li9/s;->e:I

    .line 83
    .line 84
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    const/4 p1, 0x0

    .line 92
    invoke-static {p1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    throw p0

    .line 97
    :cond_3
    const-string p0, "Overriding TrackEncryptionBox parameters is unsupported."

    .line 98
    .line 99
    invoke-static {p0}, Lt7/e0;->b(Ljava/lang/String;)Lt7/e0;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    throw p0
.end method

.method public static i(JLw7/p;)Landroid/util/Pair;
    .locals 22

    .line 1
    move-object/from16 v0, p2

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lw7/p;->I(I)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0}, Lw7/p;->j()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    invoke-static {v1}, Li9/e;->e(I)I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/4 v2, 0x4

    .line 17
    invoke-virtual {v0, v2}, Lw7/p;->J(I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Lw7/p;->y()J

    .line 21
    .line 22
    .line 23
    move-result-wide v7

    .line 24
    if-nez v1, :cond_0

    .line 25
    .line 26
    invoke-virtual {v0}, Lw7/p;->y()J

    .line 27
    .line 28
    .line 29
    move-result-wide v3

    .line 30
    invoke-virtual {v0}, Lw7/p;->y()J

    .line 31
    .line 32
    .line 33
    move-result-wide v5

    .line 34
    :goto_0
    add-long v5, v5, p0

    .line 35
    .line 36
    move-wide v10, v5

    .line 37
    goto :goto_1

    .line 38
    :cond_0
    invoke-virtual {v0}, Lw7/p;->B()J

    .line 39
    .line 40
    .line 41
    move-result-wide v3

    .line 42
    invoke-virtual {v0}, Lw7/p;->B()J

    .line 43
    .line 44
    .line 45
    move-result-wide v5

    .line 46
    goto :goto_0

    .line 47
    :goto_1
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 48
    .line 49
    sget-object v9, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 50
    .line 51
    const-wide/32 v5, 0xf4240

    .line 52
    .line 53
    .line 54
    invoke-static/range {v3 .. v9}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 55
    .line 56
    .line 57
    move-result-wide v12

    .line 58
    const/4 v1, 0x2

    .line 59
    invoke-virtual {v0, v1}, Lw7/p;->J(I)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0}, Lw7/p;->C()I

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    new-array v14, v1, [I

    .line 67
    .line 68
    new-array v15, v1, [J

    .line 69
    .line 70
    new-array v5, v1, [J

    .line 71
    .line 72
    new-array v6, v1, [J

    .line 73
    .line 74
    const/4 v9, 0x0

    .line 75
    move-wide/from16 v16, v10

    .line 76
    .line 77
    move-wide/from16 v18, v12

    .line 78
    .line 79
    move v10, v9

    .line 80
    :goto_2
    if-ge v10, v1, :cond_2

    .line 81
    .line 82
    invoke-virtual {v0}, Lw7/p;->j()I

    .line 83
    .line 84
    .line 85
    move-result v9

    .line 86
    const/high16 v11, -0x80000000

    .line 87
    .line 88
    and-int/2addr v11, v9

    .line 89
    if-nez v11, :cond_1

    .line 90
    .line 91
    invoke-virtual {v0}, Lw7/p;->y()J

    .line 92
    .line 93
    .line 94
    move-result-wide v20

    .line 95
    const v11, 0x7fffffff

    .line 96
    .line 97
    .line 98
    and-int/2addr v9, v11

    .line 99
    aput v9, v14, v10

    .line 100
    .line 101
    aput-wide v16, v15, v10

    .line 102
    .line 103
    aput-wide v18, v6, v10

    .line 104
    .line 105
    add-long v3, v3, v20

    .line 106
    .line 107
    move-object v9, v5

    .line 108
    move-object v11, v6

    .line 109
    const-wide/32 v5, 0xf4240

    .line 110
    .line 111
    .line 112
    move-object/from16 v18, v9

    .line 113
    .line 114
    sget-object v9, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 115
    .line 116
    move-object v2, v11

    .line 117
    move-object/from16 v11, v18

    .line 118
    .line 119
    invoke-static/range {v3 .. v9}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 120
    .line 121
    .line 122
    move-result-wide v5

    .line 123
    aget-wide v19, v2, v10

    .line 124
    .line 125
    sub-long v19, v5, v19

    .line 126
    .line 127
    aput-wide v19, v11, v10

    .line 128
    .line 129
    const/4 v9, 0x4

    .line 130
    invoke-virtual {v0, v9}, Lw7/p;->J(I)V

    .line 131
    .line 132
    .line 133
    aget v9, v14, v10

    .line 134
    .line 135
    move/from16 p0, v1

    .line 136
    .line 137
    int-to-long v0, v9

    .line 138
    add-long v16, v16, v0

    .line 139
    .line 140
    add-int/lit8 v10, v10, 0x1

    .line 141
    .line 142
    move/from16 v1, p0

    .line 143
    .line 144
    move-object/from16 v0, p2

    .line 145
    .line 146
    move-wide/from16 v18, v5

    .line 147
    .line 148
    move-object v5, v11

    .line 149
    move-object v6, v2

    .line 150
    const/4 v2, 0x4

    .line 151
    goto :goto_2

    .line 152
    :cond_1
    const-string v0, "Unhandled indirect reference"

    .line 153
    .line 154
    const/4 v1, 0x0

    .line 155
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    throw v0

    .line 160
    :cond_2
    move-object v11, v5

    .line 161
    move-object v2, v6

    .line 162
    invoke-static {v12, v13}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    new-instance v1, Lo8/k;

    .line 167
    .line 168
    invoke-direct {v1, v14, v15, v11, v2}, Lo8/k;-><init>([I[J[J[J)V

    .line 169
    .line 170
    .line 171
    invoke-static {v0, v1}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    return-object v0
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    invoke-static {p1, v0, v1}, Li9/p;->k(Lo8/p;ZZ)Lo8/g0;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    invoke-static {p1}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    sget-object v2, Lhr/h0;->e:Lhr/f0;

    .line 15
    .line 16
    sget-object v2, Lhr/x0;->h:Lhr/x0;

    .line 17
    .line 18
    :goto_0
    iput-object v2, p0, Li9/j;->p:Lhr/x0;

    .line 19
    .line 20
    if-nez p1, :cond_1

    .line 21
    .line 22
    return v0

    .line 23
    :cond_1
    return v1
.end method

.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 6

    .line 1
    iget v0, p0, Li9/j;->b:I

    .line 2
    .line 3
    and-int/lit8 v1, v0, 0x20

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    new-instance v1, La8/b;

    .line 8
    .line 9
    iget-object v2, p0, Li9/j;->a:Ll9/h;

    .line 10
    .line 11
    invoke-direct {v1, p1, v2}, La8/b;-><init>(Lo8/q;Ll9/h;)V

    .line 12
    .line 13
    .line 14
    move-object p1, v1

    .line 15
    :cond_0
    iput-object p1, p0, Li9/j;->G:Lo8/q;

    .line 16
    .line 17
    invoke-virtual {p0}, Li9/j;->e()V

    .line 18
    .line 19
    .line 20
    const/4 p1, 0x2

    .line 21
    new-array p1, p1, [Lo8/i0;

    .line 22
    .line 23
    iput-object p1, p0, Li9/j;->H:[Lo8/i0;

    .line 24
    .line 25
    and-int/lit8 v0, v0, 0x4

    .line 26
    .line 27
    const/16 v1, 0x64

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    iget-object v0, p0, Li9/j;->G:Lo8/q;

    .line 33
    .line 34
    const/4 v3, 0x5

    .line 35
    invoke-interface {v0, v1, v3}, Lo8/q;->q(II)Lo8/i0;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    aput-object v0, p1, v2

    .line 40
    .line 41
    const/4 p1, 0x1

    .line 42
    const/16 v1, 0x65

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    move p1, v2

    .line 46
    :goto_0
    iget-object v0, p0, Li9/j;->H:[Lo8/i0;

    .line 47
    .line 48
    invoke-static {p1, v0}, Lw7/w;->F(I[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    check-cast p1, [Lo8/i0;

    .line 53
    .line 54
    iput-object p1, p0, Li9/j;->H:[Lo8/i0;

    .line 55
    .line 56
    array-length v0, p1

    .line 57
    move v3, v2

    .line 58
    :goto_1
    if-ge v3, v0, :cond_2

    .line 59
    .line 60
    aget-object v4, p1, v3

    .line 61
    .line 62
    sget-object v5, Li9/j;->N:Lt7/o;

    .line 63
    .line 64
    invoke-interface {v4, v5}, Lo8/i0;->c(Lt7/o;)V

    .line 65
    .line 66
    .line 67
    add-int/lit8 v3, v3, 0x1

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    iget-object p1, p0, Li9/j;->c:Ljava/util/List;

    .line 71
    .line 72
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 73
    .line 74
    .line 75
    move-result v0

    .line 76
    new-array v0, v0, [Lo8/i0;

    .line 77
    .line 78
    iput-object v0, p0, Li9/j;->I:[Lo8/i0;

    .line 79
    .line 80
    :goto_2
    iget-object v0, p0, Li9/j;->I:[Lo8/i0;

    .line 81
    .line 82
    array-length v0, v0

    .line 83
    if-ge v2, v0, :cond_3

    .line 84
    .line 85
    iget-object v0, p0, Li9/j;->G:Lo8/q;

    .line 86
    .line 87
    add-int/lit8 v3, v1, 0x1

    .line 88
    .line 89
    const/4 v4, 0x3

    .line 90
    invoke-interface {v0, v1, v4}, Lo8/q;->q(II)Lo8/i0;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    check-cast v1, Lt7/o;

    .line 99
    .line 100
    invoke-interface {v0, v1}, Lo8/i0;->c(Lt7/o;)V

    .line 101
    .line 102
    .line 103
    iget-object v1, p0, Li9/j;->I:[Lo8/i0;

    .line 104
    .line 105
    aput-object v0, v1, v2

    .line 106
    .line 107
    add-int/lit8 v2, v2, 0x1

    .line 108
    .line 109
    move v1, v3

    .line 110
    goto :goto_2

    .line 111
    :cond_3
    return-void
.end method

.method public final d(JJ)V
    .locals 3

    .line 1
    iget-object p1, p0, Li9/j;->d:Landroid/util/SparseArray;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    const/4 v0, 0x0

    .line 8
    move v1, v0

    .line 9
    :goto_0
    if-ge v1, p2, :cond_0

    .line 10
    .line 11
    invoke-virtual {p1, v1}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    check-cast v2, Li9/i;

    .line 16
    .line 17
    invoke-virtual {v2}, Li9/i;->e()V

    .line 18
    .line 19
    .line 20
    add-int/lit8 v1, v1, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    iget-object p1, p0, Li9/j;->m:Ljava/util/ArrayDeque;

    .line 24
    .line 25
    invoke-virtual {p1}, Ljava/util/ArrayDeque;->clear()V

    .line 26
    .line 27
    .line 28
    iput v0, p0, Li9/j;->w:I

    .line 29
    .line 30
    iget-object p1, p0, Li9/j;->n:Lca/j;

    .line 31
    .line 32
    iget-object p1, p1, Lca/j;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p1, Ljava/util/PriorityQueue;

    .line 35
    .line 36
    invoke-virtual {p1}, Ljava/util/PriorityQueue;->clear()V

    .line 37
    .line 38
    .line 39
    iput-wide p3, p0, Li9/j;->x:J

    .line 40
    .line 41
    iget-object p1, p0, Li9/j;->l:Ljava/util/ArrayDeque;

    .line 42
    .line 43
    invoke-virtual {p1}, Ljava/util/ArrayDeque;->clear()V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p0}, Li9/j;->e()V

    .line 47
    .line 48
    .line 49
    return-void
.end method

.method public final e()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Li9/j;->q:I

    .line 3
    .line 4
    iput v0, p0, Li9/j;->t:I

    .line 5
    .line 6
    return-void
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    :goto_0
    iget v2, v0, Li9/j;->q:I

    .line 6
    .line 7
    iget-object v5, v0, Li9/j;->l:Ljava/util/ArrayDeque;

    .line 8
    .line 9
    iget-object v7, v0, Li9/j;->n:Lca/j;

    .line 10
    .line 11
    iget-object v8, v0, Li9/j;->i:Lw7/p;

    .line 12
    .line 13
    iget-object v9, v0, Li9/j;->o:Lfb/k;

    .line 14
    .line 15
    iget-object v10, v0, Li9/j;->d:Landroid/util/SparseArray;

    .line 16
    .line 17
    const/4 v13, 0x2

    .line 18
    const/4 v15, 0x1

    .line 19
    if-eqz v2, :cond_3f

    .line 20
    .line 21
    iget-object v3, v0, Li9/j;->m:Ljava/util/ArrayDeque;

    .line 22
    .line 23
    iget v4, v0, Li9/j;->b:I

    .line 24
    .line 25
    const-string v6, "FragmentedMp4Extractor"

    .line 26
    .line 27
    if-eq v2, v15, :cond_32

    .line 28
    .line 29
    const-wide v16, 0x7fffffffffffffffL

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    if-eq v2, v13, :cond_2d

    .line 35
    .line 36
    iget-object v2, v0, Li9/j;->A:Li9/i;

    .line 37
    .line 38
    if-nez v2, :cond_9

    .line 39
    .line 40
    invoke-virtual {v10}, Landroid/util/SparseArray;->size()I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    move/from16 v19, v13

    .line 45
    .line 46
    const/4 v9, 0x0

    .line 47
    const/4 v13, 0x0

    .line 48
    :goto_1
    if-ge v13, v2, :cond_4

    .line 49
    .line 50
    invoke-virtual {v10, v13}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v20

    .line 54
    const/16 v21, 0x0

    .line 55
    .line 56
    move-object/from16 v14, v20

    .line 57
    .line 58
    check-cast v14, Li9/i;

    .line 59
    .line 60
    const/16 v20, 0x8

    .line 61
    .line 62
    iget-boolean v12, v14, Li9/i;->m:Z

    .line 63
    .line 64
    move/from16 v22, v15

    .line 65
    .line 66
    iget-object v15, v14, Li9/i;->b:Li9/s;

    .line 67
    .line 68
    if-nez v12, :cond_0

    .line 69
    .line 70
    iget v5, v14, Li9/i;->f:I

    .line 71
    .line 72
    iget-object v11, v14, Li9/i;->d:Li9/t;

    .line 73
    .line 74
    iget v11, v11, Li9/t;->b:I

    .line 75
    .line 76
    if-eq v5, v11, :cond_3

    .line 77
    .line 78
    :cond_0
    if-eqz v12, :cond_1

    .line 79
    .line 80
    iget v5, v14, Li9/i;->h:I

    .line 81
    .line 82
    iget v11, v15, Li9/s;->d:I

    .line 83
    .line 84
    if-ne v5, v11, :cond_1

    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_1
    if-nez v12, :cond_2

    .line 88
    .line 89
    iget-object v5, v14, Li9/i;->d:Li9/t;

    .line 90
    .line 91
    iget-object v5, v5, Li9/t;->c:[J

    .line 92
    .line 93
    iget v11, v14, Li9/i;->f:I

    .line 94
    .line 95
    aget-wide v11, v5, v11

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_2
    iget-object v5, v15, Li9/s;->f:[J

    .line 99
    .line 100
    iget v11, v14, Li9/i;->h:I

    .line 101
    .line 102
    aget-wide v11, v5, v11

    .line 103
    .line 104
    :goto_2
    cmp-long v5, v11, v16

    .line 105
    .line 106
    if-gez v5, :cond_3

    .line 107
    .line 108
    move-wide/from16 v16, v11

    .line 109
    .line 110
    move-object v9, v14

    .line 111
    :cond_3
    :goto_3
    add-int/lit8 v13, v13, 0x1

    .line 112
    .line 113
    move/from16 v15, v22

    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_4
    move/from16 v22, v15

    .line 117
    .line 118
    const/16 v20, 0x8

    .line 119
    .line 120
    const/16 v21, 0x0

    .line 121
    .line 122
    if-nez v9, :cond_6

    .line 123
    .line 124
    iget-wide v2, v0, Li9/j;->v:J

    .line 125
    .line 126
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 127
    .line 128
    .line 129
    move-result-wide v4

    .line 130
    sub-long/2addr v2, v4

    .line 131
    long-to-int v2, v2

    .line 132
    if-ltz v2, :cond_5

    .line 133
    .line 134
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v0}, Li9/j;->e()V

    .line 138
    .line 139
    .line 140
    goto/16 :goto_0

    .line 141
    .line 142
    :cond_5
    const-string v0, "Offset to end of mdat was negative."

    .line 143
    .line 144
    const/4 v1, 0x0

    .line 145
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    throw v0

    .line 150
    :cond_6
    iget-boolean v2, v9, Li9/i;->m:Z

    .line 151
    .line 152
    if-nez v2, :cond_7

    .line 153
    .line 154
    iget-object v2, v9, Li9/i;->d:Li9/t;

    .line 155
    .line 156
    iget-object v2, v2, Li9/t;->c:[J

    .line 157
    .line 158
    iget v5, v9, Li9/i;->f:I

    .line 159
    .line 160
    aget-wide v10, v2, v5

    .line 161
    .line 162
    goto :goto_4

    .line 163
    :cond_7
    iget-object v2, v9, Li9/i;->b:Li9/s;

    .line 164
    .line 165
    iget-object v2, v2, Li9/s;->f:[J

    .line 166
    .line 167
    iget v5, v9, Li9/i;->h:I

    .line 168
    .line 169
    aget-wide v10, v2, v5

    .line 170
    .line 171
    :goto_4
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 172
    .line 173
    .line 174
    move-result-wide v12

    .line 175
    sub-long/2addr v10, v12

    .line 176
    long-to-int v2, v10

    .line 177
    if-gez v2, :cond_8

    .line 178
    .line 179
    const-string v2, "Ignoring negative offset to sample data."

    .line 180
    .line 181
    invoke-static {v6, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    move/from16 v2, v21

    .line 185
    .line 186
    :cond_8
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 187
    .line 188
    .line 189
    iput-object v9, v0, Li9/j;->A:Li9/i;

    .line 190
    .line 191
    move-object v2, v9

    .line 192
    goto :goto_5

    .line 193
    :cond_9
    move/from16 v19, v13

    .line 194
    .line 195
    move/from16 v22, v15

    .line 196
    .line 197
    const/16 v20, 0x8

    .line 198
    .line 199
    const/16 v21, 0x0

    .line 200
    .line 201
    :goto_5
    iget-object v9, v2, Li9/i;->a:Lo8/i0;

    .line 202
    .line 203
    iget-object v5, v2, Li9/i;->b:Li9/s;

    .line 204
    .line 205
    iget v6, v0, Li9/j;->q:I

    .line 206
    .line 207
    const/4 v10, 0x6

    .line 208
    const-string v11, "video/hevc"

    .line 209
    .line 210
    const-string v12, "video/avc"

    .line 211
    .line 212
    const/4 v13, 0x4

    .line 213
    const/4 v14, 0x3

    .line 214
    if-ne v6, v14, :cond_14

    .line 215
    .line 216
    iget-boolean v6, v2, Li9/i;->m:Z

    .line 217
    .line 218
    if-nez v6, :cond_a

    .line 219
    .line 220
    iget-object v6, v2, Li9/i;->d:Li9/t;

    .line 221
    .line 222
    iget-object v6, v6, Li9/t;->d:[I

    .line 223
    .line 224
    iget v14, v2, Li9/i;->f:I

    .line 225
    .line 226
    aget v6, v6, v14

    .line 227
    .line 228
    goto :goto_6

    .line 229
    :cond_a
    iget-object v6, v5, Li9/s;->h:[I

    .line 230
    .line 231
    iget v14, v2, Li9/i;->f:I

    .line 232
    .line 233
    aget v6, v6, v14

    .line 234
    .line 235
    :goto_6
    iput v6, v0, Li9/j;->B:I

    .line 236
    .line 237
    iget-object v6, v2, Li9/i;->d:Li9/t;

    .line 238
    .line 239
    iget-object v6, v6, Li9/t;->a:Li9/q;

    .line 240
    .line 241
    iget-object v6, v6, Li9/q;->g:Lt7/o;

    .line 242
    .line 243
    iget-object v14, v6, Lt7/o;->n:Ljava/lang/String;

    .line 244
    .line 245
    invoke-static {v14, v12}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    move-result v14

    .line 249
    if-eqz v14, :cond_c

    .line 250
    .line 251
    and-int/lit8 v4, v4, 0x40

    .line 252
    .line 253
    if-eqz v4, :cond_b

    .line 254
    .line 255
    :goto_7
    move/from16 v4, v22

    .line 256
    .line 257
    goto :goto_8

    .line 258
    :cond_b
    move/from16 v4, v21

    .line 259
    .line 260
    goto :goto_8

    .line 261
    :cond_c
    iget-object v6, v6, Lt7/o;->n:Ljava/lang/String;

    .line 262
    .line 263
    invoke-static {v6, v11}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    move-result v6

    .line 267
    if-eqz v6, :cond_b

    .line 268
    .line 269
    and-int/lit16 v4, v4, 0x80

    .line 270
    .line 271
    if-eqz v4, :cond_b

    .line 272
    .line 273
    goto :goto_7

    .line 274
    :goto_8
    xor-int/lit8 v4, v4, 0x1

    .line 275
    .line 276
    iput-boolean v4, v0, Li9/j;->E:Z

    .line 277
    .line 278
    iget v4, v2, Li9/i;->f:I

    .line 279
    .line 280
    iget v6, v2, Li9/i;->i:I

    .line 281
    .line 282
    if-ge v4, v6, :cond_11

    .line 283
    .line 284
    iget v3, v0, Li9/j;->B:I

    .line 285
    .line 286
    invoke-interface {v1, v3}, Lo8/p;->n(I)V

    .line 287
    .line 288
    .line 289
    invoke-virtual {v2}, Li9/i;->b()Li9/r;

    .line 290
    .line 291
    .line 292
    move-result-object v1

    .line 293
    if-nez v1, :cond_d

    .line 294
    .line 295
    goto :goto_9

    .line 296
    :cond_d
    iget-object v3, v5, Li9/s;->n:Lw7/p;

    .line 297
    .line 298
    iget v1, v1, Li9/r;->d:I

    .line 299
    .line 300
    if-eqz v1, :cond_e

    .line 301
    .line 302
    invoke-virtual {v3, v1}, Lw7/p;->J(I)V

    .line 303
    .line 304
    .line 305
    :cond_e
    iget v1, v2, Li9/i;->f:I

    .line 306
    .line 307
    iget-boolean v4, v5, Li9/s;->k:Z

    .line 308
    .line 309
    if-eqz v4, :cond_f

    .line 310
    .line 311
    iget-object v4, v5, Li9/s;->l:[Z

    .line 312
    .line 313
    aget-boolean v1, v4, v1

    .line 314
    .line 315
    if-eqz v1, :cond_f

    .line 316
    .line 317
    invoke-virtual {v3}, Lw7/p;->C()I

    .line 318
    .line 319
    .line 320
    move-result v1

    .line 321
    mul-int/2addr v1, v10

    .line 322
    invoke-virtual {v3, v1}, Lw7/p;->J(I)V

    .line 323
    .line 324
    .line 325
    :cond_f
    :goto_9
    invoke-virtual {v2}, Li9/i;->c()Z

    .line 326
    .line 327
    .line 328
    move-result v1

    .line 329
    if-nez v1, :cond_10

    .line 330
    .line 331
    const/4 v1, 0x0

    .line 332
    iput-object v1, v0, Li9/j;->A:Li9/i;

    .line 333
    .line 334
    :cond_10
    const/4 v14, 0x3

    .line 335
    iput v14, v0, Li9/j;->q:I

    .line 336
    .line 337
    return v21

    .line 338
    :cond_11
    iget-object v4, v2, Li9/i;->d:Li9/t;

    .line 339
    .line 340
    iget-object v4, v4, Li9/t;->a:Li9/q;

    .line 341
    .line 342
    iget v4, v4, Li9/q;->h:I

    .line 343
    .line 344
    move/from16 v6, v22

    .line 345
    .line 346
    if-ne v4, v6, :cond_12

    .line 347
    .line 348
    iget v4, v0, Li9/j;->B:I

    .line 349
    .line 350
    add-int/lit8 v4, v4, -0x8

    .line 351
    .line 352
    iput v4, v0, Li9/j;->B:I

    .line 353
    .line 354
    move/from16 v4, v20

    .line 355
    .line 356
    invoke-interface {v1, v4}, Lo8/p;->n(I)V

    .line 357
    .line 358
    .line 359
    :cond_12
    iget-object v4, v2, Li9/i;->d:Li9/t;

    .line 360
    .line 361
    iget-object v4, v4, Li9/t;->a:Li9/q;

    .line 362
    .line 363
    iget-object v4, v4, Li9/q;->g:Lt7/o;

    .line 364
    .line 365
    iget-object v4, v4, Lt7/o;->n:Ljava/lang/String;

    .line 366
    .line 367
    const-string v6, "audio/ac4"

    .line 368
    .line 369
    invoke-virtual {v6, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 370
    .line 371
    .line 372
    move-result v4

    .line 373
    if-eqz v4, :cond_13

    .line 374
    .line 375
    iget v4, v0, Li9/j;->B:I

    .line 376
    .line 377
    const/4 v6, 0x7

    .line 378
    invoke-virtual {v2, v4, v6}, Li9/i;->d(II)I

    .line 379
    .line 380
    .line 381
    move-result v4

    .line 382
    iput v4, v0, Li9/j;->C:I

    .line 383
    .line 384
    iget v4, v0, Li9/j;->B:I

    .line 385
    .line 386
    invoke-static {v4, v8}, Lo8/b;->g(ILw7/p;)V

    .line 387
    .line 388
    .line 389
    move/from16 v4, v21

    .line 390
    .line 391
    invoke-interface {v9, v8, v6, v4}, Lo8/i0;->a(Lw7/p;II)V

    .line 392
    .line 393
    .line 394
    iget v8, v0, Li9/j;->C:I

    .line 395
    .line 396
    add-int/2addr v8, v6

    .line 397
    iput v8, v0, Li9/j;->C:I

    .line 398
    .line 399
    goto :goto_a

    .line 400
    :cond_13
    move/from16 v4, v21

    .line 401
    .line 402
    iget v6, v0, Li9/j;->B:I

    .line 403
    .line 404
    invoke-virtual {v2, v6, v4}, Li9/i;->d(II)I

    .line 405
    .line 406
    .line 407
    move-result v6

    .line 408
    iput v6, v0, Li9/j;->C:I

    .line 409
    .line 410
    :goto_a
    iget v6, v0, Li9/j;->B:I

    .line 411
    .line 412
    iget v8, v0, Li9/j;->C:I

    .line 413
    .line 414
    add-int/2addr v6, v8

    .line 415
    iput v6, v0, Li9/j;->B:I

    .line 416
    .line 417
    iput v13, v0, Li9/j;->q:I

    .line 418
    .line 419
    iput v4, v0, Li9/j;->D:I

    .line 420
    .line 421
    :cond_14
    iget-object v4, v2, Li9/i;->d:Li9/t;

    .line 422
    .line 423
    iget-object v6, v4, Li9/t;->a:Li9/q;

    .line 424
    .line 425
    iget-boolean v8, v2, Li9/i;->m:Z

    .line 426
    .line 427
    if-nez v8, :cond_15

    .line 428
    .line 429
    iget-object v4, v4, Li9/t;->f:[J

    .line 430
    .line 431
    iget v5, v2, Li9/i;->f:I

    .line 432
    .line 433
    aget-wide v4, v4, v5

    .line 434
    .line 435
    goto :goto_b

    .line 436
    :cond_15
    iget v4, v2, Li9/i;->f:I

    .line 437
    .line 438
    iget-object v5, v5, Li9/s;->i:[J

    .line 439
    .line 440
    aget-wide v4, v5, v4

    .line 441
    .line 442
    :goto_b
    iget v8, v6, Li9/q;->k:I

    .line 443
    .line 444
    iget-object v6, v6, Li9/q;->g:Lt7/o;

    .line 445
    .line 446
    if-eqz v8, :cond_25

    .line 447
    .line 448
    iget-object v14, v0, Li9/j;->f:Lw7/p;

    .line 449
    .line 450
    iget-object v15, v14, Lw7/p;->a:[B

    .line 451
    .line 452
    const/16 v21, 0x0

    .line 453
    .line 454
    aput-byte v21, v15, v21

    .line 455
    .line 456
    const/16 v22, 0x1

    .line 457
    .line 458
    aput-byte v21, v15, v22

    .line 459
    .line 460
    aput-byte v21, v15, v19

    .line 461
    .line 462
    rsub-int/lit8 v10, v8, 0x4

    .line 463
    .line 464
    :goto_c
    iget v13, v0, Li9/j;->C:I

    .line 465
    .line 466
    move-object/from16 v17, v2

    .line 467
    .line 468
    iget v2, v0, Li9/j;->B:I

    .line 469
    .line 470
    if-ge v13, v2, :cond_26

    .line 471
    .line 472
    iget v2, v0, Li9/j;->D:I

    .line 473
    .line 474
    if-nez v2, :cond_20

    .line 475
    .line 476
    iget-object v2, v0, Li9/j;->I:[Lo8/i0;

    .line 477
    .line 478
    array-length v2, v2

    .line 479
    if-gtz v2, :cond_16

    .line 480
    .line 481
    iget-boolean v2, v0, Li9/j;->E:Z

    .line 482
    .line 483
    if-nez v2, :cond_17

    .line 484
    .line 485
    :cond_16
    invoke-static {v6}, Lx7/n;->d(Lt7/o;)I

    .line 486
    .line 487
    .line 488
    move-result v2

    .line 489
    add-int v13, v8, v2

    .line 490
    .line 491
    move/from16 v19, v2

    .line 492
    .line 493
    iget v2, v0, Li9/j;->B:I

    .line 494
    .line 495
    move/from16 v20, v2

    .line 496
    .line 497
    iget v2, v0, Li9/j;->C:I

    .line 498
    .line 499
    sub-int v2, v20, v2

    .line 500
    .line 501
    if-gt v13, v2, :cond_17

    .line 502
    .line 503
    move/from16 v2, v19

    .line 504
    .line 505
    goto :goto_d

    .line 506
    :cond_17
    const/4 v2, 0x0

    .line 507
    :goto_d
    add-int v13, v8, v2

    .line 508
    .line 509
    invoke-interface {v1, v15, v10, v13}, Lo8/p;->readFully([BII)V

    .line 510
    .line 511
    .line 512
    const/4 v13, 0x0

    .line 513
    invoke-virtual {v14, v13}, Lw7/p;->I(I)V

    .line 514
    .line 515
    .line 516
    invoke-virtual {v14}, Lw7/p;->j()I

    .line 517
    .line 518
    .line 519
    move-result v19

    .line 520
    if-ltz v19, :cond_1f

    .line 521
    .line 522
    sub-int v13, v19, v2

    .line 523
    .line 524
    iput v13, v0, Li9/j;->D:I

    .line 525
    .line 526
    iget-object v13, v0, Li9/j;->e:Lw7/p;

    .line 527
    .line 528
    move/from16 v20, v8

    .line 529
    .line 530
    const/4 v8, 0x0

    .line 531
    invoke-virtual {v13, v8}, Lw7/p;->I(I)V

    .line 532
    .line 533
    .line 534
    move/from16 v19, v10

    .line 535
    .line 536
    const/4 v10, 0x4

    .line 537
    invoke-interface {v9, v13, v10, v8}, Lo8/i0;->a(Lw7/p;II)V

    .line 538
    .line 539
    .line 540
    iget v8, v0, Li9/j;->C:I

    .line 541
    .line 542
    add-int/2addr v8, v10

    .line 543
    iput v8, v0, Li9/j;->C:I

    .line 544
    .line 545
    iget v8, v0, Li9/j;->B:I

    .line 546
    .line 547
    add-int v8, v8, v19

    .line 548
    .line 549
    iput v8, v0, Li9/j;->B:I

    .line 550
    .line 551
    iget-object v8, v0, Li9/j;->I:[Lo8/i0;

    .line 552
    .line 553
    array-length v8, v8

    .line 554
    if-lez v8, :cond_1c

    .line 555
    .line 556
    if-lez v2, :cond_1c

    .line 557
    .line 558
    aget-byte v8, v15, v10

    .line 559
    .line 560
    iget-object v10, v6, Lt7/o;->n:Ljava/lang/String;

    .line 561
    .line 562
    iget-object v13, v6, Lt7/o;->k:Ljava/lang/String;

    .line 563
    .line 564
    invoke-static {v10, v12}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 565
    .line 566
    .line 567
    move-result v10

    .line 568
    if-nez v10, :cond_19

    .line 569
    .line 570
    invoke-static {v13, v12}, Lt7/d0;->b(Ljava/lang/String;Ljava/lang/String;)Z

    .line 571
    .line 572
    .line 573
    move-result v10

    .line 574
    if-eqz v10, :cond_18

    .line 575
    .line 576
    goto :goto_e

    .line 577
    :cond_18
    move/from16 v23, v8

    .line 578
    .line 579
    const/4 v8, 0x6

    .line 580
    goto :goto_f

    .line 581
    :cond_19
    :goto_e
    and-int/lit8 v10, v8, 0x1f

    .line 582
    .line 583
    move/from16 v23, v8

    .line 584
    .line 585
    const/4 v8, 0x6

    .line 586
    if-eq v10, v8, :cond_1b

    .line 587
    .line 588
    :goto_f
    iget-object v10, v6, Lt7/o;->n:Ljava/lang/String;

    .line 589
    .line 590
    invoke-static {v10, v11}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 591
    .line 592
    .line 593
    move-result v10

    .line 594
    if-nez v10, :cond_1a

    .line 595
    .line 596
    invoke-static {v13, v11}, Lt7/d0;->b(Ljava/lang/String;Ljava/lang/String;)Z

    .line 597
    .line 598
    .line 599
    move-result v10

    .line 600
    if-eqz v10, :cond_1d

    .line 601
    .line 602
    :cond_1a
    and-int/lit8 v10, v23, 0x7e

    .line 603
    .line 604
    const/16 v22, 0x1

    .line 605
    .line 606
    shr-int/lit8 v10, v10, 0x1

    .line 607
    .line 608
    const/16 v13, 0x27

    .line 609
    .line 610
    if-ne v10, v13, :cond_1d

    .line 611
    .line 612
    :cond_1b
    const/4 v10, 0x1

    .line 613
    goto :goto_10

    .line 614
    :cond_1c
    const/4 v8, 0x6

    .line 615
    :cond_1d
    const/4 v10, 0x0

    .line 616
    :goto_10
    iput-boolean v10, v0, Li9/j;->F:Z

    .line 617
    .line 618
    const/4 v13, 0x0

    .line 619
    invoke-interface {v9, v14, v2, v13}, Lo8/i0;->a(Lw7/p;II)V

    .line 620
    .line 621
    .line 622
    iget v10, v0, Li9/j;->C:I

    .line 623
    .line 624
    add-int/2addr v10, v2

    .line 625
    iput v10, v0, Li9/j;->C:I

    .line 626
    .line 627
    if-lez v2, :cond_1e

    .line 628
    .line 629
    iget-boolean v10, v0, Li9/j;->E:Z

    .line 630
    .line 631
    if-nez v10, :cond_1e

    .line 632
    .line 633
    invoke-static {v15, v2, v6}, Lx7/n;->c([BILt7/o;)Z

    .line 634
    .line 635
    .line 636
    move-result v2

    .line 637
    if-eqz v2, :cond_1e

    .line 638
    .line 639
    const/4 v2, 0x1

    .line 640
    iput-boolean v2, v0, Li9/j;->E:Z

    .line 641
    .line 642
    :cond_1e
    :goto_11
    move-object/from16 v2, v17

    .line 643
    .line 644
    move/from16 v10, v19

    .line 645
    .line 646
    move/from16 v8, v20

    .line 647
    .line 648
    goto/16 :goto_c

    .line 649
    .line 650
    :cond_1f
    const-string v0, "Invalid NAL length"

    .line 651
    .line 652
    const/4 v1, 0x0

    .line 653
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 654
    .line 655
    .line 656
    move-result-object v0

    .line 657
    throw v0

    .line 658
    :cond_20
    move/from16 v20, v8

    .line 659
    .line 660
    move/from16 v19, v10

    .line 661
    .line 662
    const/4 v8, 0x6

    .line 663
    iget-boolean v10, v0, Li9/j;->F:Z

    .line 664
    .line 665
    if-eqz v10, :cond_24

    .line 666
    .line 667
    iget-object v10, v0, Li9/j;->g:Lw7/p;

    .line 668
    .line 669
    invoke-virtual {v10, v2}, Lw7/p;->F(I)V

    .line 670
    .line 671
    .line 672
    iget-object v2, v10, Lw7/p;->a:[B

    .line 673
    .line 674
    iget v13, v0, Li9/j;->D:I

    .line 675
    .line 676
    const/4 v8, 0x0

    .line 677
    invoke-interface {v1, v2, v8, v13}, Lo8/p;->readFully([BII)V

    .line 678
    .line 679
    .line 680
    iget v2, v0, Li9/j;->D:I

    .line 681
    .line 682
    invoke-interface {v9, v10, v2, v8}, Lo8/i0;->a(Lw7/p;II)V

    .line 683
    .line 684
    .line 685
    iget v2, v0, Li9/j;->D:I

    .line 686
    .line 687
    iget-object v13, v10, Lw7/p;->a:[B

    .line 688
    .line 689
    move/from16 v23, v2

    .line 690
    .line 691
    iget v2, v10, Lw7/p;->c:I

    .line 692
    .line 693
    invoke-static {v2, v13}, Lx7/n;->m(I[B)I

    .line 694
    .line 695
    .line 696
    move-result v2

    .line 697
    invoke-virtual {v10, v8}, Lw7/p;->I(I)V

    .line 698
    .line 699
    .line 700
    invoke-virtual {v10, v2}, Lw7/p;->H(I)V

    .line 701
    .line 702
    .line 703
    iget v2, v6, Lt7/o;->p:I

    .line 704
    .line 705
    const/4 v13, -0x1

    .line 706
    if-ne v2, v13, :cond_21

    .line 707
    .line 708
    iget v2, v7, Lca/j;->a:I

    .line 709
    .line 710
    if-eqz v2, :cond_22

    .line 711
    .line 712
    invoke-virtual {v7, v8}, Lca/j;->m(I)V

    .line 713
    .line 714
    .line 715
    goto :goto_12

    .line 716
    :cond_21
    iget v8, v7, Lca/j;->a:I

    .line 717
    .line 718
    if-eq v8, v2, :cond_22

    .line 719
    .line 720
    invoke-virtual {v7, v2}, Lca/j;->m(I)V

    .line 721
    .line 722
    .line 723
    :cond_22
    :goto_12
    invoke-virtual {v7, v4, v5, v10}, Lca/j;->a(JLw7/p;)V

    .line 724
    .line 725
    .line 726
    invoke-virtual/range {v17 .. v17}, Li9/i;->a()I

    .line 727
    .line 728
    .line 729
    move-result v2

    .line 730
    const/16 v16, 0x4

    .line 731
    .line 732
    and-int/lit8 v2, v2, 0x4

    .line 733
    .line 734
    const/4 v13, 0x0

    .line 735
    if-eqz v2, :cond_23

    .line 736
    .line 737
    invoke-virtual {v7, v13}, Lca/j;->d(I)V

    .line 738
    .line 739
    .line 740
    :cond_23
    move/from16 v2, v23

    .line 741
    .line 742
    goto :goto_13

    .line 743
    :cond_24
    const/4 v13, 0x0

    .line 744
    const/16 v16, 0x4

    .line 745
    .line 746
    invoke-interface {v9, v1, v2, v13}, Lo8/i0;->d(Lt7/g;IZ)I

    .line 747
    .line 748
    .line 749
    move-result v2

    .line 750
    :goto_13
    iget v8, v0, Li9/j;->C:I

    .line 751
    .line 752
    add-int/2addr v8, v2

    .line 753
    iput v8, v0, Li9/j;->C:I

    .line 754
    .line 755
    iget v8, v0, Li9/j;->D:I

    .line 756
    .line 757
    sub-int/2addr v8, v2

    .line 758
    iput v8, v0, Li9/j;->D:I

    .line 759
    .line 760
    goto :goto_11

    .line 761
    :cond_25
    move-object/from16 v17, v2

    .line 762
    .line 763
    :goto_14
    iget v2, v0, Li9/j;->C:I

    .line 764
    .line 765
    iget v6, v0, Li9/j;->B:I

    .line 766
    .line 767
    if-ge v2, v6, :cond_26

    .line 768
    .line 769
    sub-int/2addr v6, v2

    .line 770
    const/4 v13, 0x0

    .line 771
    invoke-interface {v9, v1, v6, v13}, Lo8/i0;->d(Lt7/g;IZ)I

    .line 772
    .line 773
    .line 774
    move-result v2

    .line 775
    iget v6, v0, Li9/j;->C:I

    .line 776
    .line 777
    add-int/2addr v6, v2

    .line 778
    iput v6, v0, Li9/j;->C:I

    .line 779
    .line 780
    goto :goto_14

    .line 781
    :cond_26
    invoke-virtual/range {v17 .. v17}, Li9/i;->a()I

    .line 782
    .line 783
    .line 784
    move-result v1

    .line 785
    iget-boolean v2, v0, Li9/j;->E:Z

    .line 786
    .line 787
    if-nez v2, :cond_27

    .line 788
    .line 789
    const/high16 v2, 0x4000000

    .line 790
    .line 791
    or-int/2addr v1, v2

    .line 792
    :cond_27
    move v12, v1

    .line 793
    invoke-virtual/range {v17 .. v17}, Li9/i;->b()Li9/r;

    .line 794
    .line 795
    .line 796
    move-result-object v1

    .line 797
    if-eqz v1, :cond_28

    .line 798
    .line 799
    iget-object v1, v1, Li9/r;->c:Lo8/h0;

    .line 800
    .line 801
    move-object v15, v1

    .line 802
    goto :goto_15

    .line 803
    :cond_28
    const/4 v15, 0x0

    .line 804
    :goto_15
    iget v13, v0, Li9/j;->B:I

    .line 805
    .line 806
    const/4 v14, 0x0

    .line 807
    move-wide v10, v4

    .line 808
    invoke-interface/range {v9 .. v15}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 809
    .line 810
    .line 811
    :cond_29
    invoke-virtual {v3}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 812
    .line 813
    .line 814
    move-result v1

    .line 815
    if-nez v1, :cond_2b

    .line 816
    .line 817
    invoke-virtual {v3}, Ljava/util/ArrayDeque;->removeFirst()Ljava/lang/Object;

    .line 818
    .line 819
    .line 820
    move-result-object v1

    .line 821
    check-cast v1, Li9/h;

    .line 822
    .line 823
    iget v2, v0, Li9/j;->w:I

    .line 824
    .line 825
    iget v4, v1, Li9/h;->c:I

    .line 826
    .line 827
    sub-int/2addr v2, v4

    .line 828
    iput v2, v0, Li9/j;->w:I

    .line 829
    .line 830
    iget-wide v4, v1, Li9/h;->a:J

    .line 831
    .line 832
    iget-boolean v2, v1, Li9/h;->b:Z

    .line 833
    .line 834
    if-eqz v2, :cond_2a

    .line 835
    .line 836
    add-long/2addr v4, v10

    .line 837
    :cond_2a
    move-wide/from16 v24, v4

    .line 838
    .line 839
    iget-object v2, v0, Li9/j;->H:[Lo8/i0;

    .line 840
    .line 841
    array-length v4, v2

    .line 842
    const/4 v5, 0x0

    .line 843
    :goto_16
    if-ge v5, v4, :cond_29

    .line 844
    .line 845
    aget-object v23, v2, v5

    .line 846
    .line 847
    iget v6, v1, Li9/h;->c:I

    .line 848
    .line 849
    iget v7, v0, Li9/j;->w:I

    .line 850
    .line 851
    const/16 v29, 0x0

    .line 852
    .line 853
    const/16 v26, 0x1

    .line 854
    .line 855
    move/from16 v27, v6

    .line 856
    .line 857
    move/from16 v28, v7

    .line 858
    .line 859
    invoke-interface/range {v23 .. v29}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 860
    .line 861
    .line 862
    add-int/lit8 v5, v5, 0x1

    .line 863
    .line 864
    goto :goto_16

    .line 865
    :cond_2b
    invoke-virtual/range {v17 .. v17}, Li9/i;->c()Z

    .line 866
    .line 867
    .line 868
    move-result v1

    .line 869
    if-nez v1, :cond_2c

    .line 870
    .line 871
    const/4 v1, 0x0

    .line 872
    iput-object v1, v0, Li9/j;->A:Li9/i;

    .line 873
    .line 874
    :cond_2c
    const/4 v14, 0x3

    .line 875
    iput v14, v0, Li9/j;->q:I

    .line 876
    .line 877
    const/16 v21, 0x0

    .line 878
    .line 879
    return v21

    .line 880
    :cond_2d
    invoke-virtual {v10}, Landroid/util/SparseArray;->size()I

    .line 881
    .line 882
    .line 883
    move-result v2

    .line 884
    const/4 v3, 0x0

    .line 885
    const/4 v4, 0x0

    .line 886
    :goto_17
    if-ge v3, v2, :cond_2f

    .line 887
    .line 888
    invoke-virtual {v10, v3}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 889
    .line 890
    .line 891
    move-result-object v5

    .line 892
    check-cast v5, Li9/i;

    .line 893
    .line 894
    iget-object v5, v5, Li9/i;->b:Li9/s;

    .line 895
    .line 896
    iget-boolean v6, v5, Li9/s;->o:Z

    .line 897
    .line 898
    if-eqz v6, :cond_2e

    .line 899
    .line 900
    iget-wide v5, v5, Li9/s;->c:J

    .line 901
    .line 902
    cmp-long v7, v5, v16

    .line 903
    .line 904
    if-gez v7, :cond_2e

    .line 905
    .line 906
    invoke-virtual {v10, v3}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 907
    .line 908
    .line 909
    move-result-object v4

    .line 910
    check-cast v4, Li9/i;

    .line 911
    .line 912
    move-wide/from16 v16, v5

    .line 913
    .line 914
    :cond_2e
    add-int/lit8 v3, v3, 0x1

    .line 915
    .line 916
    goto :goto_17

    .line 917
    :cond_2f
    if-nez v4, :cond_30

    .line 918
    .line 919
    const/4 v14, 0x3

    .line 920
    iput v14, v0, Li9/j;->q:I

    .line 921
    .line 922
    goto/16 :goto_0

    .line 923
    .line 924
    :cond_30
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 925
    .line 926
    .line 927
    move-result-wide v2

    .line 928
    sub-long v2, v16, v2

    .line 929
    .line 930
    long-to-int v2, v2

    .line 931
    if-ltz v2, :cond_31

    .line 932
    .line 933
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 934
    .line 935
    .line 936
    iget-object v2, v4, Li9/i;->b:Li9/s;

    .line 937
    .line 938
    iget-object v3, v2, Li9/s;->n:Lw7/p;

    .line 939
    .line 940
    iget-object v4, v3, Lw7/p;->a:[B

    .line 941
    .line 942
    iget v5, v3, Lw7/p;->c:I

    .line 943
    .line 944
    const/4 v13, 0x0

    .line 945
    invoke-interface {v1, v4, v13, v5}, Lo8/p;->readFully([BII)V

    .line 946
    .line 947
    .line 948
    invoke-virtual {v3, v13}, Lw7/p;->I(I)V

    .line 949
    .line 950
    .line 951
    iput-boolean v13, v2, Li9/s;->o:Z

    .line 952
    .line 953
    goto/16 :goto_0

    .line 954
    .line 955
    :cond_31
    const-string v0, "Offset to encryption data was negative."

    .line 956
    .line 957
    const/4 v1, 0x0

    .line 958
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 959
    .line 960
    .line 961
    move-result-object v0

    .line 962
    throw v0

    .line 963
    :cond_32
    iget-wide v7, v0, Li9/j;->s:J

    .line 964
    .line 965
    iget v2, v0, Li9/j;->t:I

    .line 966
    .line 967
    int-to-long v10, v2

    .line 968
    sub-long/2addr v7, v10

    .line 969
    long-to-int v2, v7

    .line 970
    iget-object v7, v0, Li9/j;->u:Lw7/p;

    .line 971
    .line 972
    if-eqz v7, :cond_3e

    .line 973
    .line 974
    iget-object v8, v7, Lw7/p;->a:[B

    .line 975
    .line 976
    const/16 v10, 0x8

    .line 977
    .line 978
    invoke-interface {v1, v8, v10, v2}, Lo8/p;->readFully([BII)V

    .line 979
    .line 980
    .line 981
    new-instance v2, Lx7/d;

    .line 982
    .line 983
    iget v8, v0, Li9/j;->r:I

    .line 984
    .line 985
    invoke-direct {v2, v8, v7}, Lx7/d;-><init>(ILw7/p;)V

    .line 986
    .line 987
    .line 988
    invoke-virtual {v5}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 989
    .line 990
    .line 991
    move-result v10

    .line 992
    if-nez v10, :cond_33

    .line 993
    .line 994
    invoke-virtual {v5}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 995
    .line 996
    .line 997
    move-result-object v3

    .line 998
    check-cast v3, Lx7/c;

    .line 999
    .line 1000
    iget-object v3, v3, Lx7/c;->g:Ljava/util/ArrayList;

    .line 1001
    .line 1002
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1003
    .line 1004
    .line 1005
    goto/16 :goto_1c

    .line 1006
    .line 1007
    :cond_33
    const v2, 0x73696478

    .line 1008
    .line 1009
    .line 1010
    if-ne v8, v2, :cond_35

    .line 1011
    .line 1012
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1013
    .line 1014
    .line 1015
    move-result-wide v2

    .line 1016
    invoke-static {v2, v3, v7}, Li9/j;->i(JLw7/p;)Landroid/util/Pair;

    .line 1017
    .line 1018
    .line 1019
    move-result-object v2

    .line 1020
    iget-object v3, v2, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 1021
    .line 1022
    check-cast v3, Lo8/k;

    .line 1023
    .line 1024
    invoke-virtual {v9, v3}, Lfb/k;->a(Lo8/k;)V

    .line 1025
    .line 1026
    .line 1027
    iget-boolean v3, v0, Li9/j;->J:Z

    .line 1028
    .line 1029
    if-nez v3, :cond_34

    .line 1030
    .line 1031
    iget-object v3, v2, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 1032
    .line 1033
    check-cast v3, Ljava/lang/Long;

    .line 1034
    .line 1035
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 1036
    .line 1037
    .line 1038
    move-result-wide v3

    .line 1039
    iput-wide v3, v0, Li9/j;->z:J

    .line 1040
    .line 1041
    iget-object v3, v0, Li9/j;->G:Lo8/q;

    .line 1042
    .line 1043
    iget-object v2, v2, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 1044
    .line 1045
    check-cast v2, Lo8/c0;

    .line 1046
    .line 1047
    invoke-interface {v3, v2}, Lo8/q;->c(Lo8/c0;)V

    .line 1048
    .line 1049
    .line 1050
    const/4 v2, 0x1

    .line 1051
    iput-boolean v2, v0, Li9/j;->J:Z

    .line 1052
    .line 1053
    goto/16 :goto_1c

    .line 1054
    .line 1055
    :cond_34
    const/4 v2, 0x1

    .line 1056
    and-int/lit16 v3, v4, 0x100

    .line 1057
    .line 1058
    if-eqz v3, :cond_3d

    .line 1059
    .line 1060
    iget-boolean v3, v0, Li9/j;->K:Z

    .line 1061
    .line 1062
    if-nez v3, :cond_3d

    .line 1063
    .line 1064
    iget-object v3, v9, Lfb/k;->a:Ljava/util/LinkedHashMap;

    .line 1065
    .line 1066
    invoke-interface {v3}, Ljava/util/Map;->size()I

    .line 1067
    .line 1068
    .line 1069
    move-result v3

    .line 1070
    if-le v3, v2, :cond_3d

    .line 1071
    .line 1072
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1073
    .line 1074
    .line 1075
    move-result-wide v2

    .line 1076
    iput-wide v2, v0, Li9/j;->L:J

    .line 1077
    .line 1078
    goto/16 :goto_1c

    .line 1079
    .line 1080
    :cond_35
    const v2, 0x656d7367

    .line 1081
    .line 1082
    .line 1083
    if-ne v8, v2, :cond_3d

    .line 1084
    .line 1085
    iget-object v2, v0, Li9/j;->H:[Lo8/i0;

    .line 1086
    .line 1087
    array-length v2, v2

    .line 1088
    if-nez v2, :cond_36

    .line 1089
    .line 1090
    goto/16 :goto_1c

    .line 1091
    .line 1092
    :cond_36
    const/16 v4, 0x8

    .line 1093
    .line 1094
    invoke-virtual {v7, v4}, Lw7/p;->I(I)V

    .line 1095
    .line 1096
    .line 1097
    invoke-virtual {v7}, Lw7/p;->j()I

    .line 1098
    .line 1099
    .line 1100
    move-result v2

    .line 1101
    invoke-static {v2}, Li9/e;->e(I)I

    .line 1102
    .line 1103
    .line 1104
    move-result v2

    .line 1105
    const-wide v4, -0x7fffffffffffffffL    # -4.9E-324

    .line 1106
    .line 1107
    .line 1108
    .line 1109
    .line 1110
    if-eqz v2, :cond_38

    .line 1111
    .line 1112
    const/4 v8, 0x1

    .line 1113
    if-eq v2, v8, :cond_37

    .line 1114
    .line 1115
    const-string v3, "Skipping unsupported emsg version: "

    .line 1116
    .line 1117
    invoke-static {v3, v2, v6}, Lvj/b;->w(Ljava/lang/String;ILjava/lang/String;)V

    .line 1118
    .line 1119
    .line 1120
    goto/16 :goto_1c

    .line 1121
    .line 1122
    :cond_37
    invoke-virtual {v7}, Lw7/p;->y()J

    .line 1123
    .line 1124
    .line 1125
    move-result-wide v12

    .line 1126
    invoke-virtual {v7}, Lw7/p;->B()J

    .line 1127
    .line 1128
    .line 1129
    move-result-wide v8

    .line 1130
    sget-object v14, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 1131
    .line 1132
    const-wide/32 v10, 0xf4240

    .line 1133
    .line 1134
    .line 1135
    invoke-static/range {v8 .. v14}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 1136
    .line 1137
    .line 1138
    move-result-wide v15

    .line 1139
    invoke-virtual {v7}, Lw7/p;->y()J

    .line 1140
    .line 1141
    .line 1142
    move-result-wide v8

    .line 1143
    const-wide/16 v10, 0x3e8

    .line 1144
    .line 1145
    invoke-static/range {v8 .. v14}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 1146
    .line 1147
    .line 1148
    move-result-wide v8

    .line 1149
    invoke-virtual {v7}, Lw7/p;->y()J

    .line 1150
    .line 1151
    .line 1152
    move-result-wide v10

    .line 1153
    invoke-virtual {v7}, Lw7/p;->r()Ljava/lang/String;

    .line 1154
    .line 1155
    .line 1156
    move-result-object v2

    .line 1157
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1158
    .line 1159
    .line 1160
    invoke-virtual {v7}, Lw7/p;->r()Ljava/lang/String;

    .line 1161
    .line 1162
    .line 1163
    move-result-object v6

    .line 1164
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1165
    .line 1166
    .line 1167
    move-wide v13, v15

    .line 1168
    move-wide v15, v4

    .line 1169
    goto :goto_19

    .line 1170
    :cond_38
    invoke-virtual {v7}, Lw7/p;->r()Ljava/lang/String;

    .line 1171
    .line 1172
    .line 1173
    move-result-object v2

    .line 1174
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1175
    .line 1176
    .line 1177
    invoke-virtual {v7}, Lw7/p;->r()Ljava/lang/String;

    .line 1178
    .line 1179
    .line 1180
    move-result-object v6

    .line 1181
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1182
    .line 1183
    .line 1184
    invoke-virtual {v7}, Lw7/p;->y()J

    .line 1185
    .line 1186
    .line 1187
    move-result-wide v12

    .line 1188
    invoke-virtual {v7}, Lw7/p;->y()J

    .line 1189
    .line 1190
    .line 1191
    move-result-wide v8

    .line 1192
    sget-object v14, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 1193
    .line 1194
    const-wide/32 v10, 0xf4240

    .line 1195
    .line 1196
    .line 1197
    invoke-static/range {v8 .. v14}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 1198
    .line 1199
    .line 1200
    move-result-wide v15

    .line 1201
    iget-wide v8, v0, Li9/j;->z:J

    .line 1202
    .line 1203
    cmp-long v10, v8, v4

    .line 1204
    .line 1205
    if-eqz v10, :cond_39

    .line 1206
    .line 1207
    add-long/2addr v8, v15

    .line 1208
    move-wide/from16 v17, v8

    .line 1209
    .line 1210
    goto :goto_18

    .line 1211
    :cond_39
    move-wide/from16 v17, v4

    .line 1212
    .line 1213
    :goto_18
    invoke-virtual {v7}, Lw7/p;->y()J

    .line 1214
    .line 1215
    .line 1216
    move-result-wide v8

    .line 1217
    const-wide/16 v10, 0x3e8

    .line 1218
    .line 1219
    invoke-static/range {v8 .. v14}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 1220
    .line 1221
    .line 1222
    move-result-wide v8

    .line 1223
    invoke-virtual {v7}, Lw7/p;->y()J

    .line 1224
    .line 1225
    .line 1226
    move-result-wide v10

    .line 1227
    move-wide v13, v15

    .line 1228
    move-wide v15, v4

    .line 1229
    move-wide v4, v13

    .line 1230
    move-wide/from16 v13, v17

    .line 1231
    .line 1232
    :goto_19
    invoke-virtual {v7}, Lw7/p;->a()I

    .line 1233
    .line 1234
    .line 1235
    move-result v12

    .line 1236
    new-array v12, v12, [B

    .line 1237
    .line 1238
    move-wide/from16 v17, v15

    .line 1239
    .line 1240
    invoke-virtual {v7}, Lw7/p;->a()I

    .line 1241
    .line 1242
    .line 1243
    move-result v15

    .line 1244
    const/4 v1, 0x0

    .line 1245
    invoke-virtual {v7, v12, v1, v15}, Lw7/p;->h([BII)V

    .line 1246
    .line 1247
    .line 1248
    new-instance v1, Lz8/a;

    .line 1249
    .line 1250
    new-instance v1, Lw7/p;

    .line 1251
    .line 1252
    iget-object v7, v0, Li9/j;->j:Ly/a;

    .line 1253
    .line 1254
    iget-object v15, v7, Ly/a;->b:Ljava/lang/Object;

    .line 1255
    .line 1256
    check-cast v15, Ljava/io/DataOutputStream;

    .line 1257
    .line 1258
    iget-object v7, v7, Ly/a;->a:Ljava/lang/Object;

    .line 1259
    .line 1260
    check-cast v7, Ljava/io/ByteArrayOutputStream;

    .line 1261
    .line 1262
    invoke-virtual {v7}, Ljava/io/ByteArrayOutputStream;->reset()V

    .line 1263
    .line 1264
    .line 1265
    :try_start_0
    invoke-virtual {v15, v2}, Ljava/io/DataOutputStream;->writeBytes(Ljava/lang/String;)V

    .line 1266
    .line 1267
    .line 1268
    const/4 v2, 0x0

    .line 1269
    invoke-virtual {v15, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 1270
    .line 1271
    .line 1272
    invoke-virtual {v15, v6}, Ljava/io/DataOutputStream;->writeBytes(Ljava/lang/String;)V

    .line 1273
    .line 1274
    .line 1275
    invoke-virtual {v15, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 1276
    .line 1277
    .line 1278
    invoke-virtual {v15, v8, v9}, Ljava/io/DataOutputStream;->writeLong(J)V

    .line 1279
    .line 1280
    .line 1281
    invoke-virtual {v15, v10, v11}, Ljava/io/DataOutputStream;->writeLong(J)V

    .line 1282
    .line 1283
    .line 1284
    invoke-virtual {v15, v12}, Ljava/io/OutputStream;->write([B)V

    .line 1285
    .line 1286
    .line 1287
    invoke-virtual {v15}, Ljava/io/DataOutputStream;->flush()V

    .line 1288
    .line 1289
    .line 1290
    invoke-virtual {v7}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 1291
    .line 1292
    .line 1293
    move-result-object v2
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 1294
    invoke-direct {v1, v2}, Lw7/p;-><init>([B)V

    .line 1295
    .line 1296
    .line 1297
    invoke-virtual {v1}, Lw7/p;->a()I

    .line 1298
    .line 1299
    .line 1300
    move-result v2

    .line 1301
    iget-object v6, v0, Li9/j;->H:[Lo8/i0;

    .line 1302
    .line 1303
    array-length v7, v6

    .line 1304
    const/4 v8, 0x0

    .line 1305
    :goto_1a
    if-ge v8, v7, :cond_3a

    .line 1306
    .line 1307
    aget-object v9, v6, v8

    .line 1308
    .line 1309
    const/4 v10, 0x0

    .line 1310
    invoke-virtual {v1, v10}, Lw7/p;->I(I)V

    .line 1311
    .line 1312
    .line 1313
    invoke-interface {v9, v1, v2, v10}, Lo8/i0;->a(Lw7/p;II)V

    .line 1314
    .line 1315
    .line 1316
    add-int/lit8 v8, v8, 0x1

    .line 1317
    .line 1318
    goto :goto_1a

    .line 1319
    :cond_3a
    cmp-long v1, v13, v17

    .line 1320
    .line 1321
    if-nez v1, :cond_3b

    .line 1322
    .line 1323
    new-instance v1, Li9/h;

    .line 1324
    .line 1325
    const/4 v6, 0x1

    .line 1326
    invoke-direct {v1, v4, v5, v2, v6}, Li9/h;-><init>(JIZ)V

    .line 1327
    .line 1328
    .line 1329
    invoke-virtual {v3, v1}, Ljava/util/ArrayDeque;->addLast(Ljava/lang/Object;)V

    .line 1330
    .line 1331
    .line 1332
    iget v1, v0, Li9/j;->w:I

    .line 1333
    .line 1334
    add-int/2addr v1, v2

    .line 1335
    iput v1, v0, Li9/j;->w:I

    .line 1336
    .line 1337
    goto :goto_1c

    .line 1338
    :cond_3b
    invoke-virtual {v3}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 1339
    .line 1340
    .line 1341
    move-result v1

    .line 1342
    if-nez v1, :cond_3c

    .line 1343
    .line 1344
    new-instance v1, Li9/h;

    .line 1345
    .line 1346
    const/4 v8, 0x0

    .line 1347
    invoke-direct {v1, v13, v14, v2, v8}, Li9/h;-><init>(JIZ)V

    .line 1348
    .line 1349
    .line 1350
    invoke-virtual {v3, v1}, Ljava/util/ArrayDeque;->addLast(Ljava/lang/Object;)V

    .line 1351
    .line 1352
    .line 1353
    iget v1, v0, Li9/j;->w:I

    .line 1354
    .line 1355
    add-int/2addr v1, v2

    .line 1356
    iput v1, v0, Li9/j;->w:I

    .line 1357
    .line 1358
    goto :goto_1c

    .line 1359
    :cond_3c
    iget-object v1, v0, Li9/j;->H:[Lo8/i0;

    .line 1360
    .line 1361
    array-length v3, v1

    .line 1362
    const/4 v4, 0x0

    .line 1363
    :goto_1b
    if-ge v4, v3, :cond_3d

    .line 1364
    .line 1365
    aget-object v12, v1, v4

    .line 1366
    .line 1367
    const/16 v17, 0x0

    .line 1368
    .line 1369
    const/16 v18, 0x0

    .line 1370
    .line 1371
    const/4 v15, 0x1

    .line 1372
    move/from16 v16, v2

    .line 1373
    .line 1374
    invoke-interface/range {v12 .. v18}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 1375
    .line 1376
    .line 1377
    add-int/lit8 v4, v4, 0x1

    .line 1378
    .line 1379
    goto :goto_1b

    .line 1380
    :catch_0
    move-exception v0

    .line 1381
    new-instance v1, Ljava/lang/RuntimeException;

    .line 1382
    .line 1383
    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 1384
    .line 1385
    .line 1386
    throw v1

    .line 1387
    :cond_3d
    :goto_1c
    move-object/from16 v1, p1

    .line 1388
    .line 1389
    goto :goto_1d

    .line 1390
    :cond_3e
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 1391
    .line 1392
    .line 1393
    :goto_1d
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1394
    .line 1395
    .line 1396
    move-result-wide v2

    .line 1397
    invoke-virtual {v0, v2, v3}, Li9/j;->k(J)V

    .line 1398
    .line 1399
    .line 1400
    goto/16 :goto_0

    .line 1401
    .line 1402
    :cond_3f
    move/from16 v19, v13

    .line 1403
    .line 1404
    iget v2, v0, Li9/j;->t:I

    .line 1405
    .line 1406
    const-wide/16 v3, 0x0

    .line 1407
    .line 1408
    const-wide/16 v11, -0x1

    .line 1409
    .line 1410
    iget-object v6, v0, Li9/j;->k:Lw7/p;

    .line 1411
    .line 1412
    if-nez v2, :cond_46

    .line 1413
    .line 1414
    iget-object v2, v6, Lw7/p;->a:[B

    .line 1415
    .line 1416
    const/16 v13, 0x8

    .line 1417
    .line 1418
    const/4 v14, 0x0

    .line 1419
    const/4 v15, 0x1

    .line 1420
    invoke-interface {v1, v2, v14, v13, v15}, Lo8/p;->f([BIIZ)Z

    .line 1421
    .line 1422
    .line 1423
    move-result v2

    .line 1424
    if-nez v2, :cond_45

    .line 1425
    .line 1426
    iget-wide v1, v0, Li9/j;->L:J

    .line 1427
    .line 1428
    cmp-long v5, v1, v11

    .line 1429
    .line 1430
    if-eqz v5, :cond_44

    .line 1431
    .line 1432
    move-object/from16 v13, p2

    .line 1433
    .line 1434
    iput-wide v1, v13, Lo8/s;->a:J

    .line 1435
    .line 1436
    iput-wide v11, v0, Li9/j;->L:J

    .line 1437
    .line 1438
    iget-object v1, v0, Li9/j;->G:Lo8/q;

    .line 1439
    .line 1440
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1441
    .line 1442
    .line 1443
    new-instance v2, Ljava/util/ArrayList;

    .line 1444
    .line 1445
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 1446
    .line 1447
    .line 1448
    new-instance v5, Ljava/util/ArrayList;

    .line 1449
    .line 1450
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 1451
    .line 1452
    .line 1453
    new-instance v6, Ljava/util/ArrayList;

    .line 1454
    .line 1455
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 1456
    .line 1457
    .line 1458
    new-instance v7, Ljava/util/ArrayList;

    .line 1459
    .line 1460
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 1461
    .line 1462
    .line 1463
    iget-object v8, v9, Lfb/k;->a:Ljava/util/LinkedHashMap;

    .line 1464
    .line 1465
    invoke-virtual {v8}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 1466
    .line 1467
    .line 1468
    move-result-object v8

    .line 1469
    invoke-interface {v8}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 1470
    .line 1471
    .line 1472
    move-result-object v8

    .line 1473
    :goto_1e
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 1474
    .line 1475
    .line 1476
    move-result v9

    .line 1477
    if-eqz v9, :cond_40

    .line 1478
    .line 1479
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1480
    .line 1481
    .line 1482
    move-result-object v9

    .line 1483
    check-cast v9, Lo8/k;

    .line 1484
    .line 1485
    iget-object v10, v9, Lo8/k;->b:[I

    .line 1486
    .line 1487
    invoke-virtual {v2, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1488
    .line 1489
    .line 1490
    iget-object v10, v9, Lo8/k;->c:[J

    .line 1491
    .line 1492
    invoke-virtual {v5, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1493
    .line 1494
    .line 1495
    iget-object v10, v9, Lo8/k;->d:[J

    .line 1496
    .line 1497
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1498
    .line 1499
    .line 1500
    iget-object v9, v9, Lo8/k;->e:[J

    .line 1501
    .line 1502
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1503
    .line 1504
    .line 1505
    goto :goto_1e

    .line 1506
    :cond_40
    new-instance v8, Lo8/k;

    .line 1507
    .line 1508
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 1509
    .line 1510
    .line 1511
    move-result v9

    .line 1512
    new-array v9, v9, [[I

    .line 1513
    .line 1514
    invoke-virtual {v2, v9}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 1515
    .line 1516
    .line 1517
    move-result-object v2

    .line 1518
    check-cast v2, [[I

    .line 1519
    .line 1520
    array-length v9, v2

    .line 1521
    const/4 v10, 0x0

    .line 1522
    :goto_1f
    if-ge v10, v9, :cond_41

    .line 1523
    .line 1524
    aget-object v11, v2, v10

    .line 1525
    .line 1526
    array-length v11, v11

    .line 1527
    int-to-long v11, v11

    .line 1528
    add-long/2addr v3, v11

    .line 1529
    add-int/lit8 v10, v10, 0x1

    .line 1530
    .line 1531
    goto :goto_1f

    .line 1532
    :cond_41
    long-to-int v9, v3

    .line 1533
    int-to-long v10, v9

    .line 1534
    cmp-long v10, v3, v10

    .line 1535
    .line 1536
    if-nez v10, :cond_42

    .line 1537
    .line 1538
    const/4 v10, 0x1

    .line 1539
    goto :goto_20

    .line 1540
    :cond_42
    const/4 v10, 0x0

    .line 1541
    :goto_20
    const-string v11, "the total number of elements (%s) in the arrays must fit in an int"

    .line 1542
    .line 1543
    invoke-static {v3, v4, v11, v10}, Lkp/i9;->b(JLjava/lang/String;Z)V

    .line 1544
    .line 1545
    .line 1546
    new-array v3, v9, [I

    .line 1547
    .line 1548
    array-length v4, v2

    .line 1549
    const/4 v9, 0x0

    .line 1550
    const/4 v10, 0x0

    .line 1551
    :goto_21
    if-ge v9, v4, :cond_43

    .line 1552
    .line 1553
    aget-object v11, v2, v9

    .line 1554
    .line 1555
    array-length v12, v11

    .line 1556
    const/4 v13, 0x0

    .line 1557
    invoke-static {v11, v13, v3, v10, v12}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 1558
    .line 1559
    .line 1560
    array-length v11, v11

    .line 1561
    add-int/2addr v10, v11

    .line 1562
    add-int/lit8 v9, v9, 0x1

    .line 1563
    .line 1564
    goto :goto_21

    .line 1565
    :cond_43
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 1566
    .line 1567
    .line 1568
    move-result v2

    .line 1569
    new-array v2, v2, [[J

    .line 1570
    .line 1571
    invoke-virtual {v5, v2}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 1572
    .line 1573
    .line 1574
    move-result-object v2

    .line 1575
    check-cast v2, [[J

    .line 1576
    .line 1577
    invoke-static {v2}, Llp/ee;->a([[J)[J

    .line 1578
    .line 1579
    .line 1580
    move-result-object v2

    .line 1581
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 1582
    .line 1583
    .line 1584
    move-result v4

    .line 1585
    new-array v4, v4, [[J

    .line 1586
    .line 1587
    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 1588
    .line 1589
    .line 1590
    move-result-object v4

    .line 1591
    check-cast v4, [[J

    .line 1592
    .line 1593
    invoke-static {v4}, Llp/ee;->a([[J)[J

    .line 1594
    .line 1595
    .line 1596
    move-result-object v4

    .line 1597
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 1598
    .line 1599
    .line 1600
    move-result v5

    .line 1601
    new-array v5, v5, [[J

    .line 1602
    .line 1603
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 1604
    .line 1605
    .line 1606
    move-result-object v5

    .line 1607
    check-cast v5, [[J

    .line 1608
    .line 1609
    invoke-static {v5}, Llp/ee;->a([[J)[J

    .line 1610
    .line 1611
    .line 1612
    move-result-object v5

    .line 1613
    invoke-direct {v8, v3, v2, v4, v5}, Lo8/k;-><init>([I[J[J[J)V

    .line 1614
    .line 1615
    .line 1616
    invoke-interface {v1, v8}, Lo8/q;->c(Lo8/c0;)V

    .line 1617
    .line 1618
    .line 1619
    const/4 v2, 0x1

    .line 1620
    iput-boolean v2, v0, Li9/j;->K:Z

    .line 1621
    .line 1622
    return v2

    .line 1623
    :cond_44
    const/4 v14, 0x0

    .line 1624
    invoke-virtual {v7, v14}, Lca/j;->d(I)V

    .line 1625
    .line 1626
    .line 1627
    const/16 v18, -0x1

    .line 1628
    .line 1629
    return v18

    .line 1630
    :cond_45
    move-object/from16 v13, p2

    .line 1631
    .line 1632
    const/16 v2, 0x8

    .line 1633
    .line 1634
    const/4 v14, 0x0

    .line 1635
    iput v2, v0, Li9/j;->t:I

    .line 1636
    .line 1637
    invoke-virtual {v6, v14}, Lw7/p;->I(I)V

    .line 1638
    .line 1639
    .line 1640
    invoke-virtual {v6}, Lw7/p;->y()J

    .line 1641
    .line 1642
    .line 1643
    move-result-wide v14

    .line 1644
    iput-wide v14, v0, Li9/j;->s:J

    .line 1645
    .line 1646
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 1647
    .line 1648
    .line 1649
    move-result v2

    .line 1650
    iput v2, v0, Li9/j;->r:I

    .line 1651
    .line 1652
    goto :goto_22

    .line 1653
    :cond_46
    move-object/from16 v13, p2

    .line 1654
    .line 1655
    :goto_22
    iget-wide v14, v0, Li9/j;->s:J

    .line 1656
    .line 1657
    const-wide/16 v23, 0x1

    .line 1658
    .line 1659
    cmp-long v2, v14, v23

    .line 1660
    .line 1661
    if-nez v2, :cond_47

    .line 1662
    .line 1663
    iget-object v2, v6, Lw7/p;->a:[B

    .line 1664
    .line 1665
    const/16 v4, 0x8

    .line 1666
    .line 1667
    invoke-interface {v1, v2, v4, v4}, Lo8/p;->readFully([BII)V

    .line 1668
    .line 1669
    .line 1670
    iget v2, v0, Li9/j;->t:I

    .line 1671
    .line 1672
    add-int/2addr v2, v4

    .line 1673
    iput v2, v0, Li9/j;->t:I

    .line 1674
    .line 1675
    invoke-virtual {v6}, Lw7/p;->B()J

    .line 1676
    .line 1677
    .line 1678
    move-result-wide v2

    .line 1679
    iput-wide v2, v0, Li9/j;->s:J

    .line 1680
    .line 1681
    goto :goto_23

    .line 1682
    :cond_47
    cmp-long v2, v14, v3

    .line 1683
    .line 1684
    if-nez v2, :cond_49

    .line 1685
    .line 1686
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 1687
    .line 1688
    .line 1689
    move-result-wide v2

    .line 1690
    cmp-long v4, v2, v11

    .line 1691
    .line 1692
    if-nez v4, :cond_48

    .line 1693
    .line 1694
    invoke-virtual {v5}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 1695
    .line 1696
    .line 1697
    move-result v4

    .line 1698
    if-nez v4, :cond_48

    .line 1699
    .line 1700
    invoke-virtual {v5}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 1701
    .line 1702
    .line 1703
    move-result-object v2

    .line 1704
    check-cast v2, Lx7/c;

    .line 1705
    .line 1706
    iget-wide v2, v2, Lx7/c;->f:J

    .line 1707
    .line 1708
    :cond_48
    cmp-long v4, v2, v11

    .line 1709
    .line 1710
    if-eqz v4, :cond_49

    .line 1711
    .line 1712
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1713
    .line 1714
    .line 1715
    move-result-wide v14

    .line 1716
    sub-long/2addr v2, v14

    .line 1717
    iget v4, v0, Li9/j;->t:I

    .line 1718
    .line 1719
    int-to-long v14, v4

    .line 1720
    add-long/2addr v2, v14

    .line 1721
    iput-wide v2, v0, Li9/j;->s:J

    .line 1722
    .line 1723
    :cond_49
    :goto_23
    iget-wide v2, v0, Li9/j;->s:J

    .line 1724
    .line 1725
    iget v4, v0, Li9/j;->t:I

    .line 1726
    .line 1727
    int-to-long v14, v4

    .line 1728
    cmp-long v4, v2, v14

    .line 1729
    .line 1730
    if-ltz v4, :cond_59

    .line 1731
    .line 1732
    move-wide/from16 v23, v11

    .line 1733
    .line 1734
    iget-wide v11, v0, Li9/j;->L:J

    .line 1735
    .line 1736
    cmp-long v4, v11, v23

    .line 1737
    .line 1738
    if-eqz v4, :cond_4b

    .line 1739
    .line 1740
    iget v4, v0, Li9/j;->r:I

    .line 1741
    .line 1742
    const v5, 0x73696478

    .line 1743
    .line 1744
    .line 1745
    if-ne v4, v5, :cond_4a

    .line 1746
    .line 1747
    long-to-int v2, v2

    .line 1748
    invoke-virtual {v8, v2}, Lw7/p;->F(I)V

    .line 1749
    .line 1750
    .line 1751
    iget-object v2, v6, Lw7/p;->a:[B

    .line 1752
    .line 1753
    iget-object v3, v8, Lw7/p;->a:[B

    .line 1754
    .line 1755
    const/16 v4, 0x8

    .line 1756
    .line 1757
    const/4 v14, 0x0

    .line 1758
    invoke-static {v2, v14, v3, v14, v4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 1759
    .line 1760
    .line 1761
    iget-object v2, v8, Lw7/p;->a:[B

    .line 1762
    .line 1763
    iget-wide v5, v0, Li9/j;->s:J

    .line 1764
    .line 1765
    iget v3, v0, Li9/j;->t:I

    .line 1766
    .line 1767
    int-to-long v10, v3

    .line 1768
    sub-long/2addr v5, v10

    .line 1769
    long-to-int v3, v5

    .line 1770
    invoke-interface {v1, v2, v4, v3}, Lo8/p;->readFully([BII)V

    .line 1771
    .line 1772
    .line 1773
    invoke-interface {v1}, Lo8/p;->h()J

    .line 1774
    .line 1775
    .line 1776
    move-result-wide v2

    .line 1777
    invoke-static {v2, v3, v8}, Li9/j;->i(JLw7/p;)Landroid/util/Pair;

    .line 1778
    .line 1779
    .line 1780
    move-result-object v2

    .line 1781
    iget-object v2, v2, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 1782
    .line 1783
    check-cast v2, Lo8/k;

    .line 1784
    .line 1785
    invoke-virtual {v9, v2}, Lfb/k;->a(Lo8/k;)V

    .line 1786
    .line 1787
    .line 1788
    goto :goto_24

    .line 1789
    :cond_4a
    sub-long/2addr v2, v14

    .line 1790
    long-to-int v2, v2

    .line 1791
    const/4 v6, 0x1

    .line 1792
    invoke-interface {v1, v2, v6}, Lo8/p;->a(IZ)Z

    .line 1793
    .line 1794
    .line 1795
    :goto_24
    invoke-virtual {v0}, Li9/j;->e()V

    .line 1796
    .line 1797
    .line 1798
    goto/16 :goto_0

    .line 1799
    .line 1800
    :cond_4b
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 1801
    .line 1802
    .line 1803
    move-result-wide v2

    .line 1804
    iget v4, v0, Li9/j;->t:I

    .line 1805
    .line 1806
    int-to-long v11, v4

    .line 1807
    sub-long/2addr v2, v11

    .line 1808
    iget v4, v0, Li9/j;->r:I

    .line 1809
    .line 1810
    const v7, 0x6d646174

    .line 1811
    .line 1812
    .line 1813
    const v9, 0x6d6f6f66

    .line 1814
    .line 1815
    .line 1816
    if-eq v4, v9, :cond_4c

    .line 1817
    .line 1818
    if-ne v4, v7, :cond_4d

    .line 1819
    .line 1820
    :cond_4c
    iget-boolean v4, v0, Li9/j;->J:Z

    .line 1821
    .line 1822
    if-nez v4, :cond_4d

    .line 1823
    .line 1824
    iget-object v4, v0, Li9/j;->G:Lo8/q;

    .line 1825
    .line 1826
    new-instance v11, Lo8/t;

    .line 1827
    .line 1828
    iget-wide v14, v0, Li9/j;->y:J

    .line 1829
    .line 1830
    invoke-direct {v11, v14, v15, v2, v3}, Lo8/t;-><init>(JJ)V

    .line 1831
    .line 1832
    .line 1833
    invoke-interface {v4, v11}, Lo8/q;->c(Lo8/c0;)V

    .line 1834
    .line 1835
    .line 1836
    const/4 v15, 0x1

    .line 1837
    iput-boolean v15, v0, Li9/j;->J:Z

    .line 1838
    .line 1839
    :cond_4d
    iget v4, v0, Li9/j;->r:I

    .line 1840
    .line 1841
    if-ne v4, v9, :cond_4e

    .line 1842
    .line 1843
    invoke-virtual {v10}, Landroid/util/SparseArray;->size()I

    .line 1844
    .line 1845
    .line 1846
    move-result v4

    .line 1847
    const/4 v11, 0x0

    .line 1848
    :goto_25
    if-ge v11, v4, :cond_4e

    .line 1849
    .line 1850
    invoke-virtual {v10, v11}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 1851
    .line 1852
    .line 1853
    move-result-object v12

    .line 1854
    check-cast v12, Li9/i;

    .line 1855
    .line 1856
    iget-object v12, v12, Li9/i;->b:Li9/s;

    .line 1857
    .line 1858
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1859
    .line 1860
    .line 1861
    iput-wide v2, v12, Li9/s;->c:J

    .line 1862
    .line 1863
    iput-wide v2, v12, Li9/s;->b:J

    .line 1864
    .line 1865
    add-int/lit8 v11, v11, 0x1

    .line 1866
    .line 1867
    goto :goto_25

    .line 1868
    :cond_4e
    iget v4, v0, Li9/j;->r:I

    .line 1869
    .line 1870
    if-ne v4, v7, :cond_4f

    .line 1871
    .line 1872
    const/4 v7, 0x0

    .line 1873
    iput-object v7, v0, Li9/j;->A:Li9/i;

    .line 1874
    .line 1875
    iget-wide v4, v0, Li9/j;->s:J

    .line 1876
    .line 1877
    add-long/2addr v2, v4

    .line 1878
    iput-wide v2, v0, Li9/j;->v:J

    .line 1879
    .line 1880
    move/from16 v2, v19

    .line 1881
    .line 1882
    iput v2, v0, Li9/j;->q:I

    .line 1883
    .line 1884
    goto/16 :goto_0

    .line 1885
    .line 1886
    :cond_4f
    const v2, 0x6d6f6f76

    .line 1887
    .line 1888
    .line 1889
    const v3, 0x6d657461

    .line 1890
    .line 1891
    .line 1892
    if-eq v4, v2, :cond_56

    .line 1893
    .line 1894
    const v2, 0x7472616b

    .line 1895
    .line 1896
    .line 1897
    if-eq v4, v2, :cond_56

    .line 1898
    .line 1899
    const v2, 0x6d646961

    .line 1900
    .line 1901
    .line 1902
    if-eq v4, v2, :cond_56

    .line 1903
    .line 1904
    const v2, 0x6d696e66

    .line 1905
    .line 1906
    .line 1907
    if-eq v4, v2, :cond_56

    .line 1908
    .line 1909
    const v2, 0x7374626c

    .line 1910
    .line 1911
    .line 1912
    if-eq v4, v2, :cond_56

    .line 1913
    .line 1914
    if-eq v4, v9, :cond_56

    .line 1915
    .line 1916
    const v2, 0x74726166

    .line 1917
    .line 1918
    .line 1919
    if-eq v4, v2, :cond_56

    .line 1920
    .line 1921
    const v2, 0x6d766578

    .line 1922
    .line 1923
    .line 1924
    if-eq v4, v2, :cond_56

    .line 1925
    .line 1926
    const v2, 0x65647473

    .line 1927
    .line 1928
    .line 1929
    if-eq v4, v2, :cond_56

    .line 1930
    .line 1931
    if-ne v4, v3, :cond_50

    .line 1932
    .line 1933
    goto/16 :goto_27

    .line 1934
    .line 1935
    :cond_50
    const v2, 0x68646c72    # 4.3148E24f

    .line 1936
    .line 1937
    .line 1938
    const-wide/32 v7, 0x7fffffff

    .line 1939
    .line 1940
    .line 1941
    if-eq v4, v2, :cond_53

    .line 1942
    .line 1943
    const v2, 0x6d646864

    .line 1944
    .line 1945
    .line 1946
    if-eq v4, v2, :cond_53

    .line 1947
    .line 1948
    const v2, 0x6d766864

    .line 1949
    .line 1950
    .line 1951
    if-eq v4, v2, :cond_53

    .line 1952
    .line 1953
    const v2, 0x73696478

    .line 1954
    .line 1955
    .line 1956
    if-eq v4, v2, :cond_53

    .line 1957
    .line 1958
    const v2, 0x73747364

    .line 1959
    .line 1960
    .line 1961
    if-eq v4, v2, :cond_53

    .line 1962
    .line 1963
    const v2, 0x73747473

    .line 1964
    .line 1965
    .line 1966
    if-eq v4, v2, :cond_53

    .line 1967
    .line 1968
    const v2, 0x63747473

    .line 1969
    .line 1970
    .line 1971
    if-eq v4, v2, :cond_53

    .line 1972
    .line 1973
    const v2, 0x73747363

    .line 1974
    .line 1975
    .line 1976
    if-eq v4, v2, :cond_53

    .line 1977
    .line 1978
    const v2, 0x7374737a

    .line 1979
    .line 1980
    .line 1981
    if-eq v4, v2, :cond_53

    .line 1982
    .line 1983
    const v2, 0x73747a32

    .line 1984
    .line 1985
    .line 1986
    if-eq v4, v2, :cond_53

    .line 1987
    .line 1988
    const v2, 0x7374636f

    .line 1989
    .line 1990
    .line 1991
    if-eq v4, v2, :cond_53

    .line 1992
    .line 1993
    const v2, 0x636f3634

    .line 1994
    .line 1995
    .line 1996
    if-eq v4, v2, :cond_53

    .line 1997
    .line 1998
    const v2, 0x73747373

    .line 1999
    .line 2000
    .line 2001
    if-eq v4, v2, :cond_53

    .line 2002
    .line 2003
    const v2, 0x74666474

    .line 2004
    .line 2005
    .line 2006
    if-eq v4, v2, :cond_53

    .line 2007
    .line 2008
    const v2, 0x74666864

    .line 2009
    .line 2010
    .line 2011
    if-eq v4, v2, :cond_53

    .line 2012
    .line 2013
    const v2, 0x746b6864

    .line 2014
    .line 2015
    .line 2016
    if-eq v4, v2, :cond_53

    .line 2017
    .line 2018
    const v2, 0x74726578

    .line 2019
    .line 2020
    .line 2021
    if-eq v4, v2, :cond_53

    .line 2022
    .line 2023
    const v2, 0x7472756e

    .line 2024
    .line 2025
    .line 2026
    if-eq v4, v2, :cond_53

    .line 2027
    .line 2028
    const v2, 0x70737368    # 3.013775E29f

    .line 2029
    .line 2030
    .line 2031
    if-eq v4, v2, :cond_53

    .line 2032
    .line 2033
    const v2, 0x7361697a

    .line 2034
    .line 2035
    .line 2036
    if-eq v4, v2, :cond_53

    .line 2037
    .line 2038
    const v2, 0x7361696f

    .line 2039
    .line 2040
    .line 2041
    if-eq v4, v2, :cond_53

    .line 2042
    .line 2043
    const v2, 0x73656e63

    .line 2044
    .line 2045
    .line 2046
    if-eq v4, v2, :cond_53

    .line 2047
    .line 2048
    const v2, 0x75756964

    .line 2049
    .line 2050
    .line 2051
    if-eq v4, v2, :cond_53

    .line 2052
    .line 2053
    const v2, 0x73626770

    .line 2054
    .line 2055
    .line 2056
    if-eq v4, v2, :cond_53

    .line 2057
    .line 2058
    const v2, 0x73677064

    .line 2059
    .line 2060
    .line 2061
    if-eq v4, v2, :cond_53

    .line 2062
    .line 2063
    const v2, 0x656c7374

    .line 2064
    .line 2065
    .line 2066
    if-eq v4, v2, :cond_53

    .line 2067
    .line 2068
    const v2, 0x6d656864

    .line 2069
    .line 2070
    .line 2071
    if-eq v4, v2, :cond_53

    .line 2072
    .line 2073
    const v2, 0x656d7367

    .line 2074
    .line 2075
    .line 2076
    if-eq v4, v2, :cond_53

    .line 2077
    .line 2078
    const v2, 0x75647461

    .line 2079
    .line 2080
    .line 2081
    if-eq v4, v2, :cond_53

    .line 2082
    .line 2083
    const v2, 0x6b657973

    .line 2084
    .line 2085
    .line 2086
    if-eq v4, v2, :cond_53

    .line 2087
    .line 2088
    const v2, 0x696c7374

    .line 2089
    .line 2090
    .line 2091
    if-ne v4, v2, :cond_51

    .line 2092
    .line 2093
    goto :goto_26

    .line 2094
    :cond_51
    iget-wide v2, v0, Li9/j;->s:J

    .line 2095
    .line 2096
    cmp-long v2, v2, v7

    .line 2097
    .line 2098
    if-gtz v2, :cond_52

    .line 2099
    .line 2100
    const/4 v7, 0x0

    .line 2101
    iput-object v7, v0, Li9/j;->u:Lw7/p;

    .line 2102
    .line 2103
    const/4 v2, 0x1

    .line 2104
    iput v2, v0, Li9/j;->q:I

    .line 2105
    .line 2106
    goto/16 :goto_0

    .line 2107
    .line 2108
    :cond_52
    const-string v0, "Skipping atom with length > 2147483647 (unsupported)."

    .line 2109
    .line 2110
    invoke-static {v0}, Lt7/e0;->b(Ljava/lang/String;)Lt7/e0;

    .line 2111
    .line 2112
    .line 2113
    move-result-object v0

    .line 2114
    throw v0

    .line 2115
    :cond_53
    :goto_26
    iget v2, v0, Li9/j;->t:I

    .line 2116
    .line 2117
    const/16 v4, 0x8

    .line 2118
    .line 2119
    if-ne v2, v4, :cond_55

    .line 2120
    .line 2121
    iget-wide v2, v0, Li9/j;->s:J

    .line 2122
    .line 2123
    cmp-long v2, v2, v7

    .line 2124
    .line 2125
    if-gtz v2, :cond_54

    .line 2126
    .line 2127
    new-instance v2, Lw7/p;

    .line 2128
    .line 2129
    iget-wide v7, v0, Li9/j;->s:J

    .line 2130
    .line 2131
    long-to-int v3, v7

    .line 2132
    invoke-direct {v2, v3}, Lw7/p;-><init>(I)V

    .line 2133
    .line 2134
    .line 2135
    iget-object v3, v6, Lw7/p;->a:[B

    .line 2136
    .line 2137
    iget-object v5, v2, Lw7/p;->a:[B

    .line 2138
    .line 2139
    const/4 v14, 0x0

    .line 2140
    invoke-static {v3, v14, v5, v14, v4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 2141
    .line 2142
    .line 2143
    iput-object v2, v0, Li9/j;->u:Lw7/p;

    .line 2144
    .line 2145
    const/4 v2, 0x1

    .line 2146
    iput v2, v0, Li9/j;->q:I

    .line 2147
    .line 2148
    goto/16 :goto_0

    .line 2149
    .line 2150
    :cond_54
    const-string v0, "Leaf atom with length > 2147483647 (unsupported)."

    .line 2151
    .line 2152
    invoke-static {v0}, Lt7/e0;->b(Ljava/lang/String;)Lt7/e0;

    .line 2153
    .line 2154
    .line 2155
    move-result-object v0

    .line 2156
    throw v0

    .line 2157
    :cond_55
    const-string v0, "Leaf atom defines extended atom size (unsupported)."

    .line 2158
    .line 2159
    invoke-static {v0}, Lt7/e0;->b(Ljava/lang/String;)Lt7/e0;

    .line 2160
    .line 2161
    .line 2162
    move-result-object v0

    .line 2163
    throw v0

    .line 2164
    :cond_56
    :goto_27
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 2165
    .line 2166
    .line 2167
    move-result-wide v6

    .line 2168
    iget-wide v9, v0, Li9/j;->s:J

    .line 2169
    .line 2170
    add-long/2addr v6, v9

    .line 2171
    const-wide/16 v11, 0x8

    .line 2172
    .line 2173
    sub-long/2addr v6, v11

    .line 2174
    iget v2, v0, Li9/j;->t:I

    .line 2175
    .line 2176
    int-to-long v11, v2

    .line 2177
    cmp-long v2, v9, v11

    .line 2178
    .line 2179
    if-eqz v2, :cond_57

    .line 2180
    .line 2181
    iget v2, v0, Li9/j;->r:I

    .line 2182
    .line 2183
    if-ne v2, v3, :cond_57

    .line 2184
    .line 2185
    const/16 v4, 0x8

    .line 2186
    .line 2187
    invoke-virtual {v8, v4}, Lw7/p;->F(I)V

    .line 2188
    .line 2189
    .line 2190
    iget-object v2, v8, Lw7/p;->a:[B

    .line 2191
    .line 2192
    const/4 v14, 0x0

    .line 2193
    invoke-interface {v1, v2, v14, v4}, Lo8/p;->o([BII)V

    .line 2194
    .line 2195
    .line 2196
    invoke-static {v8}, Li9/e;->a(Lw7/p;)V

    .line 2197
    .line 2198
    .line 2199
    iget v2, v8, Lw7/p;->b:I

    .line 2200
    .line 2201
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 2202
    .line 2203
    .line 2204
    invoke-interface {v1}, Lo8/p;->e()V

    .line 2205
    .line 2206
    .line 2207
    :cond_57
    new-instance v2, Lx7/c;

    .line 2208
    .line 2209
    iget v3, v0, Li9/j;->r:I

    .line 2210
    .line 2211
    invoke-direct {v2, v3, v6, v7}, Lx7/c;-><init>(IJ)V

    .line 2212
    .line 2213
    .line 2214
    invoke-virtual {v5, v2}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 2215
    .line 2216
    .line 2217
    iget-wide v2, v0, Li9/j;->s:J

    .line 2218
    .line 2219
    iget v4, v0, Li9/j;->t:I

    .line 2220
    .line 2221
    int-to-long v4, v4

    .line 2222
    cmp-long v2, v2, v4

    .line 2223
    .line 2224
    if-nez v2, :cond_58

    .line 2225
    .line 2226
    invoke-virtual {v0, v6, v7}, Li9/j;->k(J)V

    .line 2227
    .line 2228
    .line 2229
    goto/16 :goto_0

    .line 2230
    .line 2231
    :cond_58
    invoke-virtual {v0}, Li9/j;->e()V

    .line 2232
    .line 2233
    .line 2234
    goto/16 :goto_0

    .line 2235
    .line 2236
    :cond_59
    const-string v0, "Atom size less than header length (unsupported)."

    .line 2237
    .line 2238
    invoke-static {v0}, Lt7/e0;->b(Ljava/lang/String;)Lt7/e0;

    .line 2239
    .line 2240
    .line 2241
    move-result-object v0

    .line 2242
    throw v0
.end method

.method public final j()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Li9/j;->p:Lhr/x0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final k(J)V
    .locals 53

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    :cond_0
    :goto_0
    iget-object v1, v0, Li9/j;->l:Ljava/util/ArrayDeque;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    if-nez v2, :cond_5b

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    check-cast v2, Lx7/c;

    .line 16
    .line 17
    iget-wide v2, v2, Lx7/c;->f:J

    .line 18
    .line 19
    cmp-long v2, v2, p1

    .line 20
    .line 21
    if-nez v2, :cond_5b

    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->pop()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    move-object v3, v2

    .line 28
    check-cast v3, Lx7/c;

    .line 29
    .line 30
    iget v2, v3, Lkq/d;->e:I

    .line 31
    .line 32
    iget-object v4, v3, Lx7/c;->h:Ljava/util/ArrayList;

    .line 33
    .line 34
    iget-object v5, v3, Lx7/c;->g:Ljava/util/ArrayList;

    .line 35
    .line 36
    const v6, 0x6d6f6f76

    .line 37
    .line 38
    .line 39
    const/4 v7, 0x0

    .line 40
    iget v8, v0, Li9/j;->b:I

    .line 41
    .line 42
    const/16 v10, 0xc

    .line 43
    .line 44
    iget-object v15, v0, Li9/j;->d:Landroid/util/SparseArray;

    .line 45
    .line 46
    if-ne v2, v6, :cond_f

    .line 47
    .line 48
    move-object v6, v7

    .line 49
    invoke-static {v5}, Li9/j;->f(Ljava/util/List;)Lt7/k;

    .line 50
    .line 51
    .line 52
    move-result-object v7

    .line 53
    const v1, 0x6d766578

    .line 54
    .line 55
    .line 56
    invoke-virtual {v3, v1}, Lx7/c;->m(I)Lx7/c;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    new-instance v2, Landroid/util/SparseArray;

    .line 64
    .line 65
    invoke-direct {v2}, Landroid/util/SparseArray;-><init>()V

    .line 66
    .line 67
    .line 68
    iget-object v1, v1, Lx7/c;->g:Ljava/util/ArrayList;

    .line 69
    .line 70
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 71
    .line 72
    .line 73
    move-result v4

    .line 74
    const/4 v5, 0x0

    .line 75
    const-wide v13, -0x7fffffffffffffffL    # -4.9E-324

    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    :goto_1
    if-ge v5, v4, :cond_4

    .line 81
    .line 82
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v16

    .line 86
    move-object/from16 v6, v16

    .line 87
    .line 88
    check-cast v6, Lx7/d;

    .line 89
    .line 90
    const/16 v16, 0x0

    .line 91
    .line 92
    iget v11, v6, Lkq/d;->e:I

    .line 93
    .line 94
    iget-object v6, v6, Lx7/d;->f:Lw7/p;

    .line 95
    .line 96
    const/16 v18, 0x1

    .line 97
    .line 98
    const v12, 0x74726578

    .line 99
    .line 100
    .line 101
    if-ne v11, v12, :cond_1

    .line 102
    .line 103
    invoke-virtual {v6, v10}, Lw7/p;->I(I)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 107
    .line 108
    .line 109
    move-result v11

    .line 110
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 111
    .line 112
    .line 113
    move-result v12

    .line 114
    add-int/lit8 v12, v12, -0x1

    .line 115
    .line 116
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 117
    .line 118
    .line 119
    move-result v10

    .line 120
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 121
    .line 122
    .line 123
    move-result v9

    .line 124
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 125
    .line 126
    .line 127
    move-result v6

    .line 128
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object v11

    .line 132
    move-object/from16 v21, v1

    .line 133
    .line 134
    new-instance v1, Li9/f;

    .line 135
    .line 136
    invoke-direct {v1, v12, v10, v9, v6}, Li9/f;-><init>(IIII)V

    .line 137
    .line 138
    .line 139
    invoke-static {v11, v1}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 140
    .line 141
    .line 142
    move-result-object v1

    .line 143
    iget-object v6, v1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v6, Ljava/lang/Integer;

    .line 146
    .line 147
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 148
    .line 149
    .line 150
    move-result v6

    .line 151
    iget-object v1, v1, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v1, Li9/f;

    .line 154
    .line 155
    invoke-virtual {v2, v6, v1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    goto :goto_3

    .line 159
    :cond_1
    move-object/from16 v21, v1

    .line 160
    .line 161
    const v1, 0x6d656864

    .line 162
    .line 163
    .line 164
    if-ne v11, v1, :cond_3

    .line 165
    .line 166
    const/16 v1, 0x8

    .line 167
    .line 168
    invoke-virtual {v6, v1}, Lw7/p;->I(I)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    invoke-static {v1}, Li9/e;->e(I)I

    .line 176
    .line 177
    .line 178
    move-result v1

    .line 179
    if-nez v1, :cond_2

    .line 180
    .line 181
    invoke-virtual {v6}, Lw7/p;->y()J

    .line 182
    .line 183
    .line 184
    move-result-wide v9

    .line 185
    goto :goto_2

    .line 186
    :cond_2
    invoke-virtual {v6}, Lw7/p;->B()J

    .line 187
    .line 188
    .line 189
    move-result-wide v9

    .line 190
    :goto_2
    move-wide v13, v9

    .line 191
    :cond_3
    :goto_3
    add-int/lit8 v5, v5, 0x1

    .line 192
    .line 193
    move-object/from16 v1, v21

    .line 194
    .line 195
    const/4 v6, 0x0

    .line 196
    const/16 v10, 0xc

    .line 197
    .line 198
    goto :goto_1

    .line 199
    :cond_4
    const/16 v16, 0x0

    .line 200
    .line 201
    const/16 v18, 0x1

    .line 202
    .line 203
    const v1, 0x6d657461

    .line 204
    .line 205
    .line 206
    invoke-virtual {v3, v1}, Lx7/c;->m(I)Lx7/c;

    .line 207
    .line 208
    .line 209
    move-result-object v1

    .line 210
    if-eqz v1, :cond_5

    .line 211
    .line 212
    invoke-static {v1}, Li9/e;->f(Lx7/c;)Lt7/c0;

    .line 213
    .line 214
    .line 215
    move-result-object v1

    .line 216
    goto :goto_4

    .line 217
    :cond_5
    const/4 v1, 0x0

    .line 218
    :goto_4
    new-instance v4, Lo8/w;

    .line 219
    .line 220
    invoke-direct {v4}, Lo8/w;-><init>()V

    .line 221
    .line 222
    .line 223
    const v5, 0x75647461

    .line 224
    .line 225
    .line 226
    invoke-virtual {v3, v5}, Lx7/c;->n(I)Lx7/d;

    .line 227
    .line 228
    .line 229
    move-result-object v5

    .line 230
    if-eqz v5, :cond_6

    .line 231
    .line 232
    invoke-static {v5}, Li9/e;->k(Lx7/d;)Lt7/c0;

    .line 233
    .line 234
    .line 235
    move-result-object v5

    .line 236
    invoke-virtual {v4, v5}, Lo8/w;->b(Lt7/c0;)V

    .line 237
    .line 238
    .line 239
    move-object v11, v5

    .line 240
    goto :goto_5

    .line 241
    :cond_6
    const/4 v11, 0x0

    .line 242
    :goto_5
    new-instance v12, Lt7/c0;

    .line 243
    .line 244
    const v5, 0x6d766864

    .line 245
    .line 246
    .line 247
    invoke-virtual {v3, v5}, Lx7/c;->n(I)Lx7/d;

    .line 248
    .line 249
    .line 250
    move-result-object v5

    .line 251
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 252
    .line 253
    .line 254
    iget-object v5, v5, Lx7/d;->f:Lw7/p;

    .line 255
    .line 256
    invoke-static {v5}, Li9/e;->g(Lw7/p;)Lx7/f;

    .line 257
    .line 258
    .line 259
    move-result-object v5

    .line 260
    move/from16 v6, v18

    .line 261
    .line 262
    new-array v9, v6, [Lt7/b0;

    .line 263
    .line 264
    aput-object v5, v9, v16

    .line 265
    .line 266
    invoke-direct {v12, v9}, Lt7/c0;-><init>([Lt7/b0;)V

    .line 267
    .line 268
    .line 269
    and-int/lit8 v5, v8, 0x10

    .line 270
    .line 271
    if-eqz v5, :cond_7

    .line 272
    .line 273
    const/4 v8, 0x1

    .line 274
    goto :goto_6

    .line 275
    :cond_7
    move/from16 v8, v16

    .line 276
    .line 277
    :goto_6
    new-instance v10, Li9/g;

    .line 278
    .line 279
    invoke-direct {v10, v0}, Li9/g;-><init>(Li9/j;)V

    .line 280
    .line 281
    .line 282
    const/4 v9, 0x0

    .line 283
    move-wide v5, v13

    .line 284
    invoke-static/range {v3 .. v10}, Li9/e;->j(Lx7/c;Lo8/w;JLt7/k;ZZLgr/e;)Ljava/util/ArrayList;

    .line 285
    .line 286
    .line 287
    move-result-object v3

    .line 288
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 289
    .line 290
    .line 291
    move-result v5

    .line 292
    invoke-virtual {v15}, Landroid/util/SparseArray;->size()I

    .line 293
    .line 294
    .line 295
    move-result v6

    .line 296
    if-nez v6, :cond_c

    .line 297
    .line 298
    invoke-static {v3}, Li9/p;->b(Ljava/util/ArrayList;)Ljava/lang/String;

    .line 299
    .line 300
    .line 301
    move-result-object v6

    .line 302
    move/from16 v7, v16

    .line 303
    .line 304
    :goto_7
    if-ge v7, v5, :cond_b

    .line 305
    .line 306
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    move-result-object v8

    .line 310
    check-cast v8, Li9/t;

    .line 311
    .line 312
    iget-object v9, v8, Li9/t;->a:Li9/q;

    .line 313
    .line 314
    iget-object v10, v0, Li9/j;->G:Lo8/q;

    .line 315
    .line 316
    iget v13, v9, Li9/q;->b:I

    .line 317
    .line 318
    iget v14, v9, Li9/q;->a:I

    .line 319
    .line 320
    move-object/from16 v17, v6

    .line 321
    .line 322
    iget-object v6, v9, Li9/q;->g:Lt7/o;

    .line 323
    .line 324
    invoke-interface {v10, v7, v13}, Lo8/q;->q(II)Lo8/i0;

    .line 325
    .line 326
    .line 327
    move-result-object v10

    .line 328
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 329
    .line 330
    .line 331
    move/from16 v19, v7

    .line 332
    .line 333
    invoke-virtual {v6}, Lt7/o;->a()Lt7/n;

    .line 334
    .line 335
    .line 336
    move-result-object v7

    .line 337
    move-object/from16 v20, v3

    .line 338
    .line 339
    invoke-static/range {v17 .. v17}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object v3

    .line 343
    iput-object v3, v7, Lt7/n;->l:Ljava/lang/String;

    .line 344
    .line 345
    const/4 v3, 0x1

    .line 346
    if-ne v13, v3, :cond_8

    .line 347
    .line 348
    iget v3, v4, Lo8/w;->a:I

    .line 349
    .line 350
    move/from16 v21, v5

    .line 351
    .line 352
    const/4 v5, -0x1

    .line 353
    move-object/from16 v22, v9

    .line 354
    .line 355
    if-eq v3, v5, :cond_9

    .line 356
    .line 357
    iget v9, v4, Lo8/w;->b:I

    .line 358
    .line 359
    if-eq v9, v5, :cond_9

    .line 360
    .line 361
    iput v3, v7, Lt7/n;->H:I

    .line 362
    .line 363
    iput v9, v7, Lt7/n;->I:I

    .line 364
    .line 365
    goto :goto_8

    .line 366
    :cond_8
    move/from16 v21, v5

    .line 367
    .line 368
    move-object/from16 v22, v9

    .line 369
    .line 370
    :cond_9
    :goto_8
    iget-object v3, v6, Lt7/o;->l:Lt7/c0;

    .line 371
    .line 372
    filled-new-array {v11, v12}, [Lt7/c0;

    .line 373
    .line 374
    .line 375
    move-result-object v5

    .line 376
    invoke-static {v13, v1, v7, v3, v5}, Li9/p;->j(ILt7/c0;Lt7/n;Lt7/c0;[Lt7/c0;)V

    .line 377
    .line 378
    .line 379
    new-instance v3, Li9/i;

    .line 380
    .line 381
    invoke-virtual {v2}, Landroid/util/SparseArray;->size()I

    .line 382
    .line 383
    .line 384
    move-result v5

    .line 385
    const/4 v6, 0x1

    .line 386
    if-ne v5, v6, :cond_a

    .line 387
    .line 388
    move/from16 v5, v16

    .line 389
    .line 390
    invoke-virtual {v2, v5}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object v6

    .line 394
    check-cast v6, Li9/f;

    .line 395
    .line 396
    goto :goto_9

    .line 397
    :cond_a
    invoke-virtual {v2, v14}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 398
    .line 399
    .line 400
    move-result-object v5

    .line 401
    move-object v6, v5

    .line 402
    check-cast v6, Li9/f;

    .line 403
    .line 404
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 405
    .line 406
    .line 407
    :goto_9
    new-instance v5, Lt7/o;

    .line 408
    .line 409
    invoke-direct {v5, v7}, Lt7/o;-><init>(Lt7/n;)V

    .line 410
    .line 411
    .line 412
    invoke-direct {v3, v10, v8, v6, v5}, Li9/i;-><init>(Lo8/i0;Li9/t;Li9/f;Lt7/o;)V

    .line 413
    .line 414
    .line 415
    invoke-virtual {v15, v14, v3}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 416
    .line 417
    .line 418
    iget-wide v5, v0, Li9/j;->y:J

    .line 419
    .line 420
    move-object/from16 v3, v22

    .line 421
    .line 422
    iget-wide v7, v3, Li9/q;->e:J

    .line 423
    .line 424
    invoke-static {v5, v6, v7, v8}, Ljava/lang/Math;->max(JJ)J

    .line 425
    .line 426
    .line 427
    move-result-wide v5

    .line 428
    iput-wide v5, v0, Li9/j;->y:J

    .line 429
    .line 430
    add-int/lit8 v7, v19, 0x1

    .line 431
    .line 432
    move-object/from16 v6, v17

    .line 433
    .line 434
    move-object/from16 v3, v20

    .line 435
    .line 436
    move/from16 v5, v21

    .line 437
    .line 438
    const/16 v16, 0x0

    .line 439
    .line 440
    goto/16 :goto_7

    .line 441
    .line 442
    :cond_b
    iget-object v1, v0, Li9/j;->G:Lo8/q;

    .line 443
    .line 444
    invoke-interface {v1}, Lo8/q;->m()V

    .line 445
    .line 446
    .line 447
    goto/16 :goto_0

    .line 448
    .line 449
    :cond_c
    move-object/from16 v20, v3

    .line 450
    .line 451
    move/from16 v21, v5

    .line 452
    .line 453
    invoke-virtual {v15}, Landroid/util/SparseArray;->size()I

    .line 454
    .line 455
    .line 456
    move-result v1

    .line 457
    move/from16 v3, v21

    .line 458
    .line 459
    if-ne v1, v3, :cond_d

    .line 460
    .line 461
    const/4 v1, 0x1

    .line 462
    goto :goto_a

    .line 463
    :cond_d
    const/4 v1, 0x0

    .line 464
    :goto_a
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 465
    .line 466
    .line 467
    const/4 v1, 0x0

    .line 468
    :goto_b
    if-ge v1, v3, :cond_0

    .line 469
    .line 470
    move-object/from16 v4, v20

    .line 471
    .line 472
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 473
    .line 474
    .line 475
    move-result-object v5

    .line 476
    check-cast v5, Li9/t;

    .line 477
    .line 478
    iget-object v6, v5, Li9/t;->a:Li9/q;

    .line 479
    .line 480
    iget v7, v6, Li9/q;->a:I

    .line 481
    .line 482
    invoke-virtual {v15, v7}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 483
    .line 484
    .line 485
    move-result-object v7

    .line 486
    check-cast v7, Li9/i;

    .line 487
    .line 488
    iget v6, v6, Li9/q;->a:I

    .line 489
    .line 490
    invoke-virtual {v2}, Landroid/util/SparseArray;->size()I

    .line 491
    .line 492
    .line 493
    move-result v8

    .line 494
    const/4 v9, 0x1

    .line 495
    if-ne v8, v9, :cond_e

    .line 496
    .line 497
    const/4 v8, 0x0

    .line 498
    invoke-virtual {v2, v8}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 499
    .line 500
    .line 501
    move-result-object v6

    .line 502
    check-cast v6, Li9/f;

    .line 503
    .line 504
    goto :goto_c

    .line 505
    :cond_e
    invoke-virtual {v2, v6}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 506
    .line 507
    .line 508
    move-result-object v6

    .line 509
    check-cast v6, Li9/f;

    .line 510
    .line 511
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 512
    .line 513
    .line 514
    :goto_c
    iput-object v5, v7, Li9/i;->d:Li9/t;

    .line 515
    .line 516
    iput-object v6, v7, Li9/i;->e:Li9/f;

    .line 517
    .line 518
    iget-object v5, v7, Li9/i;->a:Lo8/i0;

    .line 519
    .line 520
    iget-object v6, v7, Li9/i;->j:Lt7/o;

    .line 521
    .line 522
    invoke-interface {v5, v6}, Lo8/i0;->c(Lt7/o;)V

    .line 523
    .line 524
    .line 525
    invoke-virtual {v7}, Li9/i;->e()V

    .line 526
    .line 527
    .line 528
    add-int/lit8 v1, v1, 0x1

    .line 529
    .line 530
    move-object/from16 v20, v4

    .line 531
    .line 532
    goto :goto_b

    .line 533
    :cond_f
    const v6, 0x6d6f6f66

    .line 534
    .line 535
    .line 536
    if-ne v2, v6, :cond_5a

    .line 537
    .line 538
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 539
    .line 540
    .line 541
    move-result v1

    .line 542
    const/4 v2, 0x0

    .line 543
    :goto_d
    if-ge v2, v1, :cond_54

    .line 544
    .line 545
    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 546
    .line 547
    .line 548
    move-result-object v3

    .line 549
    check-cast v3, Lx7/c;

    .line 550
    .line 551
    iget v6, v3, Lkq/d;->e:I

    .line 552
    .line 553
    const v7, 0x74726166

    .line 554
    .line 555
    .line 556
    if-ne v6, v7, :cond_53

    .line 557
    .line 558
    const v6, 0x74666864

    .line 559
    .line 560
    .line 561
    invoke-virtual {v3, v6}, Lx7/c;->n(I)Lx7/d;

    .line 562
    .line 563
    .line 564
    move-result-object v6

    .line 565
    iget-object v7, v3, Lx7/c;->g:Ljava/util/ArrayList;

    .line 566
    .line 567
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 568
    .line 569
    .line 570
    iget-object v6, v6, Lx7/d;->f:Lw7/p;

    .line 571
    .line 572
    const/16 v9, 0x8

    .line 573
    .line 574
    invoke-virtual {v6, v9}, Lw7/p;->I(I)V

    .line 575
    .line 576
    .line 577
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 578
    .line 579
    .line 580
    move-result v9

    .line 581
    sget-object v10, Li9/e;->a:[B

    .line 582
    .line 583
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 584
    .line 585
    .line 586
    move-result v10

    .line 587
    invoke-virtual {v15, v10}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 588
    .line 589
    .line 590
    move-result-object v10

    .line 591
    check-cast v10, Li9/i;

    .line 592
    .line 593
    if-nez v10, :cond_10

    .line 594
    .line 595
    move/from16 v23, v1

    .line 596
    .line 597
    const/4 v10, 0x0

    .line 598
    const-wide v21, -0x7fffffffffffffffL    # -4.9E-324

    .line 599
    .line 600
    .line 601
    .line 602
    .line 603
    goto :goto_12

    .line 604
    :cond_10
    iget-object v11, v10, Li9/i;->b:Li9/s;

    .line 605
    .line 606
    and-int/lit8 v12, v9, 0x1

    .line 607
    .line 608
    const-wide v21, -0x7fffffffffffffffL    # -4.9E-324

    .line 609
    .line 610
    .line 611
    .line 612
    .line 613
    if-eqz v12, :cond_11

    .line 614
    .line 615
    invoke-virtual {v6}, Lw7/p;->B()J

    .line 616
    .line 617
    .line 618
    move-result-wide v13

    .line 619
    iput-wide v13, v11, Li9/s;->b:J

    .line 620
    .line 621
    iput-wide v13, v11, Li9/s;->c:J

    .line 622
    .line 623
    :cond_11
    iget-object v12, v10, Li9/i;->e:Li9/f;

    .line 624
    .line 625
    and-int/lit8 v13, v9, 0x2

    .line 626
    .line 627
    if-eqz v13, :cond_12

    .line 628
    .line 629
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 630
    .line 631
    .line 632
    move-result v13

    .line 633
    const/16 v18, 0x1

    .line 634
    .line 635
    add-int/lit8 v13, v13, -0x1

    .line 636
    .line 637
    goto :goto_e

    .line 638
    :cond_12
    iget v13, v12, Li9/f;->a:I

    .line 639
    .line 640
    :goto_e
    and-int/lit8 v14, v9, 0x8

    .line 641
    .line 642
    if-eqz v14, :cond_13

    .line 643
    .line 644
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 645
    .line 646
    .line 647
    move-result v14

    .line 648
    goto :goto_f

    .line 649
    :cond_13
    iget v14, v12, Li9/f;->b:I

    .line 650
    .line 651
    :goto_f
    and-int/lit8 v23, v9, 0x10

    .line 652
    .line 653
    if-eqz v23, :cond_14

    .line 654
    .line 655
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 656
    .line 657
    .line 658
    move-result v23

    .line 659
    move/from16 v52, v23

    .line 660
    .line 661
    move/from16 v23, v1

    .line 662
    .line 663
    move/from16 v1, v52

    .line 664
    .line 665
    goto :goto_10

    .line 666
    :cond_14
    move/from16 v23, v1

    .line 667
    .line 668
    iget v1, v12, Li9/f;->c:I

    .line 669
    .line 670
    :goto_10
    and-int/lit8 v9, v9, 0x20

    .line 671
    .line 672
    if-eqz v9, :cond_15

    .line 673
    .line 674
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 675
    .line 676
    .line 677
    move-result v6

    .line 678
    goto :goto_11

    .line 679
    :cond_15
    iget v6, v12, Li9/f;->d:I

    .line 680
    .line 681
    :goto_11
    new-instance v9, Li9/f;

    .line 682
    .line 683
    invoke-direct {v9, v13, v14, v1, v6}, Li9/f;-><init>(IIII)V

    .line 684
    .line 685
    .line 686
    iput-object v9, v11, Li9/s;->a:Li9/f;

    .line 687
    .line 688
    :goto_12
    if-nez v10, :cond_17

    .line 689
    .line 690
    move/from16 v24, v2

    .line 691
    .line 692
    move-object/from16 v30, v4

    .line 693
    .line 694
    move-object/from16 v31, v5

    .line 695
    .line 696
    move/from16 v48, v8

    .line 697
    .line 698
    const/4 v6, 0x0

    .line 699
    const/4 v9, 0x1

    .line 700
    const/16 v13, 0xc

    .line 701
    .line 702
    :cond_16
    const/4 v8, 0x0

    .line 703
    const/16 v11, 0x8

    .line 704
    .line 705
    goto/16 :goto_3b

    .line 706
    .line 707
    :cond_17
    iget-object v1, v10, Li9/i;->b:Li9/s;

    .line 708
    .line 709
    iget-wide v11, v1, Li9/s;->p:J

    .line 710
    .line 711
    iget-boolean v6, v1, Li9/s;->q:Z

    .line 712
    .line 713
    invoke-virtual {v10}, Li9/i;->e()V

    .line 714
    .line 715
    .line 716
    const/4 v9, 0x1

    .line 717
    iput-boolean v9, v10, Li9/i;->m:Z

    .line 718
    .line 719
    const v13, 0x74666474

    .line 720
    .line 721
    .line 722
    invoke-virtual {v3, v13}, Lx7/c;->n(I)Lx7/d;

    .line 723
    .line 724
    .line 725
    move-result-object v13

    .line 726
    if-eqz v13, :cond_19

    .line 727
    .line 728
    and-int/lit8 v14, v8, 0x2

    .line 729
    .line 730
    if-nez v14, :cond_19

    .line 731
    .line 732
    iget-object v6, v13, Lx7/d;->f:Lw7/p;

    .line 733
    .line 734
    const/16 v11, 0x8

    .line 735
    .line 736
    invoke-virtual {v6, v11}, Lw7/p;->I(I)V

    .line 737
    .line 738
    .line 739
    invoke-virtual {v6}, Lw7/p;->j()I

    .line 740
    .line 741
    .line 742
    move-result v11

    .line 743
    invoke-static {v11}, Li9/e;->e(I)I

    .line 744
    .line 745
    .line 746
    move-result v11

    .line 747
    if-ne v11, v9, :cond_18

    .line 748
    .line 749
    invoke-virtual {v6}, Lw7/p;->B()J

    .line 750
    .line 751
    .line 752
    move-result-wide v11

    .line 753
    goto :goto_13

    .line 754
    :cond_18
    invoke-virtual {v6}, Lw7/p;->y()J

    .line 755
    .line 756
    .line 757
    move-result-wide v11

    .line 758
    :goto_13
    iput-wide v11, v1, Li9/s;->p:J

    .line 759
    .line 760
    iput-boolean v9, v1, Li9/s;->q:Z

    .line 761
    .line 762
    goto :goto_14

    .line 763
    :cond_19
    iput-wide v11, v1, Li9/s;->p:J

    .line 764
    .line 765
    iput-boolean v6, v1, Li9/s;->q:Z

    .line 766
    .line 767
    :goto_14
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 768
    .line 769
    .line 770
    move-result v6

    .line 771
    const/4 v9, 0x0

    .line 772
    const/4 v11, 0x0

    .line 773
    const/4 v12, 0x0

    .line 774
    :goto_15
    const v13, 0x7472756e

    .line 775
    .line 776
    .line 777
    if-ge v9, v6, :cond_1b

    .line 778
    .line 779
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 780
    .line 781
    .line 782
    move-result-object v14

    .line 783
    check-cast v14, Lx7/d;

    .line 784
    .line 785
    move/from16 v24, v2

    .line 786
    .line 787
    iget v2, v14, Lkq/d;->e:I

    .line 788
    .line 789
    if-ne v2, v13, :cond_1a

    .line 790
    .line 791
    iget-object v2, v14, Lx7/d;->f:Lw7/p;

    .line 792
    .line 793
    const/16 v13, 0xc

    .line 794
    .line 795
    invoke-virtual {v2, v13}, Lw7/p;->I(I)V

    .line 796
    .line 797
    .line 798
    invoke-virtual {v2}, Lw7/p;->A()I

    .line 799
    .line 800
    .line 801
    move-result v2

    .line 802
    if-lez v2, :cond_1a

    .line 803
    .line 804
    add-int/2addr v12, v2

    .line 805
    add-int/lit8 v11, v11, 0x1

    .line 806
    .line 807
    :cond_1a
    add-int/lit8 v9, v9, 0x1

    .line 808
    .line 809
    move/from16 v2, v24

    .line 810
    .line 811
    goto :goto_15

    .line 812
    :cond_1b
    move/from16 v24, v2

    .line 813
    .line 814
    const/4 v2, 0x0

    .line 815
    iput v2, v10, Li9/i;->h:I

    .line 816
    .line 817
    iput v2, v10, Li9/i;->g:I

    .line 818
    .line 819
    iput v2, v10, Li9/i;->f:I

    .line 820
    .line 821
    iput v11, v1, Li9/s;->d:I

    .line 822
    .line 823
    iput v12, v1, Li9/s;->e:I

    .line 824
    .line 825
    iget-object v2, v1, Li9/s;->g:[I

    .line 826
    .line 827
    array-length v2, v2

    .line 828
    if-ge v2, v11, :cond_1c

    .line 829
    .line 830
    new-array v2, v11, [J

    .line 831
    .line 832
    iput-object v2, v1, Li9/s;->f:[J

    .line 833
    .line 834
    new-array v2, v11, [I

    .line 835
    .line 836
    iput-object v2, v1, Li9/s;->g:[I

    .line 837
    .line 838
    :cond_1c
    iget-object v2, v1, Li9/s;->h:[I

    .line 839
    .line 840
    array-length v2, v2

    .line 841
    if-ge v2, v12, :cond_1d

    .line 842
    .line 843
    mul-int/lit8 v12, v12, 0x7d

    .line 844
    .line 845
    div-int/lit8 v12, v12, 0x64

    .line 846
    .line 847
    new-array v2, v12, [I

    .line 848
    .line 849
    iput-object v2, v1, Li9/s;->h:[I

    .line 850
    .line 851
    new-array v2, v12, [J

    .line 852
    .line 853
    iput-object v2, v1, Li9/s;->i:[J

    .line 854
    .line 855
    new-array v2, v12, [Z

    .line 856
    .line 857
    iput-object v2, v1, Li9/s;->j:[Z

    .line 858
    .line 859
    new-array v2, v12, [Z

    .line 860
    .line 861
    iput-object v2, v1, Li9/s;->l:[Z

    .line 862
    .line 863
    :cond_1d
    const/4 v2, 0x0

    .line 864
    const/4 v9, 0x0

    .line 865
    const/4 v11, 0x0

    .line 866
    :goto_16
    const-wide/16 v25, 0x0

    .line 867
    .line 868
    if-ge v2, v6, :cond_35

    .line 869
    .line 870
    invoke-virtual {v7, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 871
    .line 872
    .line 873
    move-result-object v27

    .line 874
    const/16 v28, 0x10

    .line 875
    .line 876
    move-object/from16 v12, v27

    .line 877
    .line 878
    check-cast v12, Lx7/d;

    .line 879
    .line 880
    iget v14, v12, Lkq/d;->e:I

    .line 881
    .line 882
    if-ne v14, v13, :cond_34

    .line 883
    .line 884
    add-int/lit8 v14, v9, 0x1

    .line 885
    .line 886
    iget-object v12, v12, Lx7/d;->f:Lw7/p;

    .line 887
    .line 888
    const/16 v13, 0x8

    .line 889
    .line 890
    invoke-virtual {v12, v13}, Lw7/p;->I(I)V

    .line 891
    .line 892
    .line 893
    invoke-virtual {v12}, Lw7/p;->j()I

    .line 894
    .line 895
    .line 896
    move-result v13

    .line 897
    sget-object v29, Li9/e;->a:[B

    .line 898
    .line 899
    move/from16 v29, v2

    .line 900
    .line 901
    iget-object v2, v10, Li9/i;->d:Li9/t;

    .line 902
    .line 903
    iget-object v2, v2, Li9/t;->a:Li9/q;

    .line 904
    .line 905
    move-object/from16 v30, v4

    .line 906
    .line 907
    iget-object v4, v1, Li9/s;->a:Li9/f;

    .line 908
    .line 909
    sget-object v31, Lw7/w;->a:Ljava/lang/String;

    .line 910
    .line 911
    move-object/from16 v31, v5

    .line 912
    .line 913
    iget-object v5, v1, Li9/s;->g:[I

    .line 914
    .line 915
    invoke-virtual {v12}, Lw7/p;->A()I

    .line 916
    .line 917
    .line 918
    move-result v32

    .line 919
    aput v32, v5, v9

    .line 920
    .line 921
    iget-object v5, v1, Li9/s;->f:[J

    .line 922
    .line 923
    move-object/from16 v33, v5

    .line 924
    .line 925
    move/from16 v32, v6

    .line 926
    .line 927
    iget-wide v5, v1, Li9/s;->b:J

    .line 928
    .line 929
    aput-wide v5, v33, v9

    .line 930
    .line 931
    and-int/lit8 v34, v13, 0x1

    .line 932
    .line 933
    if-eqz v34, :cond_1e

    .line 934
    .line 935
    move-wide/from16 v34, v5

    .line 936
    .line 937
    invoke-virtual {v12}, Lw7/p;->j()I

    .line 938
    .line 939
    .line 940
    move-result v5

    .line 941
    int-to-long v5, v5

    .line 942
    add-long v5, v34, v5

    .line 943
    .line 944
    aput-wide v5, v33, v9

    .line 945
    .line 946
    :cond_1e
    and-int/lit8 v5, v13, 0x4

    .line 947
    .line 948
    if-eqz v5, :cond_1f

    .line 949
    .line 950
    const/4 v5, 0x1

    .line 951
    goto :goto_17

    .line 952
    :cond_1f
    const/4 v5, 0x0

    .line 953
    :goto_17
    iget v6, v4, Li9/f;->d:I

    .line 954
    .line 955
    if-eqz v5, :cond_20

    .line 956
    .line 957
    invoke-virtual {v12}, Lw7/p;->j()I

    .line 958
    .line 959
    .line 960
    move-result v6

    .line 961
    :cond_20
    move/from16 v33, v5

    .line 962
    .line 963
    and-int/lit16 v5, v13, 0x100

    .line 964
    .line 965
    if-eqz v5, :cond_21

    .line 966
    .line 967
    const/4 v5, 0x1

    .line 968
    goto :goto_18

    .line 969
    :cond_21
    const/4 v5, 0x0

    .line 970
    :goto_18
    move/from16 v34, v5

    .line 971
    .line 972
    and-int/lit16 v5, v13, 0x200

    .line 973
    .line 974
    if-eqz v5, :cond_22

    .line 975
    .line 976
    const/4 v5, 0x1

    .line 977
    goto :goto_19

    .line 978
    :cond_22
    const/4 v5, 0x0

    .line 979
    :goto_19
    move/from16 v35, v5

    .line 980
    .line 981
    and-int/lit16 v5, v13, 0x400

    .line 982
    .line 983
    if-eqz v5, :cond_23

    .line 984
    .line 985
    const/4 v5, 0x1

    .line 986
    goto :goto_1a

    .line 987
    :cond_23
    const/4 v5, 0x0

    .line 988
    :goto_1a
    and-int/lit16 v13, v13, 0x800

    .line 989
    .line 990
    if-eqz v13, :cond_24

    .line 991
    .line 992
    const/4 v13, 0x1

    .line 993
    :goto_1b
    move/from16 v36, v5

    .line 994
    .line 995
    goto :goto_1c

    .line 996
    :cond_24
    const/4 v13, 0x0

    .line 997
    goto :goto_1b

    .line 998
    :goto_1c
    iget-object v5, v2, Li9/q;->i:[J

    .line 999
    .line 1000
    move/from16 v37, v6

    .line 1001
    .line 1002
    iget-object v6, v2, Li9/q;->j:[J

    .line 1003
    .line 1004
    if-eqz v5, :cond_27

    .line 1005
    .line 1006
    move-object/from16 v38, v6

    .line 1007
    .line 1008
    array-length v6, v5

    .line 1009
    move-object/from16 v39, v5

    .line 1010
    .line 1011
    const/4 v5, 0x1

    .line 1012
    if-ne v6, v5, :cond_27

    .line 1013
    .line 1014
    if-nez v38, :cond_25

    .line 1015
    .line 1016
    goto :goto_1e

    .line 1017
    :cond_25
    const/16 v16, 0x0

    .line 1018
    .line 1019
    aget-wide v40, v39, v16

    .line 1020
    .line 1021
    cmp-long v5, v40, v25

    .line 1022
    .line 1023
    if-nez v5, :cond_26

    .line 1024
    .line 1025
    goto :goto_1d

    .line 1026
    :cond_26
    iget-wide v5, v2, Li9/q;->d:J

    .line 1027
    .line 1028
    sget-object v46, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 1029
    .line 1030
    const-wide/32 v42, 0xf4240

    .line 1031
    .line 1032
    .line 1033
    move-wide/from16 v44, v5

    .line 1034
    .line 1035
    invoke-static/range {v40 .. v46}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 1036
    .line 1037
    .line 1038
    move-result-wide v5

    .line 1039
    aget-wide v42, v38, v16

    .line 1040
    .line 1041
    const-wide/32 v44, 0xf4240

    .line 1042
    .line 1043
    .line 1044
    move-wide/from16 v39, v5

    .line 1045
    .line 1046
    iget-wide v5, v2, Li9/q;->c:J

    .line 1047
    .line 1048
    move-object/from16 v48, v46

    .line 1049
    .line 1050
    move-wide/from16 v46, v5

    .line 1051
    .line 1052
    invoke-static/range {v42 .. v48}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 1053
    .line 1054
    .line 1055
    move-result-wide v5

    .line 1056
    add-long v5, v39, v5

    .line 1057
    .line 1058
    move-wide/from16 v39, v5

    .line 1059
    .line 1060
    iget-wide v5, v2, Li9/q;->e:J

    .line 1061
    .line 1062
    cmp-long v5, v39, v5

    .line 1063
    .line 1064
    if-ltz v5, :cond_27

    .line 1065
    .line 1066
    :goto_1d
    aget-wide v25, v38, v16

    .line 1067
    .line 1068
    :cond_27
    :goto_1e
    iget-object v5, v1, Li9/s;->h:[I

    .line 1069
    .line 1070
    iget-object v6, v1, Li9/s;->i:[J

    .line 1071
    .line 1072
    move-object/from16 v38, v5

    .line 1073
    .line 1074
    iget-object v5, v1, Li9/s;->j:[Z

    .line 1075
    .line 1076
    move-object/from16 v39, v5

    .line 1077
    .line 1078
    iget v5, v2, Li9/q;->b:I

    .line 1079
    .line 1080
    move-object/from16 v40, v6

    .line 1081
    .line 1082
    const/4 v6, 0x2

    .line 1083
    if-ne v5, v6, :cond_28

    .line 1084
    .line 1085
    and-int/lit8 v5, v8, 0x1

    .line 1086
    .line 1087
    if-eqz v5, :cond_28

    .line 1088
    .line 1089
    const/4 v5, 0x1

    .line 1090
    goto :goto_1f

    .line 1091
    :cond_28
    const/4 v5, 0x0

    .line 1092
    :goto_1f
    iget-object v6, v1, Li9/s;->g:[I

    .line 1093
    .line 1094
    aget v6, v6, v9

    .line 1095
    .line 1096
    add-int/2addr v6, v11

    .line 1097
    move/from16 v48, v8

    .line 1098
    .line 1099
    iget-wide v8, v2, Li9/q;->c:J

    .line 1100
    .line 1101
    move-wide/from16 v45, v8

    .line 1102
    .line 1103
    iget-wide v8, v1, Li9/s;->p:J

    .line 1104
    .line 1105
    :goto_20
    if-ge v11, v6, :cond_33

    .line 1106
    .line 1107
    if-eqz v34, :cond_29

    .line 1108
    .line 1109
    invoke-virtual {v12}, Lw7/p;->j()I

    .line 1110
    .line 1111
    .line 1112
    move-result v2

    .line 1113
    :goto_21
    move/from16 v27, v5

    .line 1114
    .line 1115
    goto :goto_22

    .line 1116
    :cond_29
    iget v2, v4, Li9/f;->b:I

    .line 1117
    .line 1118
    goto :goto_21

    .line 1119
    :goto_22
    const-string v5, "Unexpected negative value: "

    .line 1120
    .line 1121
    if-ltz v2, :cond_32

    .line 1122
    .line 1123
    if-eqz v35, :cond_2a

    .line 1124
    .line 1125
    invoke-virtual {v12}, Lw7/p;->j()I

    .line 1126
    .line 1127
    .line 1128
    move-result v41

    .line 1129
    move/from16 v49, v6

    .line 1130
    .line 1131
    move/from16 v6, v41

    .line 1132
    .line 1133
    goto :goto_23

    .line 1134
    :cond_2a
    move/from16 v49, v6

    .line 1135
    .line 1136
    iget v6, v4, Li9/f;->c:I

    .line 1137
    .line 1138
    :goto_23
    if-ltz v6, :cond_31

    .line 1139
    .line 1140
    if-eqz v36, :cond_2b

    .line 1141
    .line 1142
    invoke-virtual {v12}, Lw7/p;->j()I

    .line 1143
    .line 1144
    .line 1145
    move-result v5

    .line 1146
    goto :goto_24

    .line 1147
    :cond_2b
    if-nez v11, :cond_2c

    .line 1148
    .line 1149
    if-eqz v33, :cond_2c

    .line 1150
    .line 1151
    move/from16 v5, v37

    .line 1152
    .line 1153
    goto :goto_24

    .line 1154
    :cond_2c
    iget v5, v4, Li9/f;->d:I

    .line 1155
    .line 1156
    :goto_24
    if-eqz v13, :cond_2d

    .line 1157
    .line 1158
    invoke-virtual {v12}, Lw7/p;->j()I

    .line 1159
    .line 1160
    .line 1161
    move-result v41

    .line 1162
    move-object/from16 v50, v4

    .line 1163
    .line 1164
    move/from16 v4, v41

    .line 1165
    .line 1166
    :goto_25
    move/from16 v51, v5

    .line 1167
    .line 1168
    goto :goto_26

    .line 1169
    :cond_2d
    move-object/from16 v50, v4

    .line 1170
    .line 1171
    const/4 v4, 0x0

    .line 1172
    goto :goto_25

    .line 1173
    :goto_26
    int-to-long v4, v4

    .line 1174
    add-long/2addr v4, v8

    .line 1175
    sub-long v41, v4, v25

    .line 1176
    .line 1177
    const-wide/32 v43, 0xf4240

    .line 1178
    .line 1179
    .line 1180
    sget-object v47, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 1181
    .line 1182
    invoke-static/range {v41 .. v47}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 1183
    .line 1184
    .line 1185
    move-result-wide v4

    .line 1186
    aput-wide v4, v40, v11

    .line 1187
    .line 1188
    move-wide/from16 v41, v4

    .line 1189
    .line 1190
    iget-boolean v4, v1, Li9/s;->q:Z

    .line 1191
    .line 1192
    if-nez v4, :cond_2e

    .line 1193
    .line 1194
    iget-object v4, v10, Li9/i;->d:Li9/t;

    .line 1195
    .line 1196
    iget-wide v4, v4, Li9/t;->h:J

    .line 1197
    .line 1198
    add-long v4, v41, v4

    .line 1199
    .line 1200
    aput-wide v4, v40, v11

    .line 1201
    .line 1202
    :cond_2e
    aput v6, v38, v11

    .line 1203
    .line 1204
    shr-int/lit8 v4, v51, 0x10

    .line 1205
    .line 1206
    const/16 v18, 0x1

    .line 1207
    .line 1208
    and-int/lit8 v4, v4, 0x1

    .line 1209
    .line 1210
    if-nez v4, :cond_30

    .line 1211
    .line 1212
    if-eqz v27, :cond_2f

    .line 1213
    .line 1214
    if-nez v11, :cond_30

    .line 1215
    .line 1216
    :cond_2f
    const/4 v4, 0x1

    .line 1217
    goto :goto_27

    .line 1218
    :cond_30
    const/4 v4, 0x0

    .line 1219
    :goto_27
    aput-boolean v4, v39, v11

    .line 1220
    .line 1221
    int-to-long v4, v2

    .line 1222
    add-long/2addr v8, v4

    .line 1223
    add-int/lit8 v11, v11, 0x1

    .line 1224
    .line 1225
    move/from16 v5, v27

    .line 1226
    .line 1227
    move/from16 v6, v49

    .line 1228
    .line 1229
    move-object/from16 v4, v50

    .line 1230
    .line 1231
    goto :goto_20

    .line 1232
    :cond_31
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1233
    .line 1234
    invoke-direct {v0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1235
    .line 1236
    .line 1237
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1238
    .line 1239
    .line 1240
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1241
    .line 1242
    .line 1243
    move-result-object v0

    .line 1244
    const/4 v6, 0x0

    .line 1245
    invoke-static {v6, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 1246
    .line 1247
    .line 1248
    move-result-object v0

    .line 1249
    throw v0

    .line 1250
    :cond_32
    const/4 v6, 0x0

    .line 1251
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1252
    .line 1253
    invoke-direct {v0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1254
    .line 1255
    .line 1256
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1257
    .line 1258
    .line 1259
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1260
    .line 1261
    .line 1262
    move-result-object v0

    .line 1263
    invoke-static {v6, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 1264
    .line 1265
    .line 1266
    move-result-object v0

    .line 1267
    throw v0

    .line 1268
    :cond_33
    move/from16 v49, v6

    .line 1269
    .line 1270
    iput-wide v8, v1, Li9/s;->p:J

    .line 1271
    .line 1272
    move v9, v14

    .line 1273
    move/from16 v11, v49

    .line 1274
    .line 1275
    goto :goto_28

    .line 1276
    :cond_34
    move/from16 v29, v2

    .line 1277
    .line 1278
    move-object/from16 v30, v4

    .line 1279
    .line 1280
    move-object/from16 v31, v5

    .line 1281
    .line 1282
    move/from16 v32, v6

    .line 1283
    .line 1284
    move/from16 v48, v8

    .line 1285
    .line 1286
    :goto_28
    add-int/lit8 v2, v29, 0x1

    .line 1287
    .line 1288
    move-object/from16 v4, v30

    .line 1289
    .line 1290
    move-object/from16 v5, v31

    .line 1291
    .line 1292
    move/from16 v6, v32

    .line 1293
    .line 1294
    move/from16 v8, v48

    .line 1295
    .line 1296
    const v13, 0x7472756e

    .line 1297
    .line 1298
    .line 1299
    goto/16 :goto_16

    .line 1300
    .line 1301
    :cond_35
    move-object/from16 v30, v4

    .line 1302
    .line 1303
    move-object/from16 v31, v5

    .line 1304
    .line 1305
    move/from16 v48, v8

    .line 1306
    .line 1307
    const/16 v28, 0x10

    .line 1308
    .line 1309
    iget-object v2, v10, Li9/i;->d:Li9/t;

    .line 1310
    .line 1311
    iget-object v2, v2, Li9/t;->a:Li9/q;

    .line 1312
    .line 1313
    iget-object v4, v1, Li9/s;->a:Li9/f;

    .line 1314
    .line 1315
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1316
    .line 1317
    .line 1318
    iget v4, v4, Li9/f;->a:I

    .line 1319
    .line 1320
    iget-object v2, v2, Li9/q;->l:[Li9/r;

    .line 1321
    .line 1322
    aget-object v2, v2, v4

    .line 1323
    .line 1324
    const v4, 0x7361697a

    .line 1325
    .line 1326
    .line 1327
    invoke-virtual {v3, v4}, Lx7/c;->n(I)Lx7/d;

    .line 1328
    .line 1329
    .line 1330
    move-result-object v4

    .line 1331
    if-eqz v4, :cond_3c

    .line 1332
    .line 1333
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1334
    .line 1335
    .line 1336
    iget-object v4, v4, Lx7/d;->f:Lw7/p;

    .line 1337
    .line 1338
    iget v5, v2, Li9/r;->d:I

    .line 1339
    .line 1340
    const/16 v13, 0x8

    .line 1341
    .line 1342
    invoke-virtual {v4, v13}, Lw7/p;->I(I)V

    .line 1343
    .line 1344
    .line 1345
    invoke-virtual {v4}, Lw7/p;->j()I

    .line 1346
    .line 1347
    .line 1348
    move-result v6

    .line 1349
    sget-object v8, Li9/e;->a:[B

    .line 1350
    .line 1351
    const/4 v9, 0x1

    .line 1352
    and-int/2addr v6, v9

    .line 1353
    if-ne v6, v9, :cond_36

    .line 1354
    .line 1355
    invoke-virtual {v4, v13}, Lw7/p;->J(I)V

    .line 1356
    .line 1357
    .line 1358
    :cond_36
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 1359
    .line 1360
    .line 1361
    move-result v6

    .line 1362
    invoke-virtual {v4}, Lw7/p;->A()I

    .line 1363
    .line 1364
    .line 1365
    move-result v8

    .line 1366
    iget v9, v1, Li9/s;->e:I

    .line 1367
    .line 1368
    if-gt v8, v9, :cond_3b

    .line 1369
    .line 1370
    if-nez v6, :cond_39

    .line 1371
    .line 1372
    iget-object v6, v1, Li9/s;->l:[Z

    .line 1373
    .line 1374
    const/4 v9, 0x0

    .line 1375
    const/4 v10, 0x0

    .line 1376
    :goto_29
    if-ge v9, v8, :cond_38

    .line 1377
    .line 1378
    invoke-virtual {v4}, Lw7/p;->w()I

    .line 1379
    .line 1380
    .line 1381
    move-result v11

    .line 1382
    add-int/2addr v10, v11

    .line 1383
    if-le v11, v5, :cond_37

    .line 1384
    .line 1385
    const/4 v11, 0x1

    .line 1386
    goto :goto_2a

    .line 1387
    :cond_37
    const/4 v11, 0x0

    .line 1388
    :goto_2a
    aput-boolean v11, v6, v9

    .line 1389
    .line 1390
    add-int/lit8 v9, v9, 0x1

    .line 1391
    .line 1392
    goto :goto_29

    .line 1393
    :cond_38
    const/4 v6, 0x0

    .line 1394
    goto :goto_2c

    .line 1395
    :cond_39
    if-le v6, v5, :cond_3a

    .line 1396
    .line 1397
    const/4 v4, 0x1

    .line 1398
    goto :goto_2b

    .line 1399
    :cond_3a
    const/4 v4, 0x0

    .line 1400
    :goto_2b
    mul-int v10, v6, v8

    .line 1401
    .line 1402
    iget-object v5, v1, Li9/s;->l:[Z

    .line 1403
    .line 1404
    const/4 v6, 0x0

    .line 1405
    invoke-static {v5, v6, v8, v4}, Ljava/util/Arrays;->fill([ZIIZ)V

    .line 1406
    .line 1407
    .line 1408
    :goto_2c
    iget-object v4, v1, Li9/s;->l:[Z

    .line 1409
    .line 1410
    iget v5, v1, Li9/s;->e:I

    .line 1411
    .line 1412
    invoke-static {v4, v8, v5, v6}, Ljava/util/Arrays;->fill([ZIIZ)V

    .line 1413
    .line 1414
    .line 1415
    if-lez v10, :cond_3c

    .line 1416
    .line 1417
    iget-object v4, v1, Li9/s;->n:Lw7/p;

    .line 1418
    .line 1419
    invoke-virtual {v4, v10}, Lw7/p;->F(I)V

    .line 1420
    .line 1421
    .line 1422
    const/4 v9, 0x1

    .line 1423
    iput-boolean v9, v1, Li9/s;->k:Z

    .line 1424
    .line 1425
    iput-boolean v9, v1, Li9/s;->o:Z

    .line 1426
    .line 1427
    goto :goto_2d

    .line 1428
    :cond_3b
    const-string v0, "Saiz sample count "

    .line 1429
    .line 1430
    const-string v2, " is greater than fragment sample count"

    .line 1431
    .line 1432
    invoke-static {v0, v8, v2}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 1433
    .line 1434
    .line 1435
    move-result-object v0

    .line 1436
    iget v1, v1, Li9/s;->e:I

    .line 1437
    .line 1438
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1439
    .line 1440
    .line 1441
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1442
    .line 1443
    .line 1444
    move-result-object v0

    .line 1445
    const/4 v6, 0x0

    .line 1446
    invoke-static {v6, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 1447
    .line 1448
    .line 1449
    move-result-object v0

    .line 1450
    throw v0

    .line 1451
    :cond_3c
    :goto_2d
    const v4, 0x7361696f

    .line 1452
    .line 1453
    .line 1454
    invoke-virtual {v3, v4}, Lx7/c;->n(I)Lx7/d;

    .line 1455
    .line 1456
    .line 1457
    move-result-object v4

    .line 1458
    if-eqz v4, :cond_3f

    .line 1459
    .line 1460
    iget-object v4, v4, Lx7/d;->f:Lw7/p;

    .line 1461
    .line 1462
    const/16 v13, 0x8

    .line 1463
    .line 1464
    invoke-virtual {v4, v13}, Lw7/p;->I(I)V

    .line 1465
    .line 1466
    .line 1467
    invoke-virtual {v4}, Lw7/p;->j()I

    .line 1468
    .line 1469
    .line 1470
    move-result v5

    .line 1471
    sget-object v6, Li9/e;->a:[B

    .line 1472
    .line 1473
    and-int/lit8 v6, v5, 0x1

    .line 1474
    .line 1475
    const/4 v9, 0x1

    .line 1476
    if-ne v6, v9, :cond_3d

    .line 1477
    .line 1478
    invoke-virtual {v4, v13}, Lw7/p;->J(I)V

    .line 1479
    .line 1480
    .line 1481
    :cond_3d
    invoke-virtual {v4}, Lw7/p;->A()I

    .line 1482
    .line 1483
    .line 1484
    move-result v6

    .line 1485
    if-ne v6, v9, :cond_40

    .line 1486
    .line 1487
    invoke-static {v5}, Li9/e;->e(I)I

    .line 1488
    .line 1489
    .line 1490
    move-result v5

    .line 1491
    iget-wide v8, v1, Li9/s;->c:J

    .line 1492
    .line 1493
    if-nez v5, :cond_3e

    .line 1494
    .line 1495
    invoke-virtual {v4}, Lw7/p;->y()J

    .line 1496
    .line 1497
    .line 1498
    move-result-wide v4

    .line 1499
    goto :goto_2e

    .line 1500
    :cond_3e
    invoke-virtual {v4}, Lw7/p;->B()J

    .line 1501
    .line 1502
    .line 1503
    move-result-wide v4

    .line 1504
    :goto_2e
    add-long/2addr v8, v4

    .line 1505
    iput-wide v8, v1, Li9/s;->c:J

    .line 1506
    .line 1507
    :cond_3f
    const/4 v6, 0x0

    .line 1508
    goto :goto_2f

    .line 1509
    :cond_40
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1510
    .line 1511
    const-string v1, "Unexpected saio entry count: "

    .line 1512
    .line 1513
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1514
    .line 1515
    .line 1516
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1517
    .line 1518
    .line 1519
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1520
    .line 1521
    .line 1522
    move-result-object v0

    .line 1523
    const/4 v6, 0x0

    .line 1524
    invoke-static {v6, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 1525
    .line 1526
    .line 1527
    move-result-object v0

    .line 1528
    throw v0

    .line 1529
    :goto_2f
    const v4, 0x73656e63

    .line 1530
    .line 1531
    .line 1532
    invoke-virtual {v3, v4}, Lx7/c;->n(I)Lx7/d;

    .line 1533
    .line 1534
    .line 1535
    move-result-object v3

    .line 1536
    if-eqz v3, :cond_41

    .line 1537
    .line 1538
    iget-object v3, v3, Lx7/d;->f:Lw7/p;

    .line 1539
    .line 1540
    const/4 v5, 0x0

    .line 1541
    invoke-static {v3, v5, v1}, Li9/j;->g(Lw7/p;ILi9/s;)V

    .line 1542
    .line 1543
    .line 1544
    :cond_41
    if-eqz v2, :cond_42

    .line 1545
    .line 1546
    iget-object v2, v2, Li9/r;->b:Ljava/lang/String;

    .line 1547
    .line 1548
    move-object/from16 v34, v2

    .line 1549
    .line 1550
    goto :goto_30

    .line 1551
    :cond_42
    move-object/from16 v34, v6

    .line 1552
    .line 1553
    :goto_30
    move-object v2, v6

    .line 1554
    move-object v3, v2

    .line 1555
    const/4 v4, 0x0

    .line 1556
    :goto_31
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 1557
    .line 1558
    .line 1559
    move-result v5

    .line 1560
    if-ge v4, v5, :cond_45

    .line 1561
    .line 1562
    invoke-virtual {v7, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1563
    .line 1564
    .line 1565
    move-result-object v5

    .line 1566
    check-cast v5, Lx7/d;

    .line 1567
    .line 1568
    iget-object v8, v5, Lx7/d;->f:Lw7/p;

    .line 1569
    .line 1570
    iget v5, v5, Lkq/d;->e:I

    .line 1571
    .line 1572
    const v9, 0x73626770

    .line 1573
    .line 1574
    .line 1575
    const v10, 0x73656967

    .line 1576
    .line 1577
    .line 1578
    if-ne v5, v9, :cond_43

    .line 1579
    .line 1580
    const/16 v13, 0xc

    .line 1581
    .line 1582
    invoke-virtual {v8, v13}, Lw7/p;->I(I)V

    .line 1583
    .line 1584
    .line 1585
    invoke-virtual {v8}, Lw7/p;->j()I

    .line 1586
    .line 1587
    .line 1588
    move-result v5

    .line 1589
    if-ne v5, v10, :cond_44

    .line 1590
    .line 1591
    move-object v2, v8

    .line 1592
    goto :goto_32

    .line 1593
    :cond_43
    const/16 v13, 0xc

    .line 1594
    .line 1595
    const v9, 0x73677064

    .line 1596
    .line 1597
    .line 1598
    if-ne v5, v9, :cond_44

    .line 1599
    .line 1600
    invoke-virtual {v8, v13}, Lw7/p;->I(I)V

    .line 1601
    .line 1602
    .line 1603
    invoke-virtual {v8}, Lw7/p;->j()I

    .line 1604
    .line 1605
    .line 1606
    move-result v5

    .line 1607
    if-ne v5, v10, :cond_44

    .line 1608
    .line 1609
    move-object v3, v8

    .line 1610
    :cond_44
    :goto_32
    add-int/lit8 v4, v4, 0x1

    .line 1611
    .line 1612
    goto :goto_31

    .line 1613
    :cond_45
    const/16 v13, 0xc

    .line 1614
    .line 1615
    if-eqz v2, :cond_46

    .line 1616
    .line 1617
    if-nez v3, :cond_47

    .line 1618
    .line 1619
    :cond_46
    :goto_33
    const/4 v9, 0x1

    .line 1620
    goto/16 :goto_38

    .line 1621
    .line 1622
    :cond_47
    const/16 v9, 0x8

    .line 1623
    .line 1624
    invoke-virtual {v2, v9}, Lw7/p;->I(I)V

    .line 1625
    .line 1626
    .line 1627
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 1628
    .line 1629
    .line 1630
    move-result v4

    .line 1631
    invoke-static {v4}, Li9/e;->e(I)I

    .line 1632
    .line 1633
    .line 1634
    move-result v4

    .line 1635
    const/4 v5, 0x4

    .line 1636
    invoke-virtual {v2, v5}, Lw7/p;->J(I)V

    .line 1637
    .line 1638
    .line 1639
    const/4 v8, 0x1

    .line 1640
    if-ne v4, v8, :cond_48

    .line 1641
    .line 1642
    invoke-virtual {v2, v5}, Lw7/p;->J(I)V

    .line 1643
    .line 1644
    .line 1645
    :cond_48
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 1646
    .line 1647
    .line 1648
    move-result v2

    .line 1649
    if-ne v2, v8, :cond_50

    .line 1650
    .line 1651
    invoke-virtual {v3, v9}, Lw7/p;->I(I)V

    .line 1652
    .line 1653
    .line 1654
    invoke-virtual {v3}, Lw7/p;->j()I

    .line 1655
    .line 1656
    .line 1657
    move-result v2

    .line 1658
    invoke-static {v2}, Li9/e;->e(I)I

    .line 1659
    .line 1660
    .line 1661
    move-result v2

    .line 1662
    invoke-virtual {v3, v5}, Lw7/p;->J(I)V

    .line 1663
    .line 1664
    .line 1665
    if-ne v2, v8, :cond_4a

    .line 1666
    .line 1667
    invoke-virtual {v3}, Lw7/p;->y()J

    .line 1668
    .line 1669
    .line 1670
    move-result-wide v8

    .line 1671
    cmp-long v2, v8, v25

    .line 1672
    .line 1673
    if-eqz v2, :cond_49

    .line 1674
    .line 1675
    goto :goto_34

    .line 1676
    :cond_49
    const-string v0, "Variable length description in sgpd found (unsupported)"

    .line 1677
    .line 1678
    invoke-static {v0}, Lt7/e0;->b(Ljava/lang/String;)Lt7/e0;

    .line 1679
    .line 1680
    .line 1681
    move-result-object v0

    .line 1682
    throw v0

    .line 1683
    :cond_4a
    const/4 v4, 0x2

    .line 1684
    if-lt v2, v4, :cond_4b

    .line 1685
    .line 1686
    invoke-virtual {v3, v5}, Lw7/p;->J(I)V

    .line 1687
    .line 1688
    .line 1689
    :cond_4b
    :goto_34
    invoke-virtual {v3}, Lw7/p;->y()J

    .line 1690
    .line 1691
    .line 1692
    move-result-wide v8

    .line 1693
    const-wide/16 v10, 0x1

    .line 1694
    .line 1695
    cmp-long v2, v8, v10

    .line 1696
    .line 1697
    if-nez v2, :cond_4f

    .line 1698
    .line 1699
    const/4 v9, 0x1

    .line 1700
    invoke-virtual {v3, v9}, Lw7/p;->J(I)V

    .line 1701
    .line 1702
    .line 1703
    invoke-virtual {v3}, Lw7/p;->w()I

    .line 1704
    .line 1705
    .line 1706
    move-result v2

    .line 1707
    and-int/lit16 v4, v2, 0xf0

    .line 1708
    .line 1709
    shr-int/lit8 v37, v4, 0x4

    .line 1710
    .line 1711
    and-int/lit8 v38, v2, 0xf

    .line 1712
    .line 1713
    invoke-virtual {v3}, Lw7/p;->w()I

    .line 1714
    .line 1715
    .line 1716
    move-result v2

    .line 1717
    if-ne v2, v9, :cond_4c

    .line 1718
    .line 1719
    const/16 v33, 0x1

    .line 1720
    .line 1721
    goto :goto_35

    .line 1722
    :cond_4c
    const/16 v33, 0x0

    .line 1723
    .line 1724
    :goto_35
    if-nez v33, :cond_4d

    .line 1725
    .line 1726
    goto :goto_33

    .line 1727
    :cond_4d
    invoke-virtual {v3}, Lw7/p;->w()I

    .line 1728
    .line 1729
    .line 1730
    move-result v35

    .line 1731
    move/from16 v2, v28

    .line 1732
    .line 1733
    new-array v4, v2, [B

    .line 1734
    .line 1735
    const/4 v5, 0x0

    .line 1736
    invoke-virtual {v3, v4, v5, v2}, Lw7/p;->h([BII)V

    .line 1737
    .line 1738
    .line 1739
    if-nez v35, :cond_4e

    .line 1740
    .line 1741
    invoke-virtual {v3}, Lw7/p;->w()I

    .line 1742
    .line 1743
    .line 1744
    move-result v2

    .line 1745
    new-array v8, v2, [B

    .line 1746
    .line 1747
    invoke-virtual {v3, v8, v5, v2}, Lw7/p;->h([BII)V

    .line 1748
    .line 1749
    .line 1750
    move-object/from16 v39, v8

    .line 1751
    .line 1752
    :goto_36
    const/4 v9, 0x1

    .line 1753
    goto :goto_37

    .line 1754
    :cond_4e
    move-object/from16 v39, v6

    .line 1755
    .line 1756
    goto :goto_36

    .line 1757
    :goto_37
    iput-boolean v9, v1, Li9/s;->k:Z

    .line 1758
    .line 1759
    new-instance v32, Li9/r;

    .line 1760
    .line 1761
    move-object/from16 v36, v4

    .line 1762
    .line 1763
    invoke-direct/range {v32 .. v39}, Li9/r;-><init>(ZLjava/lang/String;I[BII[B)V

    .line 1764
    .line 1765
    .line 1766
    move-object/from16 v2, v32

    .line 1767
    .line 1768
    iput-object v2, v1, Li9/s;->m:Li9/r;

    .line 1769
    .line 1770
    goto :goto_38

    .line 1771
    :cond_4f
    const-string v0, "Entry count in sgpd != 1 (unsupported)."

    .line 1772
    .line 1773
    invoke-static {v0}, Lt7/e0;->b(Ljava/lang/String;)Lt7/e0;

    .line 1774
    .line 1775
    .line 1776
    move-result-object v0

    .line 1777
    throw v0

    .line 1778
    :cond_50
    const-string v0, "Entry count in sbgp != 1 (unsupported)."

    .line 1779
    .line 1780
    invoke-static {v0}, Lt7/e0;->b(Ljava/lang/String;)Lt7/e0;

    .line 1781
    .line 1782
    .line 1783
    move-result-object v0

    .line 1784
    throw v0

    .line 1785
    :goto_38
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 1786
    .line 1787
    .line 1788
    move-result v2

    .line 1789
    const/4 v5, 0x0

    .line 1790
    :goto_39
    if-ge v5, v2, :cond_16

    .line 1791
    .line 1792
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1793
    .line 1794
    .line 1795
    move-result-object v3

    .line 1796
    check-cast v3, Lx7/d;

    .line 1797
    .line 1798
    iget v4, v3, Lkq/d;->e:I

    .line 1799
    .line 1800
    const v8, 0x75756964

    .line 1801
    .line 1802
    .line 1803
    if-ne v4, v8, :cond_52

    .line 1804
    .line 1805
    iget-object v3, v3, Lx7/d;->f:Lw7/p;

    .line 1806
    .line 1807
    const/16 v11, 0x8

    .line 1808
    .line 1809
    invoke-virtual {v3, v11}, Lw7/p;->I(I)V

    .line 1810
    .line 1811
    .line 1812
    iget-object v4, v0, Li9/j;->h:[B

    .line 1813
    .line 1814
    const/4 v8, 0x0

    .line 1815
    const/16 v10, 0x10

    .line 1816
    .line 1817
    invoke-virtual {v3, v4, v8, v10}, Lw7/p;->h([BII)V

    .line 1818
    .line 1819
    .line 1820
    sget-object v12, Li9/j;->M:[B

    .line 1821
    .line 1822
    invoke-static {v4, v12}, Ljava/util/Arrays;->equals([B[B)Z

    .line 1823
    .line 1824
    .line 1825
    move-result v4

    .line 1826
    if-nez v4, :cond_51

    .line 1827
    .line 1828
    goto :goto_3a

    .line 1829
    :cond_51
    invoke-static {v3, v10, v1}, Li9/j;->g(Lw7/p;ILi9/s;)V

    .line 1830
    .line 1831
    .line 1832
    goto :goto_3a

    .line 1833
    :cond_52
    const/4 v8, 0x0

    .line 1834
    const/16 v10, 0x10

    .line 1835
    .line 1836
    const/16 v11, 0x8

    .line 1837
    .line 1838
    :goto_3a
    add-int/lit8 v5, v5, 0x1

    .line 1839
    .line 1840
    goto :goto_39

    .line 1841
    :cond_53
    move/from16 v23, v1

    .line 1842
    .line 1843
    move/from16 v24, v2

    .line 1844
    .line 1845
    move-object/from16 v30, v4

    .line 1846
    .line 1847
    move-object/from16 v31, v5

    .line 1848
    .line 1849
    move/from16 v48, v8

    .line 1850
    .line 1851
    const/4 v6, 0x0

    .line 1852
    const/4 v8, 0x0

    .line 1853
    const/4 v9, 0x1

    .line 1854
    const/16 v11, 0x8

    .line 1855
    .line 1856
    const/16 v13, 0xc

    .line 1857
    .line 1858
    const-wide v21, -0x7fffffffffffffffL    # -4.9E-324

    .line 1859
    .line 1860
    .line 1861
    .line 1862
    .line 1863
    :goto_3b
    add-int/lit8 v2, v24, 0x1

    .line 1864
    .line 1865
    move/from16 v1, v23

    .line 1866
    .line 1867
    move-object/from16 v4, v30

    .line 1868
    .line 1869
    move-object/from16 v5, v31

    .line 1870
    .line 1871
    move/from16 v8, v48

    .line 1872
    .line 1873
    goto/16 :goto_d

    .line 1874
    .line 1875
    :cond_54
    move-object/from16 v31, v5

    .line 1876
    .line 1877
    const/4 v6, 0x0

    .line 1878
    const/4 v8, 0x0

    .line 1879
    const-wide v21, -0x7fffffffffffffffL    # -4.9E-324

    .line 1880
    .line 1881
    .line 1882
    .line 1883
    .line 1884
    invoke-static/range {v31 .. v31}, Li9/j;->f(Ljava/util/List;)Lt7/k;

    .line 1885
    .line 1886
    .line 1887
    move-result-object v1

    .line 1888
    if-eqz v1, :cond_56

    .line 1889
    .line 1890
    invoke-virtual {v15}, Landroid/util/SparseArray;->size()I

    .line 1891
    .line 1892
    .line 1893
    move-result v2

    .line 1894
    move v5, v8

    .line 1895
    :goto_3c
    if-ge v5, v2, :cond_56

    .line 1896
    .line 1897
    invoke-virtual {v15, v5}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 1898
    .line 1899
    .line 1900
    move-result-object v3

    .line 1901
    check-cast v3, Li9/i;

    .line 1902
    .line 1903
    iget-object v4, v3, Li9/i;->d:Li9/t;

    .line 1904
    .line 1905
    iget-object v4, v4, Li9/t;->a:Li9/q;

    .line 1906
    .line 1907
    iget-object v7, v3, Li9/i;->b:Li9/s;

    .line 1908
    .line 1909
    iget-object v7, v7, Li9/s;->a:Li9/f;

    .line 1910
    .line 1911
    sget-object v9, Lw7/w;->a:Ljava/lang/String;

    .line 1912
    .line 1913
    iget v7, v7, Li9/f;->a:I

    .line 1914
    .line 1915
    iget-object v4, v4, Li9/q;->l:[Li9/r;

    .line 1916
    .line 1917
    aget-object v4, v4, v7

    .line 1918
    .line 1919
    if-eqz v4, :cond_55

    .line 1920
    .line 1921
    iget-object v4, v4, Li9/r;->b:Ljava/lang/String;

    .line 1922
    .line 1923
    goto :goto_3d

    .line 1924
    :cond_55
    move-object v4, v6

    .line 1925
    :goto_3d
    invoke-virtual {v1, v4}, Lt7/k;->a(Ljava/lang/String;)Lt7/k;

    .line 1926
    .line 1927
    .line 1928
    move-result-object v4

    .line 1929
    iget-object v7, v3, Li9/i;->j:Lt7/o;

    .line 1930
    .line 1931
    invoke-virtual {v7}, Lt7/o;->a()Lt7/n;

    .line 1932
    .line 1933
    .line 1934
    move-result-object v7

    .line 1935
    iput-object v4, v7, Lt7/n;->q:Lt7/k;

    .line 1936
    .line 1937
    new-instance v4, Lt7/o;

    .line 1938
    .line 1939
    invoke-direct {v4, v7}, Lt7/o;-><init>(Lt7/n;)V

    .line 1940
    .line 1941
    .line 1942
    iget-object v3, v3, Li9/i;->a:Lo8/i0;

    .line 1943
    .line 1944
    invoke-interface {v3, v4}, Lo8/i0;->c(Lt7/o;)V

    .line 1945
    .line 1946
    .line 1947
    add-int/lit8 v5, v5, 0x1

    .line 1948
    .line 1949
    goto :goto_3c

    .line 1950
    :cond_56
    iget-wide v1, v0, Li9/j;->x:J

    .line 1951
    .line 1952
    cmp-long v1, v1, v21

    .line 1953
    .line 1954
    if-eqz v1, :cond_0

    .line 1955
    .line 1956
    invoke-virtual {v15}, Landroid/util/SparseArray;->size()I

    .line 1957
    .line 1958
    .line 1959
    move-result v1

    .line 1960
    move v11, v8

    .line 1961
    :goto_3e
    if-ge v11, v1, :cond_59

    .line 1962
    .line 1963
    invoke-virtual {v15, v11}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 1964
    .line 1965
    .line 1966
    move-result-object v2

    .line 1967
    check-cast v2, Li9/i;

    .line 1968
    .line 1969
    iget-wide v3, v0, Li9/j;->x:J

    .line 1970
    .line 1971
    iget v5, v2, Li9/i;->f:I

    .line 1972
    .line 1973
    :goto_3f
    iget-object v6, v2, Li9/i;->b:Li9/s;

    .line 1974
    .line 1975
    iget v7, v6, Li9/s;->e:I

    .line 1976
    .line 1977
    if-ge v5, v7, :cond_58

    .line 1978
    .line 1979
    iget-object v7, v6, Li9/s;->i:[J

    .line 1980
    .line 1981
    aget-wide v7, v7, v5

    .line 1982
    .line 1983
    cmp-long v7, v7, v3

    .line 1984
    .line 1985
    if-gtz v7, :cond_58

    .line 1986
    .line 1987
    iget-object v6, v6, Li9/s;->j:[Z

    .line 1988
    .line 1989
    aget-boolean v6, v6, v5

    .line 1990
    .line 1991
    if-eqz v6, :cond_57

    .line 1992
    .line 1993
    iput v5, v2, Li9/i;->i:I

    .line 1994
    .line 1995
    :cond_57
    add-int/lit8 v5, v5, 0x1

    .line 1996
    .line 1997
    goto :goto_3f

    .line 1998
    :cond_58
    add-int/lit8 v11, v11, 0x1

    .line 1999
    .line 2000
    goto :goto_3e

    .line 2001
    :cond_59
    move-wide/from16 v2, v21

    .line 2002
    .line 2003
    iput-wide v2, v0, Li9/j;->x:J

    .line 2004
    .line 2005
    goto/16 :goto_0

    .line 2006
    .line 2007
    :cond_5a
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 2008
    .line 2009
    .line 2010
    move-result v2

    .line 2011
    if-nez v2, :cond_0

    .line 2012
    .line 2013
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 2014
    .line 2015
    .line 2016
    move-result-object v1

    .line 2017
    check-cast v1, Lx7/c;

    .line 2018
    .line 2019
    iget-object v1, v1, Lx7/c;->h:Ljava/util/ArrayList;

    .line 2020
    .line 2021
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2022
    .line 2023
    .line 2024
    goto/16 :goto_0

    .line 2025
    .line 2026
    :cond_5b
    invoke-virtual {v0}, Li9/j;->e()V

    .line 2027
    .line 2028
    .line 2029
    return-void
.end method
