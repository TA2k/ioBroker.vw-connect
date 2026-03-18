.class public final Lxf0/c3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:J

.field public final synthetic h:Lvf0/i;

.field public final synthetic i:J

.field public final synthetic j:J


# direct methods
.method public constructor <init>(JJJJLvf0/i;JJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lxf0/c3;->d:J

    .line 5
    .line 6
    iput-wide p3, p0, Lxf0/c3;->e:J

    .line 7
    .line 8
    iput-wide p5, p0, Lxf0/c3;->f:J

    .line 9
    .line 10
    iput-wide p7, p0, Lxf0/c3;->g:J

    .line 11
    .line 12
    iput-object p9, p0, Lxf0/c3;->h:Lvf0/i;

    .line 13
    .line 14
    iput-wide p10, p0, Lxf0/c3;->i:J

    .line 15
    .line 16
    iput-wide p12, p0, Lxf0/c3;->j:J

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lg3/d;

    .line 6
    .line 7
    const-string v2, "$this$Canvas"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {v1}, Lg3/d;->e()J

    .line 13
    .line 14
    .line 15
    move-result-wide v2

    .line 16
    invoke-static {v2, v3}, Ld3/e;->c(J)F

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    sget v13, Lxf0/i3;->c:F

    .line 21
    .line 22
    invoke-interface {v1, v13}, Lt4/c;->w0(F)F

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    new-instance v4, Lxf0/b3;

    .line 27
    .line 28
    iget-wide v7, v0, Lxf0/c3;->i:J

    .line 29
    .line 30
    const/4 v9, 0x0

    .line 31
    iget-object v5, v0, Lxf0/c3;->h:Lvf0/i;

    .line 32
    .line 33
    move v6, v2

    .line 34
    invoke-direct/range {v4 .. v9}, Lxf0/b3;-><init>(Lvf0/i;FJI)V

    .line 35
    .line 36
    .line 37
    move-object v14, v5

    .line 38
    iget-wide v5, v0, Lxf0/c3;->d:J

    .line 39
    .line 40
    move-object v12, v4

    .line 41
    move-wide v4, v5

    .line 42
    iget-wide v6, v0, Lxf0/c3;->e:J

    .line 43
    .line 44
    iget-wide v8, v0, Lxf0/c3;->f:J

    .line 45
    .line 46
    iget-wide v10, v0, Lxf0/c3;->g:J

    .line 47
    .line 48
    invoke-static/range {v1 .. v12}, Lxf0/y1;->t(Lg3/d;FFJJJJLay0/k;)V

    .line 49
    .line 50
    .line 51
    iget-wide v10, v0, Lxf0/c3;->d:J

    .line 52
    .line 53
    iget-wide v3, v0, Lxf0/c3;->e:J

    .line 54
    .line 55
    iget-wide v5, v0, Lxf0/c3;->f:J

    .line 56
    .line 57
    move-wide v15, v10

    .line 58
    iget-wide v10, v0, Lxf0/c3;->g:J

    .line 59
    .line 60
    iget-wide v7, v0, Lxf0/c3;->j:J

    .line 61
    .line 62
    invoke-interface {v1}, Lg3/d;->x0()Lgw0/c;

    .line 63
    .line 64
    .line 65
    move-result-object v12

    .line 66
    move-wide/from16 v17, v10

    .line 67
    .line 68
    invoke-virtual {v12}, Lgw0/c;->o()J

    .line 69
    .line 70
    .line 71
    move-result-wide v9

    .line 72
    invoke-virtual {v12}, Lgw0/c;->h()Le3/r;

    .line 73
    .line 74
    .line 75
    move-result-object v11

    .line 76
    invoke-interface {v11}, Le3/r;->o()V

    .line 77
    .line 78
    .line 79
    :try_start_0
    iget-object v11, v12, Lgw0/c;->e:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v11, Lbu/c;

    .line 82
    .line 83
    move/from16 p1, v2

    .line 84
    .line 85
    iget-object v2, v11, Lbu/c;->e:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v2, Lgw0/c;

    .line 88
    .line 89
    invoke-virtual {v2}, Lgw0/c;->o()J

    .line 90
    .line 91
    .line 92
    move-result-wide v19

    .line 93
    move-wide/from16 v21, v3

    .line 94
    .line 95
    invoke-static/range {v19 .. v20}, Ljp/ef;->d(J)J

    .line 96
    .line 97
    .line 98
    move-result-wide v2

    .line 99
    const/high16 v4, -0x40800000    # -1.0f

    .line 100
    .line 101
    move-wide/from16 v19, v5

    .line 102
    .line 103
    const/high16 v5, 0x3f800000    # 1.0f

    .line 104
    .line 105
    invoke-virtual {v11, v2, v3, v4, v5}, Lbu/c;->A(JFF)V

    .line 106
    .line 107
    .line 108
    invoke-interface {v1, v13}, Lt4/c;->w0(F)F

    .line 109
    .line 110
    .line 111
    move-result v3

    .line 112
    new-instance v4, Lxf0/b3;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 113
    .line 114
    move-wide v5, v9

    .line 115
    const/4 v9, 0x1

    .line 116
    move-wide/from16 v23, v5

    .line 117
    .line 118
    move-object v5, v14

    .line 119
    move-wide/from16 v13, v23

    .line 120
    .line 121
    move/from16 v6, p1

    .line 122
    .line 123
    :try_start_1
    invoke-direct/range {v4 .. v9}, Lxf0/b3;-><init>(Lvf0/i;FJI)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 124
    .line 125
    .line 126
    move-object v2, v12

    .line 127
    move-object v12, v4

    .line 128
    move-wide v4, v15

    .line 129
    move-object v15, v2

    .line 130
    move v2, v6

    .line 131
    move-wide/from16 v10, v17

    .line 132
    .line 133
    move-wide/from16 v8, v19

    .line 134
    .line 135
    move-wide/from16 v6, v21

    .line 136
    .line 137
    :try_start_2
    invoke-static/range {v1 .. v12}, Lxf0/y1;->t(Lg3/d;FFJJJJLay0/k;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 138
    .line 139
    .line 140
    invoke-static {v15, v13, v14}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 141
    .line 142
    .line 143
    sget v2, Lxf0/i3;->d:F

    .line 144
    .line 145
    invoke-interface {v1, v2}, Lt4/c;->w0(F)F

    .line 146
    .line 147
    .line 148
    move-result v3

    .line 149
    invoke-interface {v1}, Lg3/d;->D0()J

    .line 150
    .line 151
    .line 152
    move-result-wide v4

    .line 153
    const/16 v2, 0x20

    .line 154
    .line 155
    shr-long/2addr v4, v2

    .line 156
    long-to-int v4, v4

    .line 157
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 158
    .line 159
    .line 160
    move-result v4

    .line 161
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    int-to-long v4, v4

    .line 166
    const/4 v6, 0x0

    .line 167
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 168
    .line 169
    .line 170
    move-result v6

    .line 171
    int-to-long v6, v6

    .line 172
    shl-long/2addr v4, v2

    .line 173
    const-wide v8, 0xffffffffL

    .line 174
    .line 175
    .line 176
    .line 177
    .line 178
    and-long/2addr v6, v8

    .line 179
    or-long/2addr v4, v6

    .line 180
    const/4 v6, 0x0

    .line 181
    const/16 v7, 0x78

    .line 182
    .line 183
    iget-wide v8, v0, Lxf0/c3;->d:J

    .line 184
    .line 185
    move-object v0, v1

    .line 186
    move-wide v1, v8

    .line 187
    invoke-static/range {v0 .. v7}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 188
    .line 189
    .line 190
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 191
    .line 192
    return-object v0

    .line 193
    :catchall_0
    move-exception v0

    .line 194
    goto :goto_1

    .line 195
    :catchall_1
    move-exception v0

    .line 196
    :goto_0
    move-object v15, v12

    .line 197
    goto :goto_1

    .line 198
    :catchall_2
    move-exception v0

    .line 199
    move-wide v13, v9

    .line 200
    goto :goto_0

    .line 201
    :goto_1
    invoke-static {v15, v13, v14}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 202
    .line 203
    .line 204
    throw v0
.end method
