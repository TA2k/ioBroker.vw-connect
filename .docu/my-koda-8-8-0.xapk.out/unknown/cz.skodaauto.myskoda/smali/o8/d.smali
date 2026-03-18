.class public final Lo8/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public final b:I

.field public final c:I

.field public final d:I

.field public final e:I

.field public final f:I

.field public final g:I

.field public final h:I

.field public final i:I

.field public final j:I

.field public final k:F

.field public final l:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;IIIIIIIIIFLjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo8/d;->a:Ljava/util/ArrayList;

    .line 5
    .line 6
    iput p2, p0, Lo8/d;->b:I

    .line 7
    .line 8
    iput p3, p0, Lo8/d;->c:I

    .line 9
    .line 10
    iput p4, p0, Lo8/d;->d:I

    .line 11
    .line 12
    iput p5, p0, Lo8/d;->e:I

    .line 13
    .line 14
    iput p6, p0, Lo8/d;->f:I

    .line 15
    .line 16
    iput p7, p0, Lo8/d;->g:I

    .line 17
    .line 18
    iput p8, p0, Lo8/d;->h:I

    .line 19
    .line 20
    iput p9, p0, Lo8/d;->i:I

    .line 21
    .line 22
    iput p10, p0, Lo8/d;->j:I

    .line 23
    .line 24
    iput p11, p0, Lo8/d;->k:F

    .line 25
    .line 26
    iput-object p12, p0, Lo8/d;->l:Ljava/lang/String;

    .line 27
    .line 28
    return-void
.end method

.method public static a(Lw7/p;)Lo8/d;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    :try_start_0
    invoke-virtual {v0, v1}, Lw7/p;->J(I)V

    .line 5
    .line 6
    .line 7
    invoke-virtual {v0}, Lw7/p;->w()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/4 v3, 0x3

    .line 12
    and-int/2addr v2, v3

    .line 13
    add-int/lit8 v6, v2, 0x1

    .line 14
    .line 15
    if-eq v6, v3, :cond_3

    .line 16
    .line 17
    new-instance v5, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Lw7/p;->w()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    and-int/lit8 v2, v2, 0x1f

    .line 27
    .line 28
    const/4 v3, 0x0

    .line 29
    move v4, v3

    .line 30
    :goto_0
    if-ge v4, v2, :cond_0

    .line 31
    .line 32
    invoke-virtual {v0}, Lw7/p;->C()I

    .line 33
    .line 34
    .line 35
    move-result v7

    .line 36
    iget v8, v0, Lw7/p;->b:I

    .line 37
    .line 38
    invoke-virtual {v0, v7}, Lw7/p;->J(I)V

    .line 39
    .line 40
    .line 41
    iget-object v9, v0, Lw7/p;->a:[B

    .line 42
    .line 43
    sget-object v10, Lw7/c;->a:[B

    .line 44
    .line 45
    add-int/lit8 v11, v7, 0x4

    .line 46
    .line 47
    new-array v11, v11, [B

    .line 48
    .line 49
    invoke-static {v10, v3, v11, v3, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 50
    .line 51
    .line 52
    invoke-static {v9, v8, v11, v1, v7}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v5, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    add-int/lit8 v4, v4, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    invoke-virtual {v0}, Lw7/p;->w()I

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    move v7, v3

    .line 66
    :goto_1
    if-ge v7, v4, :cond_1

    .line 67
    .line 68
    invoke-virtual {v0}, Lw7/p;->C()I

    .line 69
    .line 70
    .line 71
    move-result v8

    .line 72
    iget v9, v0, Lw7/p;->b:I

    .line 73
    .line 74
    invoke-virtual {v0, v8}, Lw7/p;->J(I)V

    .line 75
    .line 76
    .line 77
    iget-object v10, v0, Lw7/p;->a:[B

    .line 78
    .line 79
    sget-object v11, Lw7/c;->a:[B

    .line 80
    .line 81
    add-int/lit8 v12, v8, 0x4

    .line 82
    .line 83
    new-array v12, v12, [B

    .line 84
    .line 85
    invoke-static {v11, v3, v12, v3, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 86
    .line 87
    .line 88
    invoke-static {v10, v9, v12, v1, v8}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v5, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    add-int/lit8 v7, v7, 0x1

    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_1
    if-lez v2, :cond_2

    .line 98
    .line 99
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v0

    .line 103
    check-cast v0, [B

    .line 104
    .line 105
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    check-cast v2, [B

    .line 110
    .line 111
    array-length v0, v0

    .line 112
    invoke-static {v2, v1, v0}, Lx7/n;->j([BII)Lx7/m;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    iget v1, v0, Lx7/m;->e:I

    .line 117
    .line 118
    iget v2, v0, Lx7/m;->f:I

    .line 119
    .line 120
    iget v3, v0, Lx7/m;->h:I

    .line 121
    .line 122
    add-int/lit8 v3, v3, 0x8

    .line 123
    .line 124
    iget v4, v0, Lx7/m;->i:I

    .line 125
    .line 126
    add-int/lit8 v4, v4, 0x8

    .line 127
    .line 128
    iget v7, v0, Lx7/m;->p:I

    .line 129
    .line 130
    iget v8, v0, Lx7/m;->q:I

    .line 131
    .line 132
    iget v9, v0, Lx7/m;->r:I

    .line 133
    .line 134
    iget v10, v0, Lx7/m;->s:I

    .line 135
    .line 136
    iget v11, v0, Lx7/m;->g:F

    .line 137
    .line 138
    iget v12, v0, Lx7/m;->a:I

    .line 139
    .line 140
    iget v13, v0, Lx7/m;->b:I

    .line 141
    .line 142
    iget v0, v0, Lx7/m;->c:I

    .line 143
    .line 144
    sget-object v14, Lw7/c;->a:[B

    .line 145
    .line 146
    const-string v14, "avc1.%02X%02X%02X"

    .line 147
    .line 148
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 149
    .line 150
    .line 151
    move-result-object v12

    .line 152
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 153
    .line 154
    .line 155
    move-result-object v13

    .line 156
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    filled-new-array {v12, v13, v0}, [Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    invoke-static {v14, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    move v12, v8

    .line 169
    move v13, v9

    .line 170
    move v14, v10

    .line 171
    move v15, v11

    .line 172
    move v8, v2

    .line 173
    move v9, v3

    .line 174
    move v10, v4

    .line 175
    move v11, v7

    .line 176
    move v7, v1

    .line 177
    :goto_2
    move-object/from16 v16, v0

    .line 178
    .line 179
    goto :goto_3

    .line 180
    :cond_2
    const/4 v1, -0x1

    .line 181
    const/high16 v11, 0x3f800000    # 1.0f

    .line 182
    .line 183
    const/4 v0, 0x0

    .line 184
    const/16 v10, 0x10

    .line 185
    .line 186
    move v7, v1

    .line 187
    move v8, v7

    .line 188
    move v9, v8

    .line 189
    move v12, v9

    .line 190
    move v13, v12

    .line 191
    move v14, v10

    .line 192
    move v15, v11

    .line 193
    move v10, v13

    .line 194
    move v11, v10

    .line 195
    goto :goto_2

    .line 196
    :goto_3
    new-instance v4, Lo8/d;

    .line 197
    .line 198
    invoke-direct/range {v4 .. v16}, Lo8/d;-><init>(Ljava/util/ArrayList;IIIIIIIIIFLjava/lang/String;)V

    .line 199
    .line 200
    .line 201
    return-object v4

    .line 202
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 203
    .line 204
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 205
    .line 206
    .line 207
    throw v0
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 208
    :catch_0
    move-exception v0

    .line 209
    const-string v1, "Error parsing AVC config"

    .line 210
    .line 211
    invoke-static {v0, v1}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 212
    .line 213
    .line 214
    move-result-object v0

    .line 215
    throw v0
.end method
