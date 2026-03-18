.class public final synthetic Lxk0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Ljava/util/List;

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Ll2/b1;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxk0/o;->d:Ljava/util/List;

    .line 5
    .line 6
    iput-object p2, p0, Lxk0/o;->e:Ll2/b1;

    .line 7
    .line 8
    iput p3, p0, Lxk0/o;->f:I

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    move-object/from16 v3, p3

    .line 16
    .line 17
    check-cast v3, Ll2/o;

    .line 18
    .line 19
    move-object/from16 v4, p4

    .line 20
    .line 21
    check-cast v4, Ljava/lang/Integer;

    .line 22
    .line 23
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    const-string v5, "$this$items"

    .line 28
    .line 29
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    and-int/lit8 v5, v4, 0x6

    .line 33
    .line 34
    const/4 v6, 0x4

    .line 35
    if-nez v5, :cond_1

    .line 36
    .line 37
    move-object v5, v3

    .line 38
    check-cast v5, Ll2/t;

    .line 39
    .line 40
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    if-eqz v5, :cond_0

    .line 45
    .line 46
    move v5, v6

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    const/4 v5, 0x2

    .line 49
    :goto_0
    or-int/2addr v5, v4

    .line 50
    goto :goto_1

    .line 51
    :cond_1
    move v5, v4

    .line 52
    :goto_1
    and-int/lit8 v4, v4, 0x30

    .line 53
    .line 54
    const/16 v7, 0x20

    .line 55
    .line 56
    if-nez v4, :cond_3

    .line 57
    .line 58
    move-object v4, v3

    .line 59
    check-cast v4, Ll2/t;

    .line 60
    .line 61
    invoke-virtual {v4, v2}, Ll2/t;->e(I)Z

    .line 62
    .line 63
    .line 64
    move-result v4

    .line 65
    if-eqz v4, :cond_2

    .line 66
    .line 67
    move v4, v7

    .line 68
    goto :goto_2

    .line 69
    :cond_2
    const/16 v4, 0x10

    .line 70
    .line 71
    :goto_2
    or-int/2addr v5, v4

    .line 72
    :cond_3
    and-int/lit16 v4, v5, 0x93

    .line 73
    .line 74
    const/16 v8, 0x92

    .line 75
    .line 76
    const/4 v9, 0x0

    .line 77
    const/4 v10, 0x1

    .line 78
    if-eq v4, v8, :cond_4

    .line 79
    .line 80
    move v4, v10

    .line 81
    goto :goto_3

    .line 82
    :cond_4
    move v4, v9

    .line 83
    :goto_3
    and-int/lit8 v8, v5, 0x1

    .line 84
    .line 85
    check-cast v3, Ll2/t;

    .line 86
    .line 87
    invoke-virtual {v3, v8, v4}, Ll2/t;->O(IZ)Z

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    if-eqz v4, :cond_8

    .line 92
    .line 93
    iget-object v4, v0, Lxk0/o;->d:Ljava/util/List;

    .line 94
    .line 95
    invoke-interface {v4, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v4

    .line 99
    move-object v11, v4

    .line 100
    check-cast v11, Landroid/net/Uri;

    .line 101
    .line 102
    sget v4, Lxk0/p;->a:F

    .line 103
    .line 104
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 105
    .line 106
    invoke-static {v8, v4}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 107
    .line 108
    .line 109
    move-result-object v4

    .line 110
    int-to-float v6, v6

    .line 111
    invoke-static {v6}, Ls1/f;->b(F)Ls1/e;

    .line 112
    .line 113
    .line 114
    move-result-object v6

    .line 115
    invoke-static {v4, v6}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    invoke-static {v1, v4}, Landroidx/compose/foundation/lazy/a;->a(Landroidx/compose/foundation/lazy/a;Lx2/s;)Lx2/s;

    .line 120
    .line 121
    .line 122
    move-result-object v12

    .line 123
    and-int/lit8 v1, v5, 0x70

    .line 124
    .line 125
    if-ne v1, v7, :cond_5

    .line 126
    .line 127
    move v9, v10

    .line 128
    :cond_5
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    if-nez v9, :cond_6

    .line 133
    .line 134
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 135
    .line 136
    if-ne v1, v4, :cond_7

    .line 137
    .line 138
    :cond_6
    new-instance v1, Lba0/h;

    .line 139
    .line 140
    const/16 v4, 0xc

    .line 141
    .line 142
    iget-object v5, v0, Lxk0/o;->e:Ll2/b1;

    .line 143
    .line 144
    invoke-direct {v1, v5, v2, v4}, Lba0/h;-><init>(Ljava/lang/Object;II)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {v3, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    :cond_7
    move-object/from16 v16, v1

    .line 151
    .line 152
    check-cast v16, Lay0/a;

    .line 153
    .line 154
    const/16 v17, 0xf

    .line 155
    .line 156
    const/4 v13, 0x0

    .line 157
    const/4 v14, 0x0

    .line 158
    const/4 v15, 0x0

    .line 159
    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    .line 160
    .line 161
    .line 162
    move-result-object v12

    .line 163
    new-instance v1, Ldl0/f;

    .line 164
    .line 165
    const/4 v2, 0x6

    .line 166
    const/4 v4, 0x0

    .line 167
    iget v0, v0, Lxk0/o;->f:I

    .line 168
    .line 169
    invoke-direct {v1, v0, v2, v4}, Ldl0/f;-><init>(IIB)V

    .line 170
    .line 171
    .line 172
    const v0, -0x41bef3e0

    .line 173
    .line 174
    .line 175
    invoke-static {v0, v3, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 176
    .line 177
    .line 178
    move-result-object v20

    .line 179
    const/16 v24, 0xc06

    .line 180
    .line 181
    const/16 v25, 0x5bfc

    .line 182
    .line 183
    const/4 v13, 0x0

    .line 184
    const/16 v16, 0x0

    .line 185
    .line 186
    const/16 v17, 0x0

    .line 187
    .line 188
    sget-object v18, Lt3/j;->a:Lt3/x0;

    .line 189
    .line 190
    const/16 v19, 0x0

    .line 191
    .line 192
    const/16 v21, 0x0

    .line 193
    .line 194
    const/16 v23, 0x0

    .line 195
    .line 196
    move-object/from16 v22, v3

    .line 197
    .line 198
    invoke-static/range {v11 .. v25}, Lxf0/i0;->F(Landroid/net/Uri;Lx2/s;Landroid/graphics/Bitmap;Lay0/a;Lay0/a;Lay0/a;Lx2/e;Lt3/k;Ljava/util/List;Lay0/n;Lay0/n;Ll2/o;III)V

    .line 199
    .line 200
    .line 201
    goto :goto_4

    .line 202
    :cond_8
    move-object/from16 v22, v3

    .line 203
    .line 204
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 205
    .line 206
    .line 207
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 208
    .line 209
    return-object v0
.end method
