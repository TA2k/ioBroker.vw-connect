.class public final synthetic La71/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Z

.field public final synthetic h:Z

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;

.field public final synthetic l:Ljava/lang/Object;

.field public final synthetic m:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Li91/h1;Lx2/s;Lay0/a;ZLe1/t;Lk1/a1;ZLjava/lang/String;Ljava/lang/Integer;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, La71/x;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La71/x;->i:Ljava/lang/Object;

    iput-object p2, p0, La71/x;->e:Lx2/s;

    iput-object p3, p0, La71/x;->f:Lay0/a;

    iput-boolean p4, p0, La71/x;->g:Z

    iput-object p5, p0, La71/x;->j:Ljava/lang/Object;

    iput-object p6, p0, La71/x;->k:Ljava/lang/Object;

    iput-boolean p7, p0, La71/x;->h:Z

    iput-object p8, p0, La71/x;->l:Ljava/lang/Object;

    iput-object p9, p0, La71/x;->m:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lx2/s;Ls71/h;ZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p10, 0x0

    iput p10, p0, La71/x;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La71/x;->e:Lx2/s;

    iput-object p2, p0, La71/x;->i:Ljava/lang/Object;

    iput-boolean p3, p0, La71/x;->g:Z

    iput-boolean p4, p0, La71/x;->h:Z

    iput-object p5, p0, La71/x;->f:Lay0/a;

    iput-object p6, p0, La71/x;->j:Ljava/lang/Object;

    iput-object p7, p0, La71/x;->k:Ljava/lang/Object;

    iput-object p8, p0, La71/x;->l:Ljava/lang/Object;

    iput-object p9, p0, La71/x;->m:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, La71/x;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, La71/x;->i:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v7, v1

    .line 11
    check-cast v7, Li91/h1;

    .line 12
    .line 13
    iget-object v1, v0, La71/x;->j:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v14, v1

    .line 16
    check-cast v14, Le1/t;

    .line 17
    .line 18
    iget-object v1, v0, La71/x;->k:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v15, v1

    .line 21
    check-cast v15, Lk1/a1;

    .line 22
    .line 23
    iget-object v1, v0, La71/x;->l:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v4, v1

    .line 26
    check-cast v4, Ljava/lang/String;

    .line 27
    .line 28
    iget-object v1, v0, La71/x;->m:Ljava/lang/Object;

    .line 29
    .line 30
    move-object v5, v1

    .line 31
    check-cast v5, Ljava/lang/Integer;

    .line 32
    .line 33
    move-object/from16 v1, p1

    .line 34
    .line 35
    check-cast v1, Ll2/o;

    .line 36
    .line 37
    move-object/from16 v2, p2

    .line 38
    .line 39
    check-cast v2, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    and-int/lit8 v3, v2, 0x3

    .line 46
    .line 47
    const/4 v6, 0x2

    .line 48
    const/4 v8, 0x0

    .line 49
    const/4 v9, 0x1

    .line 50
    if-eq v3, v6, :cond_0

    .line 51
    .line 52
    move v3, v9

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    move v3, v8

    .line 55
    :goto_0
    and-int/2addr v2, v9

    .line 56
    check-cast v1, Ll2/t;

    .line 57
    .line 58
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_1

    .line 63
    .line 64
    sget-object v11, Ls1/f;->a:Ls1/e;

    .line 65
    .line 66
    int-to-float v2, v8

    .line 67
    const/16 v21, 0x0

    .line 68
    .line 69
    move/from16 v17, v2

    .line 70
    .line 71
    move/from16 v18, v2

    .line 72
    .line 73
    move/from16 v19, v2

    .line 74
    .line 75
    move/from16 v20, v2

    .line 76
    .line 77
    move/from16 v16, v2

    .line 78
    .line 79
    invoke-static/range {v16 .. v21}, Lh2/o0;->b(FFFFFI)Lh2/q0;

    .line 80
    .line 81
    .line 82
    move-result-object v13

    .line 83
    invoke-virtual {v7, v1}, Li91/h1;->a(Ll2/o;)Lh2/n0;

    .line 84
    .line 85
    .line 86
    move-result-object v12

    .line 87
    const/16 v2, 0x20

    .line 88
    .line 89
    int-to-float v2, v2

    .line 90
    iget-object v3, v0, La71/x;->e:Lx2/s;

    .line 91
    .line 92
    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/d;->i(Lx2/s;F)Lx2/s;

    .line 93
    .line 94
    .line 95
    move-result-object v9

    .line 96
    new-instance v2, Li91/k;

    .line 97
    .line 98
    iget-boolean v3, v0, La71/x;->h:Z

    .line 99
    .line 100
    iget-boolean v6, v0, La71/x;->g:Z

    .line 101
    .line 102
    invoke-direct/range {v2 .. v7}, Li91/k;-><init>(ZLjava/lang/String;Ljava/lang/Integer;ZLi91/h1;)V

    .line 103
    .line 104
    .line 105
    const v3, -0x5e146104

    .line 106
    .line 107
    .line 108
    invoke-static {v3, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 109
    .line 110
    .line 111
    move-result-object v16

    .line 112
    const/high16 v18, 0x30000000

    .line 113
    .line 114
    const/16 v19, 0x100

    .line 115
    .line 116
    iget-object v8, v0, La71/x;->f:Lay0/a;

    .line 117
    .line 118
    move-object/from16 v17, v1

    .line 119
    .line 120
    move v10, v6

    .line 121
    invoke-static/range {v8 .. v19}, Lh2/r;->d(Lay0/a;Lx2/s;ZLe3/n0;Lh2/n0;Lh2/q0;Le1/t;Lk1/z0;Lt2/b;Ll2/o;II)V

    .line 122
    .line 123
    .line 124
    goto :goto_1

    .line 125
    :cond_1
    move-object/from16 v17, v1

    .line 126
    .line 127
    invoke-virtual/range {v17 .. v17}, Ll2/t;->R()V

    .line 128
    .line 129
    .line 130
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 131
    .line 132
    return-object v0

    .line 133
    :pswitch_0
    iget-object v1, v0, La71/x;->i:Ljava/lang/Object;

    .line 134
    .line 135
    move-object v3, v1

    .line 136
    check-cast v3, Ls71/h;

    .line 137
    .line 138
    iget-object v1, v0, La71/x;->j:Ljava/lang/Object;

    .line 139
    .line 140
    move-object v7, v1

    .line 141
    check-cast v7, Lay0/a;

    .line 142
    .line 143
    iget-object v1, v0, La71/x;->k:Ljava/lang/Object;

    .line 144
    .line 145
    move-object v8, v1

    .line 146
    check-cast v8, Lay0/a;

    .line 147
    .line 148
    iget-object v1, v0, La71/x;->l:Ljava/lang/Object;

    .line 149
    .line 150
    move-object v9, v1

    .line 151
    check-cast v9, Lay0/a;

    .line 152
    .line 153
    iget-object v1, v0, La71/x;->m:Ljava/lang/Object;

    .line 154
    .line 155
    move-object v10, v1

    .line 156
    check-cast v10, Lay0/a;

    .line 157
    .line 158
    move-object/from16 v11, p1

    .line 159
    .line 160
    check-cast v11, Ll2/o;

    .line 161
    .line 162
    move-object/from16 v1, p2

    .line 163
    .line 164
    check-cast v1, Ljava/lang/Integer;

    .line 165
    .line 166
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 167
    .line 168
    .line 169
    const/4 v1, 0x1

    .line 170
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 171
    .line 172
    .line 173
    move-result v12

    .line 174
    iget-object v2, v0, La71/x;->e:Lx2/s;

    .line 175
    .line 176
    iget-boolean v4, v0, La71/x;->g:Z

    .line 177
    .line 178
    iget-boolean v5, v0, La71/x;->h:Z

    .line 179
    .line 180
    iget-object v6, v0, La71/x;->f:Lay0/a;

    .line 181
    .line 182
    invoke-static/range {v2 .. v12}, La71/b;->j(Lx2/s;Ls71/h;ZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 183
    .line 184
    .line 185
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 186
    .line 187
    return-object v0

    .line 188
    nop

    .line 189
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
