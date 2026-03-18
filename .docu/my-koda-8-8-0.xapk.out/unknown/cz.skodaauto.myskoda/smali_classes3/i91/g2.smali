.class public final synthetic Li91/g2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Li91/v1;Ljava/lang/String;JLjava/lang/String;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Li91/g2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/g2;->f:Ljava/lang/Object;

    iput-object p2, p0, Li91/g2;->g:Ljava/lang/Object;

    iput-wide p3, p0, Li91/g2;->e:J

    iput-object p5, p0, Li91/g2;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lz4/k;Lvf0/j;JLz4/f;I)V
    .locals 0

    .line 2
    const/4 p6, 0x1

    iput p6, p0, Li91/g2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/g2;->f:Ljava/lang/Object;

    iput-object p2, p0, Li91/g2;->g:Ljava/lang/Object;

    iput-wide p3, p0, Li91/g2;->e:J

    iput-object p5, p0, Li91/g2;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li91/g2;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Li91/g2;->f:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Lz4/k;

    .line 12
    .line 13
    iget-object v1, v0, Li91/g2;->g:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, v1

    .line 16
    check-cast v3, Lvf0/j;

    .line 17
    .line 18
    iget-object v1, v0, Li91/g2;->h:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v6, v1

    .line 21
    check-cast v6, Lz4/f;

    .line 22
    .line 23
    move-object/from16 v7, p1

    .line 24
    .line 25
    check-cast v7, Ll2/o;

    .line 26
    .line 27
    move-object/from16 v1, p2

    .line 28
    .line 29
    check-cast v1, Ljava/lang/Integer;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const/16 v1, 0x9

    .line 35
    .line 36
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 37
    .line 38
    .line 39
    move-result v8

    .line 40
    iget-wide v4, v0, Li91/g2;->e:J

    .line 41
    .line 42
    invoke-static/range {v2 .. v8}, Lxf0/y1;->s(Lz4/k;Lvf0/j;JLz4/f;Ll2/o;I)V

    .line 43
    .line 44
    .line 45
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    return-object v0

    .line 48
    :pswitch_0
    iget-object v1, v0, Li91/g2;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v1, Li91/v1;

    .line 51
    .line 52
    iget-object v2, v0, Li91/g2;->g:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v2, Ljava/lang/String;

    .line 55
    .line 56
    iget-object v3, v0, Li91/g2;->h:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v3, Ljava/lang/String;

    .line 59
    .line 60
    move-object/from16 v4, p1

    .line 61
    .line 62
    check-cast v4, Ll2/o;

    .line 63
    .line 64
    move-object/from16 v5, p2

    .line 65
    .line 66
    check-cast v5, Ljava/lang/Integer;

    .line 67
    .line 68
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 69
    .line 70
    .line 71
    move-result v5

    .line 72
    and-int/lit8 v6, v5, 0x3

    .line 73
    .line 74
    const/4 v7, 0x2

    .line 75
    const/4 v8, 0x1

    .line 76
    const/4 v9, 0x0

    .line 77
    if-eq v6, v7, :cond_0

    .line 78
    .line 79
    move v6, v8

    .line 80
    goto :goto_0

    .line 81
    :cond_0
    move v6, v9

    .line 82
    :goto_0
    and-int/2addr v5, v8

    .line 83
    move-object v15, v4

    .line 84
    check-cast v15, Ll2/t;

    .line 85
    .line 86
    invoke-virtual {v15, v5, v6}, Ll2/t;->O(IZ)Z

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    if-eqz v4, :cond_1

    .line 91
    .line 92
    check-cast v1, Li91/z1;

    .line 93
    .line 94
    iget-object v10, v1, Li91/z1;->a:Lg4/g;

    .line 95
    .line 96
    sget-object v4, Lj91/j;->a:Ll2/u2;

    .line 97
    .line 98
    invoke-virtual {v15, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    check-cast v4, Lj91/f;

    .line 103
    .line 104
    invoke-virtual {v4}, Lj91/f;->a()Lg4/p0;

    .line 105
    .line 106
    .line 107
    move-result-object v12

    .line 108
    sget-object v4, Lx2/c;->g:Lx2/j;

    .line 109
    .line 110
    sget-object v5, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 111
    .line 112
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 113
    .line 114
    invoke-virtual {v5, v6, v4}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 115
    .line 116
    .line 117
    move-result-object v16

    .line 118
    const/16 v4, 0x20

    .line 119
    .line 120
    int-to-float v4, v4

    .line 121
    const/16 v20, 0x0

    .line 122
    .line 123
    const/16 v21, 0xb

    .line 124
    .line 125
    const/16 v17, 0x0

    .line 126
    .line 127
    const/16 v18, 0x0

    .line 128
    .line 129
    move/from16 v19, v4

    .line 130
    .line 131
    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 132
    .line 133
    .line 134
    move-result-object v4

    .line 135
    invoke-static {v4, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 136
    .line 137
    .line 138
    move-result-object v11

    .line 139
    const/16 v28, 0x6180

    .line 140
    .line 141
    const v29, 0xaff0

    .line 142
    .line 143
    .line 144
    iget-wide v13, v0, Li91/g2;->e:J

    .line 145
    .line 146
    move-object/from16 v26, v15

    .line 147
    .line 148
    const-wide/16 v15, 0x0

    .line 149
    .line 150
    const-wide/16 v17, 0x0

    .line 151
    .line 152
    const/16 v19, 0x0

    .line 153
    .line 154
    const-wide/16 v20, 0x0

    .line 155
    .line 156
    const/16 v22, 0x2

    .line 157
    .line 158
    const/16 v23, 0x0

    .line 159
    .line 160
    const/16 v24, 0x1

    .line 161
    .line 162
    const/16 v25, 0x0

    .line 163
    .line 164
    const/16 v27, 0x0

    .line 165
    .line 166
    invoke-static/range {v10 .. v29}, Li91/z3;->c(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;III)V

    .line 167
    .line 168
    .line 169
    move-object/from16 v15, v26

    .line 170
    .line 171
    invoke-static {v6, v3}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 172
    .line 173
    .line 174
    move-result-object v12

    .line 175
    iget v0, v1, Li91/z1;->b:I

    .line 176
    .line 177
    invoke-static {v0, v9, v15}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 178
    .line 179
    .line 180
    move-result-object v10

    .line 181
    const/16 v16, 0x30

    .line 182
    .line 183
    const/16 v17, 0x0

    .line 184
    .line 185
    const-string v11, ""

    .line 186
    .line 187
    invoke-static/range {v10 .. v17}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 188
    .line 189
    .line 190
    goto :goto_1

    .line 191
    :cond_1
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 192
    .line 193
    .line 194
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 195
    .line 196
    return-object v0

    .line 197
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
