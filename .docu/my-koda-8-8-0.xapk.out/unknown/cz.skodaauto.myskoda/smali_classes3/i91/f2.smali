.class public final synthetic Li91/f2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:J


# direct methods
.method public synthetic constructor <init>(Le2/l;Lx2/s;JI)V
    .locals 0

    .line 1
    const/4 p5, 0x2

    iput p5, p0, Li91/f2;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li91/f2;->e:Ljava/lang/Object;

    iput-object p2, p0, Li91/f2;->f:Ljava/lang/Object;

    iput-wide p3, p0, Li91/f2;->g:J

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Li91/v1;JI)V
    .locals 0

    .line 2
    iput p5, p0, Li91/f2;->d:I

    iput-object p1, p0, Li91/f2;->e:Ljava/lang/Object;

    iput-object p2, p0, Li91/f2;->f:Ljava/lang/Object;

    iput-wide p3, p0, Li91/f2;->g:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li91/f2;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Li91/f2;->e:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Le2/l;

    .line 12
    .line 13
    iget-object v1, v0, Li91/f2;->f:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, v1

    .line 16
    check-cast v3, Lx2/s;

    .line 17
    .line 18
    move-object/from16 v6, p1

    .line 19
    .line 20
    check-cast v6, Ll2/o;

    .line 21
    .line 22
    move-object/from16 v1, p2

    .line 23
    .line 24
    check-cast v1, Ljava/lang/Integer;

    .line 25
    .line 26
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 31
    .line 32
    .line 33
    move-result v7

    .line 34
    iget-wide v4, v0, Li91/f2;->g:J

    .line 35
    .line 36
    invoke-static/range {v2 .. v7}, Lt1/b;->a(Le2/l;Lx2/s;JLl2/o;I)V

    .line 37
    .line 38
    .line 39
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object v0

    .line 42
    :pswitch_0
    iget-object v1, v0, Li91/f2;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v1, Ljava/lang/String;

    .line 45
    .line 46
    iget-object v2, v0, Li91/f2;->f:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v2, Li91/v1;

    .line 49
    .line 50
    move-object/from16 v3, p1

    .line 51
    .line 52
    check-cast v3, Ll2/o;

    .line 53
    .line 54
    move-object/from16 v4, p2

    .line 55
    .line 56
    check-cast v4, Ljava/lang/Integer;

    .line 57
    .line 58
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 59
    .line 60
    .line 61
    move-result v4

    .line 62
    and-int/lit8 v5, v4, 0x3

    .line 63
    .line 64
    const/4 v6, 0x2

    .line 65
    const/4 v7, 0x1

    .line 66
    if-eq v5, v6, :cond_0

    .line 67
    .line 68
    move v5, v7

    .line 69
    goto :goto_0

    .line 70
    :cond_0
    const/4 v5, 0x0

    .line 71
    :goto_0
    and-int/2addr v4, v7

    .line 72
    check-cast v3, Ll2/t;

    .line 73
    .line 74
    invoke-virtual {v3, v4, v5}, Ll2/t;->O(IZ)Z

    .line 75
    .line 76
    .line 77
    move-result v4

    .line 78
    if-eqz v4, :cond_1

    .line 79
    .line 80
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 81
    .line 82
    invoke-static {v4, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    check-cast v2, Li91/a2;

    .line 87
    .line 88
    iget-object v6, v2, Li91/a2;->a:Lg4/g;

    .line 89
    .line 90
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 91
    .line 92
    invoke-virtual {v3, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v1

    .line 96
    check-cast v1, Lj91/f;

    .line 97
    .line 98
    invoke-virtual {v1}, Lj91/f;->a()Lg4/p0;

    .line 99
    .line 100
    .line 101
    move-result-object v8

    .line 102
    const/16 v24, 0x6180

    .line 103
    .line 104
    const v25, 0xaff0

    .line 105
    .line 106
    .line 107
    iget-wide v9, v0, Li91/f2;->g:J

    .line 108
    .line 109
    const-wide/16 v11, 0x0

    .line 110
    .line 111
    const-wide/16 v13, 0x0

    .line 112
    .line 113
    const/4 v15, 0x0

    .line 114
    const-wide/16 v16, 0x0

    .line 115
    .line 116
    const/16 v18, 0x2

    .line 117
    .line 118
    const/16 v19, 0x0

    .line 119
    .line 120
    const/16 v20, 0x1

    .line 121
    .line 122
    const/16 v21, 0x0

    .line 123
    .line 124
    const/16 v23, 0x0

    .line 125
    .line 126
    move-object/from16 v22, v3

    .line 127
    .line 128
    invoke-static/range {v6 .. v25}, Li91/z3;->c(Lg4/g;Lx2/s;Lg4/p0;JJJLr4/k;JIZILay0/k;Ll2/o;III)V

    .line 129
    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_1
    move-object/from16 v22, v3

    .line 133
    .line 134
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 135
    .line 136
    .line 137
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 138
    .line 139
    return-object v0

    .line 140
    :pswitch_1
    iget-object v1, v0, Li91/f2;->e:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v1, Ljava/lang/String;

    .line 143
    .line 144
    iget-object v2, v0, Li91/f2;->f:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast v2, Li91/v1;

    .line 147
    .line 148
    move-object/from16 v3, p1

    .line 149
    .line 150
    check-cast v3, Ll2/o;

    .line 151
    .line 152
    move-object/from16 v4, p2

    .line 153
    .line 154
    check-cast v4, Ljava/lang/Integer;

    .line 155
    .line 156
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 157
    .line 158
    .line 159
    move-result v4

    .line 160
    and-int/lit8 v5, v4, 0x3

    .line 161
    .line 162
    const/4 v6, 0x2

    .line 163
    const/4 v7, 0x0

    .line 164
    const/4 v8, 0x1

    .line 165
    if-eq v5, v6, :cond_2

    .line 166
    .line 167
    move v5, v8

    .line 168
    goto :goto_2

    .line 169
    :cond_2
    move v5, v7

    .line 170
    :goto_2
    and-int/2addr v4, v8

    .line 171
    move-object v13, v3

    .line 172
    check-cast v13, Ll2/t;

    .line 173
    .line 174
    invoke-virtual {v13, v4, v5}, Ll2/t;->O(IZ)Z

    .line 175
    .line 176
    .line 177
    move-result v3

    .line 178
    if-eqz v3, :cond_3

    .line 179
    .line 180
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 181
    .line 182
    invoke-static {v3, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 183
    .line 184
    .line 185
    move-result-object v10

    .line 186
    check-cast v2, Li91/p1;

    .line 187
    .line 188
    iget v1, v2, Li91/p1;->a:I

    .line 189
    .line 190
    invoke-static {v1, v7, v13}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 191
    .line 192
    .line 193
    move-result-object v8

    .line 194
    const/16 v14, 0x30

    .line 195
    .line 196
    const/4 v15, 0x0

    .line 197
    const-string v9, ""

    .line 198
    .line 199
    iget-wide v11, v0, Li91/f2;->g:J

    .line 200
    .line 201
    invoke-static/range {v8 .. v15}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 202
    .line 203
    .line 204
    goto :goto_3

    .line 205
    :cond_3
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 206
    .line 207
    .line 208
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 209
    .line 210
    return-object v0

    .line 211
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
