.class public final synthetic Ld00/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc00/n0;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lc00/n0;Lay0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Ld00/n;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ld00/n;->e:Lc00/n0;

    .line 4
    .line 5
    iput-object p2, p0, Ld00/n;->f:Lay0/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld00/n;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    const-string v4, "$this$item"

    .line 25
    .line 26
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v1, v3, 0x11

    .line 30
    .line 31
    const/16 v4, 0x10

    .line 32
    .line 33
    const/4 v5, 0x1

    .line 34
    const/4 v6, 0x0

    .line 35
    if-eq v1, v4, :cond_0

    .line 36
    .line 37
    move v1, v5

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move v1, v6

    .line 40
    :goto_0
    and-int/2addr v3, v5

    .line 41
    check-cast v2, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_2

    .line 48
    .line 49
    new-instance v7, Li91/c2;

    .line 50
    .line 51
    const v1, 0x7f1200c9

    .line 52
    .line 53
    .line 54
    invoke-static {v2, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v8

    .line 58
    iget-object v1, v0, Ld00/n;->e:Lc00/n0;

    .line 59
    .line 60
    iget v3, v1, Lc00/n0;->i:I

    .line 61
    .line 62
    invoke-static {v2, v3}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v9

    .line 66
    iget-boolean v1, v1, Lc00/n0;->g:Z

    .line 67
    .line 68
    if-eqz v1, :cond_1

    .line 69
    .line 70
    new-instance v1, Li91/u1;

    .line 71
    .line 72
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 73
    .line 74
    .line 75
    :goto_1
    move-object v11, v1

    .line 76
    goto :goto_2

    .line 77
    :cond_1
    new-instance v1, Li91/p1;

    .line 78
    .line 79
    const v3, 0x7f08033b

    .line 80
    .line 81
    .line 82
    invoke-direct {v1, v3}, Li91/p1;-><init>(I)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :goto_2
    const/4 v15, 0x0

    .line 87
    const/16 v17, 0x7f4

    .line 88
    .line 89
    const/4 v10, 0x0

    .line 90
    const/4 v12, 0x0

    .line 91
    const/4 v13, 0x0

    .line 92
    const/4 v14, 0x0

    .line 93
    iget-object v0, v0, Ld00/n;->f:Lay0/a;

    .line 94
    .line 95
    move-object/from16 v16, v0

    .line 96
    .line 97
    invoke-direct/range {v7 .. v17}, Li91/c2;-><init>(Ljava/lang/String;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Ljava/lang/String;Ljava/lang/String;Lay0/a;I)V

    .line 98
    .line 99
    .line 100
    invoke-static {v7, v2, v6}, Ld00/o;->w(Li91/d2;Ll2/o;I)V

    .line 101
    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_2
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 105
    .line 106
    .line 107
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    return-object v0

    .line 110
    :pswitch_0
    move-object/from16 v1, p1

    .line 111
    .line 112
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 113
    .line 114
    move-object/from16 v2, p2

    .line 115
    .line 116
    check-cast v2, Ll2/o;

    .line 117
    .line 118
    move-object/from16 v3, p3

    .line 119
    .line 120
    check-cast v3, Ljava/lang/Integer;

    .line 121
    .line 122
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    const-string v4, "$this$item"

    .line 127
    .line 128
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    and-int/lit8 v1, v3, 0x11

    .line 132
    .line 133
    const/16 v4, 0x10

    .line 134
    .line 135
    const/4 v5, 0x0

    .line 136
    const/4 v6, 0x1

    .line 137
    if-eq v1, v4, :cond_3

    .line 138
    .line 139
    move v1, v6

    .line 140
    goto :goto_4

    .line 141
    :cond_3
    move v1, v5

    .line 142
    :goto_4
    and-int/2addr v3, v6

    .line 143
    check-cast v2, Ll2/t;

    .line 144
    .line 145
    invoke-virtual {v2, v3, v1}, Ll2/t;->O(IZ)Z

    .line 146
    .line 147
    .line 148
    move-result v1

    .line 149
    if-eqz v1, :cond_5

    .line 150
    .line 151
    const v1, 0x7f1200b3

    .line 152
    .line 153
    .line 154
    invoke-static {v2, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v8

    .line 158
    const v1, 0x7f1200b2

    .line 159
    .line 160
    .line 161
    invoke-static {v2, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v9

    .line 165
    iget-object v1, v0, Ld00/n;->e:Lc00/n0;

    .line 166
    .line 167
    iget-object v3, v1, Lc00/n0;->a:Ljava/lang/Boolean;

    .line 168
    .line 169
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 170
    .line 171
    .line 172
    move-result v3

    .line 173
    iget-boolean v4, v1, Lc00/n0;->e:Z

    .line 174
    .line 175
    iget-boolean v1, v1, Lc00/n0;->h:Z

    .line 176
    .line 177
    xor-int/lit8 v12, v1, 0x1

    .line 178
    .line 179
    iget-object v0, v0, Ld00/n;->f:Lay0/a;

    .line 180
    .line 181
    if-eqz v4, :cond_4

    .line 182
    .line 183
    new-instance v1, Li91/u1;

    .line 184
    .line 185
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 186
    .line 187
    .line 188
    :goto_5
    move-object v11, v1

    .line 189
    goto :goto_6

    .line 190
    :cond_4
    new-instance v1, Li91/y1;

    .line 191
    .line 192
    new-instance v4, Laj0/c;

    .line 193
    .line 194
    const/16 v6, 0xa

    .line 195
    .line 196
    invoke-direct {v4, v0, v6}, Laj0/c;-><init>(Lay0/a;I)V

    .line 197
    .line 198
    .line 199
    const/4 v6, 0x0

    .line 200
    invoke-direct {v1, v3, v4, v6}, Li91/y1;-><init>(ZLay0/k;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    goto :goto_5

    .line 204
    :goto_6
    new-instance v7, Li91/c2;

    .line 205
    .line 206
    const/4 v15, 0x0

    .line 207
    const/16 v17, 0x7e4

    .line 208
    .line 209
    const/4 v10, 0x0

    .line 210
    const/4 v13, 0x0

    .line 211
    const/4 v14, 0x0

    .line 212
    move-object/from16 v16, v0

    .line 213
    .line 214
    invoke-direct/range {v7 .. v17}, Li91/c2;-><init>(Ljava/lang/String;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Ljava/lang/String;Ljava/lang/String;Lay0/a;I)V

    .line 215
    .line 216
    .line 217
    invoke-static {v7, v2, v5}, Ld00/o;->w(Li91/d2;Ll2/o;I)V

    .line 218
    .line 219
    .line 220
    goto :goto_7

    .line 221
    :cond_5
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 222
    .line 223
    .line 224
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 225
    .line 226
    return-object v0

    .line 227
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
