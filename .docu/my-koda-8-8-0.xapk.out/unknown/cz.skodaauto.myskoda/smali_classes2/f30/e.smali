.class public final synthetic Lf30/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Li91/t1;


# direct methods
.method public synthetic constructor <init>(Li91/t1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lf30/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf30/e;->e:Li91/t1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lf30/e;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v2, p1

    .line 9
    .line 10
    check-cast v2, Li91/k2;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ll2/o;

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
    const-string v4, "$this$MaulBasicListItem"

    .line 25
    .line 26
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    and-int/lit8 v4, v3, 0x6

    .line 30
    .line 31
    if-nez v4, :cond_2

    .line 32
    .line 33
    and-int/lit8 v4, v3, 0x8

    .line 34
    .line 35
    if-nez v4, :cond_0

    .line 36
    .line 37
    move-object v4, v1

    .line 38
    check-cast v4, Ll2/t;

    .line 39
    .line 40
    invoke-virtual {v4, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    goto :goto_0

    .line 45
    :cond_0
    move-object v4, v1

    .line 46
    check-cast v4, Ll2/t;

    .line 47
    .line 48
    invoke-virtual {v4, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    :goto_0
    if-eqz v4, :cond_1

    .line 53
    .line 54
    const/4 v4, 0x4

    .line 55
    goto :goto_1

    .line 56
    :cond_1
    const/4 v4, 0x2

    .line 57
    :goto_1
    or-int/2addr v3, v4

    .line 58
    :cond_2
    and-int/lit8 v4, v3, 0x13

    .line 59
    .line 60
    const/16 v5, 0x12

    .line 61
    .line 62
    if-eq v4, v5, :cond_3

    .line 63
    .line 64
    const/4 v4, 0x1

    .line 65
    goto :goto_2

    .line 66
    :cond_3
    const/4 v4, 0x0

    .line 67
    :goto_2
    and-int/lit8 v5, v3, 0x1

    .line 68
    .line 69
    move-object v8, v1

    .line 70
    check-cast v8, Ll2/t;

    .line 71
    .line 72
    invoke-virtual {v8, v5, v4}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-eqz v1, :cond_4

    .line 77
    .line 78
    move v1, v3

    .line 79
    new-instance v3, Li91/p1;

    .line 80
    .line 81
    const v4, 0x7f08033b

    .line 82
    .line 83
    .line 84
    invoke-direct {v3, v4}, Li91/p1;-><init>(I)V

    .line 85
    .line 86
    .line 87
    iget-object v0, v0, Lf30/e;->e:Li91/t1;

    .line 88
    .line 89
    iget-wide v5, v0, Li91/t1;->e:J

    .line 90
    .line 91
    shl-int/lit8 v0, v1, 0xc

    .line 92
    .line 93
    const v1, 0xe000

    .line 94
    .line 95
    .line 96
    and-int/2addr v0, v1

    .line 97
    const/16 v1, 0xc30

    .line 98
    .line 99
    or-int v9, v1, v0

    .line 100
    .line 101
    const/4 v4, 0x1

    .line 102
    const/4 v7, 0x0

    .line 103
    invoke-virtual/range {v2 .. v9}, Li91/k2;->c(Li91/v1;ZJLjava/lang/String;Ll2/o;I)V

    .line 104
    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_4
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 108
    .line 109
    .line 110
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 111
    .line 112
    return-object v0

    .line 113
    :pswitch_0
    move-object/from16 v1, p1

    .line 114
    .line 115
    check-cast v1, Li91/k2;

    .line 116
    .line 117
    move-object/from16 v2, p2

    .line 118
    .line 119
    check-cast v2, Ll2/o;

    .line 120
    .line 121
    move-object/from16 v3, p3

    .line 122
    .line 123
    check-cast v3, Ljava/lang/Integer;

    .line 124
    .line 125
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 126
    .line 127
    .line 128
    move-result v3

    .line 129
    const-string v4, "$this$MaulBasicListItem"

    .line 130
    .line 131
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    and-int/lit8 v1, v3, 0x11

    .line 135
    .line 136
    const/16 v4, 0x10

    .line 137
    .line 138
    const/4 v5, 0x1

    .line 139
    const/4 v6, 0x0

    .line 140
    if-eq v1, v4, :cond_5

    .line 141
    .line 142
    move v1, v5

    .line 143
    goto :goto_4

    .line 144
    :cond_5
    move v1, v6

    .line 145
    :goto_4
    and-int/2addr v3, v5

    .line 146
    move-object v14, v2

    .line 147
    check-cast v14, Ll2/t;

    .line 148
    .line 149
    invoke-virtual {v14, v3, v1}, Ll2/t;->O(IZ)Z

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    if-eqz v1, :cond_6

    .line 154
    .line 155
    const v1, 0x7f08033b

    .line 156
    .line 157
    .line 158
    invoke-static {v1, v6, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 159
    .line 160
    .line 161
    move-result-object v7

    .line 162
    iget-object v0, v0, Lf30/e;->e:Li91/t1;

    .line 163
    .line 164
    iget-wide v0, v0, Li91/t1;->a:J

    .line 165
    .line 166
    new-instance v13, Le3/m;

    .line 167
    .line 168
    const/4 v2, 0x5

    .line 169
    invoke-direct {v13, v0, v1, v2}, Le3/m;-><init>(JI)V

    .line 170
    .line 171
    .line 172
    const/16 v15, 0x30

    .line 173
    .line 174
    const/16 v16, 0x3c

    .line 175
    .line 176
    const/4 v8, 0x0

    .line 177
    const/4 v9, 0x0

    .line 178
    const/4 v10, 0x0

    .line 179
    const/4 v11, 0x0

    .line 180
    const/4 v12, 0x0

    .line 181
    invoke-static/range {v7 .. v16}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 182
    .line 183
    .line 184
    goto :goto_5

    .line 185
    :cond_6
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 186
    .line 187
    .line 188
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 189
    .line 190
    return-object v0

    .line 191
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
