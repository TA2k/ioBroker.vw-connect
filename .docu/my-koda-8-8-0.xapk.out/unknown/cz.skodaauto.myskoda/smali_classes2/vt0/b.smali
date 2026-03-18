.class public final synthetic Lvt0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;


# direct methods
.method public synthetic constructor <init>(Lx2/s;I)V
    .locals 0

    .line 1
    iput p2, p0, Lvt0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvt0/b;->e:Lx2/s;

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
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lvt0/b;->d:I

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
    const/4 v5, 0x0

    .line 34
    const/4 v6, 0x1

    .line 35
    if-eq v1, v4, :cond_0

    .line 36
    .line 37
    move v1, v6

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move v1, v5

    .line 40
    :goto_0
    and-int/2addr v3, v6

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
    if-eqz v1, :cond_1

    .line 48
    .line 49
    const-string v1, "garage_loading_card"

    .line 50
    .line 51
    iget-object v0, v0, Lvt0/b;->e:Lx2/s;

    .line 52
    .line 53
    invoke-static {v0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    invoke-static {v0, v2, v5}, Lxf0/i0;->C(Lx2/s;Ll2/o;I)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_1
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 62
    .line 63
    .line 64
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    return-object v0

    .line 67
    :pswitch_0
    move-object/from16 v1, p1

    .line 68
    .line 69
    check-cast v1, Ljava/lang/String;

    .line 70
    .line 71
    move-object/from16 v2, p2

    .line 72
    .line 73
    check-cast v2, Ll2/o;

    .line 74
    .line 75
    move-object/from16 v3, p3

    .line 76
    .line 77
    check-cast v3, Ljava/lang/Integer;

    .line 78
    .line 79
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    const-string v4, "formattedTimestamp"

    .line 84
    .line 85
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    and-int/lit8 v4, v3, 0x6

    .line 89
    .line 90
    if-nez v4, :cond_3

    .line 91
    .line 92
    move-object v4, v2

    .line 93
    check-cast v4, Ll2/t;

    .line 94
    .line 95
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v4

    .line 99
    if-eqz v4, :cond_2

    .line 100
    .line 101
    const/4 v4, 0x4

    .line 102
    goto :goto_2

    .line 103
    :cond_2
    const/4 v4, 0x2

    .line 104
    :goto_2
    or-int/2addr v3, v4

    .line 105
    :cond_3
    and-int/lit8 v4, v3, 0x13

    .line 106
    .line 107
    const/16 v5, 0x12

    .line 108
    .line 109
    if-eq v4, v5, :cond_4

    .line 110
    .line 111
    const/4 v4, 0x1

    .line 112
    goto :goto_3

    .line 113
    :cond_4
    const/4 v4, 0x0

    .line 114
    :goto_3
    and-int/lit8 v5, v3, 0x1

    .line 115
    .line 116
    check-cast v2, Ll2/t;

    .line 117
    .line 118
    invoke-virtual {v2, v5, v4}, Ll2/t;->O(IZ)Z

    .line 119
    .line 120
    .line 121
    move-result v4

    .line 122
    if-eqz v4, :cond_5

    .line 123
    .line 124
    const-string v4, "last_update_timestamp"

    .line 125
    .line 126
    iget-object v0, v0, Lvt0/b;->e:Lx2/s;

    .line 127
    .line 128
    invoke-static {v0, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 133
    .line 134
    invoke-virtual {v2, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v4

    .line 138
    check-cast v4, Lj91/e;

    .line 139
    .line 140
    invoke-virtual {v4}, Lj91/e;->t()J

    .line 141
    .line 142
    .line 143
    move-result-wide v4

    .line 144
    sget-object v6, Lj91/j;->a:Ll2/u2;

    .line 145
    .line 146
    invoke-virtual {v2, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v6

    .line 150
    check-cast v6, Lj91/f;

    .line 151
    .line 152
    invoke-virtual {v6}, Lj91/f;->e()Lg4/p0;

    .line 153
    .line 154
    .line 155
    move-result-object v6

    .line 156
    and-int/lit8 v20, v3, 0xe

    .line 157
    .line 158
    const/16 v21, 0x0

    .line 159
    .line 160
    const v22, 0xfff0

    .line 161
    .line 162
    .line 163
    move-object/from16 v19, v2

    .line 164
    .line 165
    move-object v2, v6

    .line 166
    const-wide/16 v6, 0x0

    .line 167
    .line 168
    const/4 v8, 0x0

    .line 169
    const-wide/16 v9, 0x0

    .line 170
    .line 171
    const/4 v11, 0x0

    .line 172
    const/4 v12, 0x0

    .line 173
    const-wide/16 v13, 0x0

    .line 174
    .line 175
    const/4 v15, 0x0

    .line 176
    const/16 v16, 0x0

    .line 177
    .line 178
    const/16 v17, 0x0

    .line 179
    .line 180
    const/16 v18, 0x0

    .line 181
    .line 182
    move-object v3, v0

    .line 183
    invoke-static/range {v1 .. v22}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 184
    .line 185
    .line 186
    goto :goto_4

    .line 187
    :cond_5
    move-object/from16 v19, v2

    .line 188
    .line 189
    invoke-virtual/range {v19 .. v19}, Ll2/t;->R()V

    .line 190
    .line 191
    .line 192
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 193
    .line 194
    return-object v0

    .line 195
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
