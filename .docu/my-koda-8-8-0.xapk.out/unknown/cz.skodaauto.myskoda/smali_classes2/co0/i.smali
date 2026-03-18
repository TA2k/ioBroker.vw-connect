.class public final synthetic Lco0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lbo0/q;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lbo0/q;I)V
    .locals 0

    .line 1
    const/4 p3, 0x0

    iput p3, p0, Lco0/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lco0/i;->f:Lay0/k;

    iput-object p2, p0, Lco0/i;->e:Lbo0/q;

    return-void
.end method

.method public synthetic constructor <init>(Lbo0/q;Lay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lco0/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lco0/i;->e:Lbo0/q;

    iput-object p2, p0, Lco0/i;->f:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lbo0/q;Lay0/k;II)V
    .locals 0

    .line 3
    iput p4, p0, Lco0/i;->d:I

    iput-object p1, p0, Lco0/i;->e:Lbo0/q;

    iput-object p2, p0, Lco0/i;->f:Lay0/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lco0/i;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    iget-object v3, v0, Lco0/i;->f:Lay0/k;

    .line 25
    .line 26
    iget-object v0, v0, Lco0/i;->e:Lbo0/q;

    .line 27
    .line 28
    invoke-static {v2, v3, v0, v1}, Lco0/c;->d(ILay0/k;Lbo0/q;Ll2/o;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object v0

    .line 34
    :pswitch_0
    move-object/from16 v1, p1

    .line 35
    .line 36
    check-cast v1, Ll2/o;

    .line 37
    .line 38
    move-object/from16 v2, p2

    .line 39
    .line 40
    check-cast v2, Ljava/lang/Integer;

    .line 41
    .line 42
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    const/4 v2, 0x1

    .line 46
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    iget-object v3, v0, Lco0/i;->f:Lay0/k;

    .line 51
    .line 52
    iget-object v0, v0, Lco0/i;->e:Lbo0/q;

    .line 53
    .line 54
    invoke-static {v2, v3, v0, v1}, Lco0/c;->g(ILay0/k;Lbo0/q;Ll2/o;)V

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :pswitch_1
    move-object/from16 v1, p1

    .line 59
    .line 60
    check-cast v1, Ll2/o;

    .line 61
    .line 62
    move-object/from16 v2, p2

    .line 63
    .line 64
    check-cast v2, Ljava/lang/Integer;

    .line 65
    .line 66
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    and-int/lit8 v3, v2, 0x3

    .line 71
    .line 72
    const/4 v4, 0x2

    .line 73
    const/4 v5, 0x1

    .line 74
    if-eq v3, v4, :cond_0

    .line 75
    .line 76
    move v3, v5

    .line 77
    goto :goto_1

    .line 78
    :cond_0
    const/4 v3, 0x0

    .line 79
    :goto_1
    and-int/2addr v2, v5

    .line 80
    move-object v14, v1

    .line 81
    check-cast v14, Ll2/t;

    .line 82
    .line 83
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-eqz v1, :cond_3

    .line 88
    .line 89
    iget-object v1, v0, Lco0/i;->e:Lbo0/q;

    .line 90
    .line 91
    iget-object v2, v1, Lbo0/q;->l:Lsx0/b;

    .line 92
    .line 93
    invoke-virtual {v2}, Lmx0/e;->iterator()Ljava/util/Iterator;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 98
    .line 99
    .line 100
    move-result v3

    .line 101
    if-eqz v3, :cond_4

    .line 102
    .line 103
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v3

    .line 107
    check-cast v3, Ljava/time/DayOfWeek;

    .line 108
    .line 109
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 110
    .line 111
    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object v5

    .line 115
    invoke-static {v4, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 116
    .line 117
    .line 118
    move-result-object v5

    .line 119
    invoke-static {v3}, Ljp/c1;->e(Ljava/time/DayOfWeek;)Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v4

    .line 123
    iget-object v6, v1, Lbo0/q;->c:Ljava/util/Set;

    .line 124
    .line 125
    invoke-interface {v6, v3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v7

    .line 129
    iget-object v6, v0, Lco0/i;->f:Lay0/k;

    .line 130
    .line 131
    invoke-virtual {v14, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v8

    .line 135
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 136
    .line 137
    .line 138
    move-result v9

    .line 139
    invoke-virtual {v14, v9}, Ll2/t;->e(I)Z

    .line 140
    .line 141
    .line 142
    move-result v9

    .line 143
    or-int/2addr v8, v9

    .line 144
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v9

    .line 148
    if-nez v8, :cond_1

    .line 149
    .line 150
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 151
    .line 152
    if-ne v9, v8, :cond_2

    .line 153
    .line 154
    :cond_1
    new-instance v9, Laa/k;

    .line 155
    .line 156
    const/16 v8, 0x14

    .line 157
    .line 158
    invoke-direct {v9, v8, v6, v3}, Laa/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v14, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    :cond_2
    move-object v6, v9

    .line 165
    check-cast v6, Lay0/a;

    .line 166
    .line 167
    const/16 v16, 0x0

    .line 168
    .line 169
    const/16 v17, 0x3ff0

    .line 170
    .line 171
    const/4 v8, 0x0

    .line 172
    const/4 v9, 0x0

    .line 173
    const/4 v10, 0x0

    .line 174
    const/4 v11, 0x0

    .line 175
    const/4 v12, 0x0

    .line 176
    const/4 v13, 0x0

    .line 177
    const/4 v15, 0x0

    .line 178
    invoke-static/range {v4 .. v17}, Li91/h0;->a(Ljava/lang/String;Lx2/s;Lay0/a;ZZZLjava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;III)V

    .line 179
    .line 180
    .line 181
    goto :goto_2

    .line 182
    :cond_3
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 183
    .line 184
    .line 185
    :cond_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 186
    .line 187
    return-object v0

    .line 188
    :pswitch_2
    move-object/from16 v1, p1

    .line 189
    .line 190
    check-cast v1, Ll2/o;

    .line 191
    .line 192
    move-object/from16 v2, p2

    .line 193
    .line 194
    check-cast v2, Ljava/lang/Integer;

    .line 195
    .line 196
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 197
    .line 198
    .line 199
    const/4 v2, 0x1

    .line 200
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 201
    .line 202
    .line 203
    move-result v2

    .line 204
    iget-object v3, v0, Lco0/i;->f:Lay0/k;

    .line 205
    .line 206
    iget-object v0, v0, Lco0/i;->e:Lbo0/q;

    .line 207
    .line 208
    invoke-static {v2, v3, v0, v1}, Lco0/c;->h(ILay0/k;Lbo0/q;Ll2/o;)V

    .line 209
    .line 210
    .line 211
    goto/16 :goto_0

    .line 212
    .line 213
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
