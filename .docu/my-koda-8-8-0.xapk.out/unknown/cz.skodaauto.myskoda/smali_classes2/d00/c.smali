.class public final synthetic Ld00/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc00/d0;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lc00/d0;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ld00/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld00/c;->f:Lay0/a;

    iput-object p2, p0, Ld00/c;->e:Lc00/d0;

    iput-object p3, p0, Ld00/c;->g:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lc00/d0;Lay0/a;Lay0/a;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Ld00/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld00/c;->e:Lc00/d0;

    iput-object p2, p0, Ld00/c;->f:Lay0/a;

    iput-object p3, p0, Ld00/c;->g:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lc00/d0;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 3
    const/4 p4, 0x2

    iput p4, p0, Ld00/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld00/c;->e:Lc00/d0;

    iput-object p2, p0, Ld00/c;->f:Lay0/a;

    iput-object p3, p0, Ld00/c;->g:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld00/c;->d:I

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
    const/16 v2, 0x9

    .line 20
    .line 21
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    iget-object v3, v0, Ld00/c;->e:Lc00/d0;

    .line 26
    .line 27
    iget-object v4, v0, Ld00/c;->f:Lay0/a;

    .line 28
    .line 29
    iget-object v0, v0, Ld00/c;->g:Lay0/a;

    .line 30
    .line 31
    invoke-static {v3, v4, v0, v1, v2}, Ld00/o;->a(Lc00/d0;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 32
    .line 33
    .line 34
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object v0

    .line 37
    :pswitch_0
    move-object/from16 v1, p1

    .line 38
    .line 39
    check-cast v1, Ll2/o;

    .line 40
    .line 41
    move-object/from16 v2, p2

    .line 42
    .line 43
    check-cast v2, Ljava/lang/Integer;

    .line 44
    .line 45
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    and-int/lit8 v3, v2, 0x3

    .line 50
    .line 51
    const/4 v4, 0x2

    .line 52
    const/4 v5, 0x1

    .line 53
    const/4 v6, 0x0

    .line 54
    if-eq v3, v4, :cond_0

    .line 55
    .line 56
    move v3, v5

    .line 57
    goto :goto_0

    .line 58
    :cond_0
    move v3, v6

    .line 59
    :goto_0
    and-int/2addr v2, v5

    .line 60
    check-cast v1, Ll2/t;

    .line 61
    .line 62
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    if-eqz v2, :cond_2

    .line 67
    .line 68
    iget-object v2, v0, Ld00/c;->e:Lc00/d0;

    .line 69
    .line 70
    iget-boolean v3, v2, Lc00/d0;->z:Z

    .line 71
    .line 72
    if-nez v3, :cond_1

    .line 73
    .line 74
    const v3, 0x7bb4a585

    .line 75
    .line 76
    .line 77
    invoke-virtual {v1, v3}, Ll2/t;->Y(I)V

    .line 78
    .line 79
    .line 80
    const/16 v3, 0x8

    .line 81
    .line 82
    iget-object v4, v0, Ld00/c;->f:Lay0/a;

    .line 83
    .line 84
    iget-object v0, v0, Ld00/c;->g:Lay0/a;

    .line 85
    .line 86
    invoke-static {v2, v4, v0, v1, v3}, Ld00/o;->a(Lc00/d0;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 87
    .line 88
    .line 89
    :goto_1
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 90
    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_1
    const v0, 0x7b5d8ab6

    .line 94
    .line 95
    .line 96
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 97
    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_2
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 101
    .line 102
    .line 103
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object v0

    .line 106
    :pswitch_1
    move-object/from16 v1, p1

    .line 107
    .line 108
    check-cast v1, Ll2/o;

    .line 109
    .line 110
    move-object/from16 v2, p2

    .line 111
    .line 112
    check-cast v2, Ljava/lang/Integer;

    .line 113
    .line 114
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 115
    .line 116
    .line 117
    move-result v2

    .line 118
    and-int/lit8 v3, v2, 0x3

    .line 119
    .line 120
    const/4 v4, 0x2

    .line 121
    const/4 v5, 0x1

    .line 122
    if-eq v3, v4, :cond_3

    .line 123
    .line 124
    move v3, v5

    .line 125
    goto :goto_3

    .line 126
    :cond_3
    const/4 v3, 0x0

    .line 127
    :goto_3
    and-int/2addr v2, v5

    .line 128
    move-object v11, v1

    .line 129
    check-cast v11, Ll2/t;

    .line 130
    .line 131
    invoke-virtual {v11, v2, v3}, Ll2/t;->O(IZ)Z

    .line 132
    .line 133
    .line 134
    move-result v1

    .line 135
    if-eqz v1, :cond_4

    .line 136
    .line 137
    const v1, 0x7f1200aa

    .line 138
    .line 139
    .line 140
    invoke-static {v11, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v5

    .line 144
    new-instance v7, Li91/w2;

    .line 145
    .line 146
    iget-object v1, v0, Ld00/c;->f:Lay0/a;

    .line 147
    .line 148
    const/4 v2, 0x3

    .line 149
    invoke-direct {v7, v1, v2}, Li91/w2;-><init>(Lay0/a;I)V

    .line 150
    .line 151
    .line 152
    new-instance v12, Li91/v2;

    .line 153
    .line 154
    iget-object v1, v0, Ld00/c;->e:Lc00/d0;

    .line 155
    .line 156
    iget-boolean v1, v1, Lc00/d0;->b:Z

    .line 157
    .line 158
    const/16 v16, 0x0

    .line 159
    .line 160
    const/4 v14, 0x4

    .line 161
    const v13, 0x7f080429

    .line 162
    .line 163
    .line 164
    iget-object v15, v0, Ld00/c;->g:Lay0/a;

    .line 165
    .line 166
    move/from16 v17, v1

    .line 167
    .line 168
    invoke-direct/range {v12 .. v17}, Li91/v2;-><init>(IILay0/a;Ljava/lang/String;Z)V

    .line 169
    .line 170
    .line 171
    invoke-static {v12}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 172
    .line 173
    .line 174
    move-result-object v8

    .line 175
    const/4 v12, 0x0

    .line 176
    const/16 v13, 0x33d

    .line 177
    .line 178
    const/4 v4, 0x0

    .line 179
    const/4 v6, 0x0

    .line 180
    const/4 v9, 0x0

    .line 181
    const/4 v10, 0x0

    .line 182
    invoke-static/range {v4 .. v13}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 183
    .line 184
    .line 185
    goto :goto_4

    .line 186
    :cond_4
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 187
    .line 188
    .line 189
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 190
    .line 191
    return-object v0

    .line 192
    nop

    .line 193
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
