.class public final Lkn/b;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Lkn/j0;

.field public final synthetic i:Lx2/d;

.field public final synthetic j:Ll2/b1;

.field public final synthetic k:Ll2/b1;

.field public final synthetic l:Ll2/b1;

.field public final synthetic m:Ll2/b1;

.field public final synthetic n:Ll2/b1;

.field public final synthetic o:Ll2/b1;

.field public final synthetic p:Ll2/b1;

.field public final synthetic q:Ll2/b1;

.field public final synthetic r:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Lx2/s;Lkn/j0;Lx2/d;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p13, p0, Lkn/b;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lkn/b;->g:Lx2/s;

    .line 4
    .line 5
    iput-object p2, p0, Lkn/b;->h:Lkn/j0;

    .line 6
    .line 7
    iput-object p3, p0, Lkn/b;->i:Lx2/d;

    .line 8
    .line 9
    iput-object p4, p0, Lkn/b;->j:Ll2/b1;

    .line 10
    .line 11
    iput-object p5, p0, Lkn/b;->k:Ll2/b1;

    .line 12
    .line 13
    iput-object p6, p0, Lkn/b;->l:Ll2/b1;

    .line 14
    .line 15
    iput-object p7, p0, Lkn/b;->m:Ll2/b1;

    .line 16
    .line 17
    iput-object p8, p0, Lkn/b;->n:Ll2/b1;

    .line 18
    .line 19
    iput-object p9, p0, Lkn/b;->o:Ll2/b1;

    .line 20
    .line 21
    iput-object p10, p0, Lkn/b;->p:Ll2/b1;

    .line 22
    .line 23
    iput-object p11, p0, Lkn/b;->q:Ll2/b1;

    .line 24
    .line 25
    iput-object p12, p0, Lkn/b;->r:Ll2/b1;

    .line 26
    .line 27
    const/4 p1, 0x2

    .line 28
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 29
    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lkn/b;->f:I

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
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v2, v2, 0xb

    .line 21
    .line 22
    const/4 v3, 0x2

    .line 23
    if-ne v2, v3, :cond_1

    .line 24
    .line 25
    move-object v2, v1

    .line 26
    check-cast v2, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    if-nez v3, :cond_0

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 36
    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    :goto_0
    new-instance v4, Lkn/b;

    .line 40
    .line 41
    iget-object v2, v0, Lkn/b;->r:Ll2/b1;

    .line 42
    .line 43
    const/16 v17, 0x0

    .line 44
    .line 45
    iget-object v5, v0, Lkn/b;->g:Lx2/s;

    .line 46
    .line 47
    iget-object v6, v0, Lkn/b;->h:Lkn/j0;

    .line 48
    .line 49
    iget-object v7, v0, Lkn/b;->i:Lx2/d;

    .line 50
    .line 51
    iget-object v8, v0, Lkn/b;->j:Ll2/b1;

    .line 52
    .line 53
    iget-object v9, v0, Lkn/b;->k:Ll2/b1;

    .line 54
    .line 55
    iget-object v10, v0, Lkn/b;->l:Ll2/b1;

    .line 56
    .line 57
    iget-object v11, v0, Lkn/b;->m:Ll2/b1;

    .line 58
    .line 59
    iget-object v12, v0, Lkn/b;->n:Ll2/b1;

    .line 60
    .line 61
    iget-object v13, v0, Lkn/b;->o:Ll2/b1;

    .line 62
    .line 63
    iget-object v14, v0, Lkn/b;->p:Ll2/b1;

    .line 64
    .line 65
    iget-object v15, v0, Lkn/b;->q:Ll2/b1;

    .line 66
    .line 67
    move-object/from16 v16, v2

    .line 68
    .line 69
    invoke-direct/range {v4 .. v17}, Lkn/b;-><init>(Lx2/s;Lkn/j0;Lx2/d;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;Ll2/b1;I)V

    .line 70
    .line 71
    .line 72
    const v0, -0x1f304d50

    .line 73
    .line 74
    .line 75
    invoke-static {v0, v1, v4}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    const/16 v2, 0x30

    .line 80
    .line 81
    const/4 v3, 0x0

    .line 82
    invoke-static {v3, v0, v1, v2}, Llp/vd;->a(Lx2/s;Lt2/b;Ll2/o;I)V

    .line 83
    .line 84
    .line 85
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    return-object v0

    .line 88
    :pswitch_0
    move-object/from16 v15, p1

    .line 89
    .line 90
    check-cast v15, Ll2/o;

    .line 91
    .line 92
    move-object/from16 v1, p2

    .line 93
    .line 94
    check-cast v1, Ljava/lang/Number;

    .line 95
    .line 96
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    and-int/lit8 v1, v1, 0xb

    .line 101
    .line 102
    const/4 v2, 0x2

    .line 103
    if-ne v1, v2, :cond_3

    .line 104
    .line 105
    move-object v1, v15

    .line 106
    check-cast v1, Ll2/t;

    .line 107
    .line 108
    invoke-virtual {v1}, Ll2/t;->A()Z

    .line 109
    .line 110
    .line 111
    move-result v2

    .line 112
    if-nez v2, :cond_2

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_2
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 116
    .line 117
    .line 118
    goto :goto_3

    .line 119
    :cond_3
    :goto_2
    iget-object v1, v0, Lkn/b;->j:Ll2/b1;

    .line 120
    .line 121
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    check-cast v1, Lkn/c0;

    .line 126
    .line 127
    iget-object v2, v0, Lkn/b;->k:Ll2/b1;

    .line 128
    .line 129
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    check-cast v2, Ljava/lang/Boolean;

    .line 134
    .line 135
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    iget-object v2, v0, Lkn/b;->l:Ll2/b1;

    .line 140
    .line 141
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v2

    .line 145
    move-object v4, v2

    .line 146
    check-cast v4, Lkn/l0;

    .line 147
    .line 148
    iget-object v2, v0, Lkn/b;->m:Ll2/b1;

    .line 149
    .line 150
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    move-object v5, v2

    .line 155
    check-cast v5, Le3/n0;

    .line 156
    .line 157
    iget-object v2, v0, Lkn/b;->n:Ll2/b1;

    .line 158
    .line 159
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v2

    .line 163
    check-cast v2, Le3/s;

    .line 164
    .line 165
    iget-wide v6, v2, Le3/s;->a:J

    .line 166
    .line 167
    iget-object v2, v0, Lkn/b;->o:Ll2/b1;

    .line 168
    .line 169
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v2

    .line 173
    check-cast v2, Le3/s;

    .line 174
    .line 175
    iget-wide v8, v2, Le3/s;->a:J

    .line 176
    .line 177
    iget-object v2, v0, Lkn/b;->p:Ll2/b1;

    .line 178
    .line 179
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v2

    .line 183
    check-cast v2, Ljava/lang/Number;

    .line 184
    .line 185
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 186
    .line 187
    .line 188
    move-result v10

    .line 189
    iget-object v2, v0, Lkn/b;->q:Ll2/b1;

    .line 190
    .line 191
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v2

    .line 195
    move-object v13, v2

    .line 196
    check-cast v13, Lay0/n;

    .line 197
    .line 198
    iget-object v2, v0, Lkn/b;->r:Ll2/b1;

    .line 199
    .line 200
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v2

    .line 204
    move-object v14, v2

    .line 205
    check-cast v14, Lay0/n;

    .line 206
    .line 207
    const/16 v16, 0x0

    .line 208
    .line 209
    iget-object v2, v0, Lkn/b;->g:Lx2/s;

    .line 210
    .line 211
    iget-object v11, v0, Lkn/b;->h:Lkn/j0;

    .line 212
    .line 213
    iget-object v12, v0, Lkn/b;->i:Lx2/d;

    .line 214
    .line 215
    invoke-static/range {v1 .. v16}, Llp/sd;->b(Lkn/c0;Lx2/s;ZLkn/l0;Le3/n0;JJFLkn/j0;Lx2/d;Lay0/n;Lay0/n;Ll2/o;I)V

    .line 216
    .line 217
    .line 218
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 219
    .line 220
    return-object v0

    .line 221
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
