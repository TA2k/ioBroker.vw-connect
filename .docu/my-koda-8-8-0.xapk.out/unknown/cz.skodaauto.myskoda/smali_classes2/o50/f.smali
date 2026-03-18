.class public final synthetic Lo50/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lql0/h;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Llx0/e;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Llx0/e;

.field public final synthetic m:Llx0/e;

.field public final synthetic n:Lay0/a;

.field public final synthetic o:Lay0/a;

.field public final synthetic p:I

.field public final synthetic q:I


# direct methods
.method public synthetic constructor <init>(Ln50/g;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lay0/k;Lay0/k;Lay0/a;Lay0/a;III)V
    .locals 0

    .line 1
    iput p14, p0, Lo50/f;->d:I

    iput-object p1, p0, Lo50/f;->e:Lql0/h;

    iput-object p2, p0, Lo50/f;->f:Lay0/a;

    iput-object p3, p0, Lo50/f;->g:Lay0/a;

    iput-object p4, p0, Lo50/f;->h:Lay0/k;

    iput-object p5, p0, Lo50/f;->i:Ljava/lang/Object;

    iput-object p6, p0, Lo50/f;->j:Llx0/e;

    iput-object p7, p0, Lo50/f;->k:Lay0/a;

    iput-object p8, p0, Lo50/f;->l:Llx0/e;

    iput-object p9, p0, Lo50/f;->m:Llx0/e;

    iput-object p10, p0, Lo50/f;->n:Lay0/a;

    iput-object p11, p0, Lo50/f;->o:Lay0/a;

    iput p12, p0, Lo50/f;->p:I

    iput p13, p0, Lo50/f;->q:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Luu0/r;Le1/n1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;II)V
    .locals 1

    .line 2
    const/4 v0, 0x2

    iput v0, p0, Lo50/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lo50/f;->e:Lql0/h;

    iput-object p2, p0, Lo50/f;->i:Ljava/lang/Object;

    iput-object p3, p0, Lo50/f;->f:Lay0/a;

    iput-object p4, p0, Lo50/f;->g:Lay0/a;

    iput-object p5, p0, Lo50/f;->k:Lay0/a;

    iput-object p6, p0, Lo50/f;->n:Lay0/a;

    iput-object p7, p0, Lo50/f;->o:Lay0/a;

    iput-object p8, p0, Lo50/f;->j:Llx0/e;

    iput-object p9, p0, Lo50/f;->l:Llx0/e;

    iput-object p10, p0, Lo50/f;->m:Llx0/e;

    iput-object p11, p0, Lo50/f;->h:Lay0/k;

    iput p12, p0, Lo50/f;->p:I

    iput p13, p0, Lo50/f;->q:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lo50/f;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lo50/f;->e:Lql0/h;

    .line 9
    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Luu0/r;

    .line 12
    .line 13
    iget-object v1, v0, Lo50/f;->i:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, v1

    .line 16
    check-cast v3, Le1/n1;

    .line 17
    .line 18
    iget-object v1, v0, Lo50/f;->j:Llx0/e;

    .line 19
    .line 20
    move-object v9, v1

    .line 21
    check-cast v9, Lay0/a;

    .line 22
    .line 23
    iget-object v1, v0, Lo50/f;->l:Llx0/e;

    .line 24
    .line 25
    move-object v10, v1

    .line 26
    check-cast v10, Lay0/a;

    .line 27
    .line 28
    iget-object v1, v0, Lo50/f;->m:Llx0/e;

    .line 29
    .line 30
    move-object v11, v1

    .line 31
    check-cast v11, Lay0/a;

    .line 32
    .line 33
    move-object/from16 v13, p1

    .line 34
    .line 35
    check-cast v13, Ll2/o;

    .line 36
    .line 37
    move-object/from16 v1, p2

    .line 38
    .line 39
    check-cast v1, Ljava/lang/Integer;

    .line 40
    .line 41
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    iget v1, v0, Lo50/f;->p:I

    .line 45
    .line 46
    or-int/lit8 v1, v1, 0x1

    .line 47
    .line 48
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 49
    .line 50
    .line 51
    move-result v14

    .line 52
    iget-object v4, v0, Lo50/f;->f:Lay0/a;

    .line 53
    .line 54
    iget-object v5, v0, Lo50/f;->g:Lay0/a;

    .line 55
    .line 56
    iget-object v6, v0, Lo50/f;->k:Lay0/a;

    .line 57
    .line 58
    iget-object v7, v0, Lo50/f;->n:Lay0/a;

    .line 59
    .line 60
    iget-object v8, v0, Lo50/f;->o:Lay0/a;

    .line 61
    .line 62
    iget-object v12, v0, Lo50/f;->h:Lay0/k;

    .line 63
    .line 64
    iget v15, v0, Lo50/f;->q:I

    .line 65
    .line 66
    invoke-static/range {v2 .. v15}, Lvu0/g;->b(Luu0/r;Le1/n1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Ll2/o;II)V

    .line 67
    .line 68
    .line 69
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    return-object v0

    .line 72
    :pswitch_0
    iget-object v1, v0, Lo50/f;->e:Lql0/h;

    .line 73
    .line 74
    move-object v2, v1

    .line 75
    check-cast v2, Ln50/g;

    .line 76
    .line 77
    iget-object v1, v0, Lo50/f;->i:Ljava/lang/Object;

    .line 78
    .line 79
    move-object v6, v1

    .line 80
    check-cast v6, Lay0/k;

    .line 81
    .line 82
    iget-object v1, v0, Lo50/f;->j:Llx0/e;

    .line 83
    .line 84
    move-object v7, v1

    .line 85
    check-cast v7, Lay0/k;

    .line 86
    .line 87
    iget-object v1, v0, Lo50/f;->l:Llx0/e;

    .line 88
    .line 89
    move-object v9, v1

    .line 90
    check-cast v9, Lay0/k;

    .line 91
    .line 92
    iget-object v1, v0, Lo50/f;->m:Llx0/e;

    .line 93
    .line 94
    move-object v10, v1

    .line 95
    check-cast v10, Lay0/k;

    .line 96
    .line 97
    move-object/from16 v13, p1

    .line 98
    .line 99
    check-cast v13, Ll2/o;

    .line 100
    .line 101
    move-object/from16 v1, p2

    .line 102
    .line 103
    check-cast v1, Ljava/lang/Integer;

    .line 104
    .line 105
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 106
    .line 107
    .line 108
    iget v1, v0, Lo50/f;->p:I

    .line 109
    .line 110
    or-int/lit8 v1, v1, 0x1

    .line 111
    .line 112
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 113
    .line 114
    .line 115
    move-result v14

    .line 116
    iget v1, v0, Lo50/f;->q:I

    .line 117
    .line 118
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 119
    .line 120
    .line 121
    move-result v15

    .line 122
    iget-object v3, v0, Lo50/f;->f:Lay0/a;

    .line 123
    .line 124
    iget-object v4, v0, Lo50/f;->g:Lay0/a;

    .line 125
    .line 126
    iget-object v5, v0, Lo50/f;->h:Lay0/k;

    .line 127
    .line 128
    iget-object v8, v0, Lo50/f;->k:Lay0/a;

    .line 129
    .line 130
    iget-object v11, v0, Lo50/f;->n:Lay0/a;

    .line 131
    .line 132
    iget-object v12, v0, Lo50/f;->o:Lay0/a;

    .line 133
    .line 134
    invoke-static/range {v2 .. v15}, Lo50/a;->g(Ln50/g;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 135
    .line 136
    .line 137
    goto :goto_0

    .line 138
    :pswitch_1
    iget-object v1, v0, Lo50/f;->e:Lql0/h;

    .line 139
    .line 140
    move-object v2, v1

    .line 141
    check-cast v2, Ln50/g;

    .line 142
    .line 143
    iget-object v1, v0, Lo50/f;->i:Ljava/lang/Object;

    .line 144
    .line 145
    move-object v6, v1

    .line 146
    check-cast v6, Lay0/k;

    .line 147
    .line 148
    iget-object v1, v0, Lo50/f;->j:Llx0/e;

    .line 149
    .line 150
    move-object v7, v1

    .line 151
    check-cast v7, Lay0/k;

    .line 152
    .line 153
    iget-object v1, v0, Lo50/f;->l:Llx0/e;

    .line 154
    .line 155
    move-object v9, v1

    .line 156
    check-cast v9, Lay0/k;

    .line 157
    .line 158
    iget-object v1, v0, Lo50/f;->m:Llx0/e;

    .line 159
    .line 160
    move-object v10, v1

    .line 161
    check-cast v10, Lay0/k;

    .line 162
    .line 163
    move-object/from16 v13, p1

    .line 164
    .line 165
    check-cast v13, Ll2/o;

    .line 166
    .line 167
    move-object/from16 v1, p2

    .line 168
    .line 169
    check-cast v1, Ljava/lang/Integer;

    .line 170
    .line 171
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 172
    .line 173
    .line 174
    iget v1, v0, Lo50/f;->p:I

    .line 175
    .line 176
    or-int/lit8 v1, v1, 0x1

    .line 177
    .line 178
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 179
    .line 180
    .line 181
    move-result v14

    .line 182
    iget v1, v0, Lo50/f;->q:I

    .line 183
    .line 184
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 185
    .line 186
    .line 187
    move-result v15

    .line 188
    iget-object v3, v0, Lo50/f;->f:Lay0/a;

    .line 189
    .line 190
    iget-object v4, v0, Lo50/f;->g:Lay0/a;

    .line 191
    .line 192
    iget-object v5, v0, Lo50/f;->h:Lay0/k;

    .line 193
    .line 194
    iget-object v8, v0, Lo50/f;->k:Lay0/a;

    .line 195
    .line 196
    iget-object v11, v0, Lo50/f;->n:Lay0/a;

    .line 197
    .line 198
    iget-object v12, v0, Lo50/f;->o:Lay0/a;

    .line 199
    .line 200
    invoke-static/range {v2 .. v15}, Lo50/a;->g(Ln50/g;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 201
    .line 202
    .line 203
    goto/16 :goto_0

    .line 204
    .line 205
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
