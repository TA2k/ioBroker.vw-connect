.class public final synthetic Lz70/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lql0/h;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/k;

.field public final synthetic l:Lay0/k;

.field public final synthetic m:Ljava/lang/Object;

.field public final synthetic n:Lay0/a;

.field public final synthetic o:Lay0/a;

.field public final synthetic p:Lay0/a;

.field public final synthetic q:Ljava/lang/Object;

.field public final synthetic r:I


# direct methods
.method public synthetic constructor <init>(Lw40/n;Lk1/z0;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lmy0/c;Lay0/a;Lay0/a;I)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lz70/d0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lz70/d0;->e:Lql0/h;

    iput-object p2, p0, Lz70/d0;->q:Ljava/lang/Object;

    iput-object p3, p0, Lz70/d0;->f:Lay0/a;

    iput-object p4, p0, Lz70/d0;->g:Lay0/a;

    iput-object p5, p0, Lz70/d0;->h:Lay0/a;

    iput-object p6, p0, Lz70/d0;->k:Lay0/k;

    iput-object p7, p0, Lz70/d0;->i:Lay0/a;

    iput-object p8, p0, Lz70/d0;->j:Lay0/a;

    iput-object p9, p0, Lz70/d0;->l:Lay0/k;

    iput-object p10, p0, Lz70/d0;->n:Lay0/a;

    iput-object p11, p0, Lz70/d0;->m:Ljava/lang/Object;

    iput-object p12, p0, Lz70/d0;->o:Lay0/a;

    iput-object p13, p0, Lz70/d0;->p:Lay0/a;

    iput p14, p0, Lz70/d0;->r:I

    return-void
.end method

.method public synthetic constructor <init>(Ly70/q1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;III)V
    .locals 0

    .line 2
    move/from16 p14, p16

    iput p14, p0, Lz70/d0;->d:I

    iput-object p1, p0, Lz70/d0;->e:Lql0/h;

    iput-object p2, p0, Lz70/d0;->f:Lay0/a;

    iput-object p3, p0, Lz70/d0;->g:Lay0/a;

    iput-object p4, p0, Lz70/d0;->h:Lay0/a;

    iput-object p5, p0, Lz70/d0;->i:Lay0/a;

    iput-object p6, p0, Lz70/d0;->j:Lay0/a;

    iput-object p7, p0, Lz70/d0;->k:Lay0/k;

    iput-object p8, p0, Lz70/d0;->l:Lay0/k;

    iput-object p9, p0, Lz70/d0;->m:Ljava/lang/Object;

    iput-object p10, p0, Lz70/d0;->n:Lay0/a;

    iput-object p11, p0, Lz70/d0;->o:Lay0/a;

    iput-object p12, p0, Lz70/d0;->p:Lay0/a;

    iput-object p13, p0, Lz70/d0;->q:Ljava/lang/Object;

    iput p15, p0, Lz70/d0;->r:I

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
    iget v1, v0, Lz70/d0;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lz70/d0;->e:Lql0/h;

    .line 9
    .line 10
    move-object v2, v1

    .line 11
    check-cast v2, Lw40/n;

    .line 12
    .line 13
    iget-object v1, v0, Lz70/d0;->q:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v3, v1

    .line 16
    check-cast v3, Lk1/z0;

    .line 17
    .line 18
    iget-object v1, v0, Lz70/d0;->m:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v12, v1

    .line 21
    check-cast v12, Lmy0/c;

    .line 22
    .line 23
    move-object/from16 v15, p1

    .line 24
    .line 25
    check-cast v15, Ll2/o;

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
    iget v1, v0, Lz70/d0;->r:I

    .line 35
    .line 36
    or-int/lit8 v1, v1, 0x1

    .line 37
    .line 38
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 39
    .line 40
    .line 41
    move-result v16

    .line 42
    iget-object v4, v0, Lz70/d0;->f:Lay0/a;

    .line 43
    .line 44
    iget-object v5, v0, Lz70/d0;->g:Lay0/a;

    .line 45
    .line 46
    iget-object v6, v0, Lz70/d0;->h:Lay0/a;

    .line 47
    .line 48
    iget-object v7, v0, Lz70/d0;->k:Lay0/k;

    .line 49
    .line 50
    iget-object v8, v0, Lz70/d0;->i:Lay0/a;

    .line 51
    .line 52
    iget-object v9, v0, Lz70/d0;->j:Lay0/a;

    .line 53
    .line 54
    iget-object v10, v0, Lz70/d0;->l:Lay0/k;

    .line 55
    .line 56
    iget-object v11, v0, Lz70/d0;->n:Lay0/a;

    .line 57
    .line 58
    iget-object v13, v0, Lz70/d0;->o:Lay0/a;

    .line 59
    .line 60
    iget-object v14, v0, Lz70/d0;->p:Lay0/a;

    .line 61
    .line 62
    invoke-static/range {v2 .. v16}, Lx40/a;->i(Lw40/n;Lk1/z0;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lmy0/c;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 63
    .line 64
    .line 65
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    return-object v0

    .line 68
    :pswitch_0
    iget-object v1, v0, Lz70/d0;->e:Lql0/h;

    .line 69
    .line 70
    move-object v2, v1

    .line 71
    check-cast v2, Ly70/q1;

    .line 72
    .line 73
    iget-object v1, v0, Lz70/d0;->m:Ljava/lang/Object;

    .line 74
    .line 75
    move-object v10, v1

    .line 76
    check-cast v10, Lay0/k;

    .line 77
    .line 78
    iget-object v1, v0, Lz70/d0;->q:Ljava/lang/Object;

    .line 79
    .line 80
    move-object v14, v1

    .line 81
    check-cast v14, Lay0/a;

    .line 82
    .line 83
    move-object/from16 v15, p1

    .line 84
    .line 85
    check-cast v15, Ll2/o;

    .line 86
    .line 87
    move-object/from16 v1, p2

    .line 88
    .line 89
    check-cast v1, Ljava/lang/Integer;

    .line 90
    .line 91
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    const/4 v1, 0x1

    .line 95
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 96
    .line 97
    .line 98
    move-result v16

    .line 99
    iget-object v3, v0, Lz70/d0;->f:Lay0/a;

    .line 100
    .line 101
    iget-object v4, v0, Lz70/d0;->g:Lay0/a;

    .line 102
    .line 103
    iget-object v5, v0, Lz70/d0;->h:Lay0/a;

    .line 104
    .line 105
    iget-object v6, v0, Lz70/d0;->i:Lay0/a;

    .line 106
    .line 107
    iget-object v7, v0, Lz70/d0;->j:Lay0/a;

    .line 108
    .line 109
    iget-object v8, v0, Lz70/d0;->k:Lay0/k;

    .line 110
    .line 111
    iget-object v9, v0, Lz70/d0;->l:Lay0/k;

    .line 112
    .line 113
    iget-object v11, v0, Lz70/d0;->n:Lay0/a;

    .line 114
    .line 115
    iget-object v12, v0, Lz70/d0;->o:Lay0/a;

    .line 116
    .line 117
    iget-object v13, v0, Lz70/d0;->p:Lay0/a;

    .line 118
    .line 119
    iget v0, v0, Lz70/d0;->r:I

    .line 120
    .line 121
    move/from16 v17, v0

    .line 122
    .line 123
    invoke-static/range {v2 .. v17}, Lz70/l;->O(Ly70/q1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 124
    .line 125
    .line 126
    goto :goto_0

    .line 127
    :pswitch_1
    iget-object v1, v0, Lz70/d0;->e:Lql0/h;

    .line 128
    .line 129
    move-object v2, v1

    .line 130
    check-cast v2, Ly70/q1;

    .line 131
    .line 132
    iget-object v1, v0, Lz70/d0;->m:Ljava/lang/Object;

    .line 133
    .line 134
    move-object v10, v1

    .line 135
    check-cast v10, Lay0/k;

    .line 136
    .line 137
    iget-object v1, v0, Lz70/d0;->q:Ljava/lang/Object;

    .line 138
    .line 139
    move-object v14, v1

    .line 140
    check-cast v14, Lay0/a;

    .line 141
    .line 142
    move-object/from16 v15, p1

    .line 143
    .line 144
    check-cast v15, Ll2/o;

    .line 145
    .line 146
    move-object/from16 v1, p2

    .line 147
    .line 148
    check-cast v1, Ljava/lang/Integer;

    .line 149
    .line 150
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    const/4 v1, 0x1

    .line 154
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 155
    .line 156
    .line 157
    move-result v16

    .line 158
    iget-object v3, v0, Lz70/d0;->f:Lay0/a;

    .line 159
    .line 160
    iget-object v4, v0, Lz70/d0;->g:Lay0/a;

    .line 161
    .line 162
    iget-object v5, v0, Lz70/d0;->h:Lay0/a;

    .line 163
    .line 164
    iget-object v6, v0, Lz70/d0;->i:Lay0/a;

    .line 165
    .line 166
    iget-object v7, v0, Lz70/d0;->j:Lay0/a;

    .line 167
    .line 168
    iget-object v8, v0, Lz70/d0;->k:Lay0/k;

    .line 169
    .line 170
    iget-object v9, v0, Lz70/d0;->l:Lay0/k;

    .line 171
    .line 172
    iget-object v11, v0, Lz70/d0;->n:Lay0/a;

    .line 173
    .line 174
    iget-object v12, v0, Lz70/d0;->o:Lay0/a;

    .line 175
    .line 176
    iget-object v13, v0, Lz70/d0;->p:Lay0/a;

    .line 177
    .line 178
    iget v0, v0, Lz70/d0;->r:I

    .line 179
    .line 180
    move/from16 v17, v0

    .line 181
    .line 182
    invoke-static/range {v2 .. v17}, Lz70/l;->O(Ly70/q1;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 183
    .line 184
    .line 185
    goto :goto_0

    .line 186
    nop

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
