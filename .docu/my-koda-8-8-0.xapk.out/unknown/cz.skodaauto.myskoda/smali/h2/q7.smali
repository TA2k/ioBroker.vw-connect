.class public final synthetic Lh2/q7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:I

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lay0/a;ZZII)V
    .locals 0

    .line 1
    const/4 p5, 0x4

    iput p5, p0, Lh2/q7;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/q7;->h:Ljava/lang/Object;

    iput-object p2, p0, Lh2/q7;->i:Ljava/lang/Object;

    iput-boolean p3, p0, Lh2/q7;->e:Z

    iput-boolean p4, p0, Lh2/q7;->f:Z

    iput p6, p0, Lh2/q7;->g:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;ZLm1/t;ZII)V
    .locals 0

    .line 2
    iput p6, p0, Lh2/q7;->d:I

    iput-object p1, p0, Lh2/q7;->h:Ljava/lang/Object;

    iput-boolean p2, p0, Lh2/q7;->e:Z

    iput-object p3, p0, Lh2/q7;->i:Ljava/lang/Object;

    iput-boolean p4, p0, Lh2/q7;->f:Z

    iput p5, p0, Lh2/q7;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;ZZLlx0/e;II)V
    .locals 0

    .line 3
    iput p6, p0, Lh2/q7;->d:I

    iput-object p1, p0, Lh2/q7;->h:Ljava/lang/Object;

    iput-boolean p2, p0, Lh2/q7;->e:Z

    iput-boolean p3, p0, Lh2/q7;->f:Z

    iput-object p4, p0, Lh2/q7;->i:Ljava/lang/Object;

    iput p5, p0, Lh2/q7;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/Object;ZLjava/lang/Object;II)V
    .locals 0

    .line 4
    iput p6, p0, Lh2/q7;->d:I

    iput-boolean p1, p0, Lh2/q7;->e:Z

    iput-object p2, p0, Lh2/q7;->h:Ljava/lang/Object;

    iput-boolean p3, p0, Lh2/q7;->f:Z

    iput-object p4, p0, Lh2/q7;->i:Ljava/lang/Object;

    iput p5, p0, Lh2/q7;->g:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lh2/q7;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/q7;->i:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v4, v0

    .line 9
    check-cast v4, Lay0/k;

    .line 10
    .line 11
    move-object v5, p1

    .line 12
    check-cast v5, Ll2/o;

    .line 13
    .line 14
    check-cast p2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    iget p1, p0, Lh2/q7;->g:I

    .line 20
    .line 21
    or-int/lit8 p1, p1, 0x1

    .line 22
    .line 23
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 24
    .line 25
    .line 26
    move-result v6

    .line 27
    iget-boolean v1, p0, Lh2/q7;->e:Z

    .line 28
    .line 29
    iget-object v2, p0, Lh2/q7;->h:Ljava/lang/Object;

    .line 30
    .line 31
    iget-boolean v3, p0, Lh2/q7;->f:Z

    .line 32
    .line 33
    invoke-static/range {v1 .. v6}, Lxk0/h;->B(ZLjava/util/List;ZLay0/k;Ll2/o;I)V

    .line 34
    .line 35
    .line 36
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    iget-object v0, p0, Lh2/q7;->h:Ljava/lang/Object;

    .line 40
    .line 41
    move-object v1, v0

    .line 42
    check-cast v1, Lay0/a;

    .line 43
    .line 44
    iget-object v0, p0, Lh2/q7;->i:Ljava/lang/Object;

    .line 45
    .line 46
    move-object v4, v0

    .line 47
    check-cast v4, Lt2/b;

    .line 48
    .line 49
    move-object v5, p1

    .line 50
    check-cast v5, Ll2/o;

    .line 51
    .line 52
    check-cast p2, Ljava/lang/Integer;

    .line 53
    .line 54
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    iget p1, p0, Lh2/q7;->g:I

    .line 58
    .line 59
    or-int/lit8 p1, p1, 0x1

    .line 60
    .line 61
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 62
    .line 63
    .line 64
    move-result v6

    .line 65
    iget-boolean v2, p0, Lh2/q7;->e:Z

    .line 66
    .line 67
    iget-boolean v3, p0, Lh2/q7;->f:Z

    .line 68
    .line 69
    invoke-static/range {v1 .. v6}, Lxf0/y1;->h(Lay0/a;ZZLt2/b;Ll2/o;I)V

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :pswitch_1
    iget-object v0, p0, Lh2/q7;->h:Ljava/lang/Object;

    .line 74
    .line 75
    move-object v1, v0

    .line 76
    check-cast v1, Lay0/a;

    .line 77
    .line 78
    iget-object v0, p0, Lh2/q7;->i:Ljava/lang/Object;

    .line 79
    .line 80
    move-object v2, v0

    .line 81
    check-cast v2, Lay0/a;

    .line 82
    .line 83
    move-object v5, p1

    .line 84
    check-cast v5, Ll2/o;

    .line 85
    .line 86
    check-cast p2, Ljava/lang/Integer;

    .line 87
    .line 88
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 89
    .line 90
    .line 91
    const/4 p1, 0x1

    .line 92
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 93
    .line 94
    .line 95
    move-result v6

    .line 96
    iget-boolean v3, p0, Lh2/q7;->e:Z

    .line 97
    .line 98
    iget-boolean v4, p0, Lh2/q7;->f:Z

    .line 99
    .line 100
    iget v7, p0, Lh2/q7;->g:I

    .line 101
    .line 102
    invoke-static/range {v1 .. v7}, Ls60/a;->b(Lay0/a;Lay0/a;ZZLl2/o;II)V

    .line 103
    .line 104
    .line 105
    goto :goto_0

    .line 106
    :pswitch_2
    iget-object v0, p0, Lh2/q7;->h:Ljava/lang/Object;

    .line 107
    .line 108
    move-object v1, v0

    .line 109
    check-cast v1, Lm70/r;

    .line 110
    .line 111
    iget-object v0, p0, Lh2/q7;->i:Ljava/lang/Object;

    .line 112
    .line 113
    move-object v4, v0

    .line 114
    check-cast v4, Lay0/a;

    .line 115
    .line 116
    move-object v5, p1

    .line 117
    check-cast v5, Ll2/o;

    .line 118
    .line 119
    check-cast p2, Ljava/lang/Integer;

    .line 120
    .line 121
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 122
    .line 123
    .line 124
    iget p1, p0, Lh2/q7;->g:I

    .line 125
    .line 126
    or-int/lit8 p1, p1, 0x1

    .line 127
    .line 128
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 129
    .line 130
    .line 131
    move-result v6

    .line 132
    iget-boolean v2, p0, Lh2/q7;->e:Z

    .line 133
    .line 134
    iget-boolean v3, p0, Lh2/q7;->f:Z

    .line 135
    .line 136
    invoke-static/range {v1 .. v6}, Ln70/r;->c(Lm70/r;ZZLay0/a;Ll2/o;I)V

    .line 137
    .line 138
    .line 139
    goto :goto_0

    .line 140
    :pswitch_3
    iget-object v0, p0, Lh2/q7;->h:Ljava/lang/Object;

    .line 141
    .line 142
    move-object v1, v0

    .line 143
    check-cast v1, Ljava/util/ArrayList;

    .line 144
    .line 145
    iget-object v0, p0, Lh2/q7;->i:Ljava/lang/Object;

    .line 146
    .line 147
    move-object v3, v0

    .line 148
    check-cast v3, Lm1/t;

    .line 149
    .line 150
    move-object v5, p1

    .line 151
    check-cast v5, Ll2/o;

    .line 152
    .line 153
    check-cast p2, Ljava/lang/Integer;

    .line 154
    .line 155
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 156
    .line 157
    .line 158
    iget p1, p0, Lh2/q7;->g:I

    .line 159
    .line 160
    or-int/lit8 p1, p1, 0x1

    .line 161
    .line 162
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 163
    .line 164
    .line 165
    move-result v6

    .line 166
    iget-boolean v2, p0, Lh2/q7;->e:Z

    .line 167
    .line 168
    iget-boolean v4, p0, Lh2/q7;->f:Z

    .line 169
    .line 170
    invoke-static/range {v1 .. v6}, Lik/a;->f(Ljava/util/ArrayList;ZLm1/t;ZLl2/o;I)V

    .line 171
    .line 172
    .line 173
    goto/16 :goto_0

    .line 174
    .line 175
    :pswitch_4
    iget-object v0, p0, Lh2/q7;->h:Ljava/lang/Object;

    .line 176
    .line 177
    move-object v1, v0

    .line 178
    check-cast v1, Lry/a;

    .line 179
    .line 180
    iget-object v0, p0, Lh2/q7;->i:Ljava/lang/Object;

    .line 181
    .line 182
    move-object v3, v0

    .line 183
    check-cast v3, Lm1/t;

    .line 184
    .line 185
    move-object v5, p1

    .line 186
    check-cast v5, Ll2/o;

    .line 187
    .line 188
    check-cast p2, Ljava/lang/Integer;

    .line 189
    .line 190
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 191
    .line 192
    .line 193
    iget p1, p0, Lh2/q7;->g:I

    .line 194
    .line 195
    or-int/lit8 p1, p1, 0x1

    .line 196
    .line 197
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 198
    .line 199
    .line 200
    move-result v6

    .line 201
    iget-boolean v2, p0, Lh2/q7;->e:Z

    .line 202
    .line 203
    iget-boolean v4, p0, Lh2/q7;->f:Z

    .line 204
    .line 205
    invoke-static/range {v1 .. v6}, Lik/a;->d(Lry/a;ZLm1/t;ZLl2/o;I)V

    .line 206
    .line 207
    .line 208
    goto/16 :goto_0

    .line 209
    .line 210
    :pswitch_5
    iget-object v0, p0, Lh2/q7;->h:Ljava/lang/Object;

    .line 211
    .line 212
    move-object v2, v0

    .line 213
    check-cast v2, Lx2/s;

    .line 214
    .line 215
    iget-object v0, p0, Lh2/q7;->i:Ljava/lang/Object;

    .line 216
    .line 217
    move-object v4, v0

    .line 218
    check-cast v4, Lh2/o7;

    .line 219
    .line 220
    move-object v5, p1

    .line 221
    check-cast v5, Ll2/o;

    .line 222
    .line 223
    check-cast p2, Ljava/lang/Integer;

    .line 224
    .line 225
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 226
    .line 227
    .line 228
    iget p1, p0, Lh2/q7;->g:I

    .line 229
    .line 230
    or-int/lit8 p1, p1, 0x1

    .line 231
    .line 232
    invoke-static {p1}, Ll2/b;->x(I)I

    .line 233
    .line 234
    .line 235
    move-result v6

    .line 236
    iget-boolean v1, p0, Lh2/q7;->e:Z

    .line 237
    .line 238
    iget-boolean v3, p0, Lh2/q7;->f:Z

    .line 239
    .line 240
    invoke-static/range {v1 .. v6}, Lh2/r7;->a(ZLx2/s;ZLh2/o7;Ll2/o;I)V

    .line 241
    .line 242
    .line 243
    goto/16 :goto_0

    .line 244
    .line 245
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
