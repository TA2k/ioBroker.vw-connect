.class public final Ltv/k;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Ltv/k;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Ltv/k;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Ltv/k;->h:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Ltv/k;->i:Ljava/lang/Object;

    .line 8
    .line 9
    const/4 p1, 0x3

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Ltv/k;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvv/m0;

    .line 7
    .line 8
    check-cast p2, Ll2/o;

    .line 9
    .line 10
    check-cast p3, Ljava/lang/Number;

    .line 11
    .line 12
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result p3

    .line 16
    const-string v0, "$this$WithStyle"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 v0, p3, 0xe

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    move-object v0, p2

    .line 26
    check-cast v0, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    const/4 v0, 0x4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v0, 0x2

    .line 37
    :goto_0
    or-int/2addr p3, v0

    .line 38
    :cond_1
    and-int/lit8 p3, p3, 0x5b

    .line 39
    .line 40
    const/16 v0, 0x12

    .line 41
    .line 42
    if-ne p3, v0, :cond_3

    .line 43
    .line 44
    move-object p3, p2

    .line 45
    check-cast p3, Ll2/t;

    .line 46
    .line 47
    invoke-virtual {p3}, Ll2/t;->A()Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-nez v0, :cond_2

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_2
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 55
    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_3
    :goto_1
    sget-object p3, Lvv/e0;->a:Ll2/e0;

    .line 59
    .line 60
    iget-object v0, p0, Ltv/k;->g:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v0, Lxf0/b2;

    .line 63
    .line 64
    invoke-virtual {p3, v0}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 65
    .line 66
    .line 67
    move-result-object p3

    .line 68
    new-instance v0, Lf7/f;

    .line 69
    .line 70
    iget-object v1, p0, Ltv/k;->h:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v1, Lx2/s;

    .line 73
    .line 74
    iget-object p0, p0, Ltv/k;->i:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p0, Lay0/o;

    .line 77
    .line 78
    const/4 v2, 0x3

    .line 79
    invoke-direct {v0, v2, p1, v1, p0}, Lf7/f;-><init>(ILjava/lang/Object;Ljava/lang/Object;Llx0/e;)V

    .line 80
    .line 81
    .line 82
    const p0, -0x67708e29

    .line 83
    .line 84
    .line 85
    invoke-static {p0, p2, v0}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    const/16 p1, 0x30

    .line 90
    .line 91
    invoke-static {p3, p0, p2, p1}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 92
    .line 93
    .line 94
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    return-object p0

    .line 97
    :pswitch_0
    iget-object v0, p0, Ltv/k;->h:Ljava/lang/Object;

    .line 98
    .line 99
    move-object v1, v0

    .line 100
    check-cast v1, Ljl/h;

    .line 101
    .line 102
    check-cast p1, Landroidx/compose/foundation/layout/c;

    .line 103
    .line 104
    check-cast p2, Ll2/o;

    .line 105
    .line 106
    check-cast p3, Ljava/lang/Number;

    .line 107
    .line 108
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 109
    .line 110
    .line 111
    move-result p3

    .line 112
    const-string v0, "$this$BoxWithConstraints"

    .line 113
    .line 114
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    and-int/lit8 v0, p3, 0xe

    .line 118
    .line 119
    if-nez v0, :cond_5

    .line 120
    .line 121
    move-object v0, p2

    .line 122
    check-cast v0, Ll2/t;

    .line 123
    .line 124
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    if-eqz v0, :cond_4

    .line 129
    .line 130
    const/4 v0, 0x4

    .line 131
    goto :goto_3

    .line 132
    :cond_4
    const/4 v0, 0x2

    .line 133
    :goto_3
    or-int/2addr p3, v0

    .line 134
    :cond_5
    and-int/lit8 p3, p3, 0x5b

    .line 135
    .line 136
    const/16 v0, 0x12

    .line 137
    .line 138
    if-ne p3, v0, :cond_7

    .line 139
    .line 140
    move-object p3, p2

    .line 141
    check-cast p3, Ll2/t;

    .line 142
    .line 143
    invoke-virtual {p3}, Ll2/t;->A()Z

    .line 144
    .line 145
    .line 146
    move-result v0

    .line 147
    if-nez v0, :cond_6

    .line 148
    .line 149
    goto :goto_4

    .line 150
    :cond_6
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 151
    .line 152
    .line 153
    goto :goto_5

    .line 154
    :cond_7
    :goto_4
    iget-object p3, p0, Ltv/k;->g:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast p3, Lt4/c;

    .line 157
    .line 158
    move-object v8, p2

    .line 159
    check-cast v8, Ll2/t;

    .line 160
    .line 161
    const p2, 0x1e7b2b64

    .line 162
    .line 163
    .line 164
    invoke-virtual {v8, p2}, Ll2/t;->Z(I)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v8, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result p2

    .line 171
    invoke-virtual {v8, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v0

    .line 175
    or-int/2addr p2, v0

    .line 176
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    if-nez p2, :cond_8

    .line 181
    .line 182
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 183
    .line 184
    if-ne v0, p2, :cond_9

    .line 185
    .line 186
    :cond_8
    new-instance p2, Ltv/j;

    .line 187
    .line 188
    const/4 v0, 0x0

    .line 189
    invoke-direct {p2, v1, p1, p3, v0}, Ltv/j;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 190
    .line 191
    .line 192
    invoke-static {p2}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    :cond_9
    const/4 p1, 0x0

    .line 200
    invoke-virtual {v8, p1}, Ll2/t;->q(Z)V

    .line 201
    .line 202
    .line 203
    check-cast v0, Ll2/t2;

    .line 204
    .line 205
    iget-object p0, p0, Ltv/k;->i:Ljava/lang/Object;

    .line 206
    .line 207
    move-object v2, p0

    .line 208
    check-cast v2, Ljava/lang/String;

    .line 209
    .line 210
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object p0

    .line 214
    move-object v3, p0

    .line 215
    check-cast v3, Lx2/s;

    .line 216
    .line 217
    const/4 v9, 0x0

    .line 218
    const/16 v10, 0x68

    .line 219
    .line 220
    const/4 v4, 0x0

    .line 221
    sget-object v5, Lt3/j;->e:Lt3/x0;

    .line 222
    .line 223
    const/4 v6, 0x0

    .line 224
    const/4 v7, 0x0

    .line 225
    invoke-static/range {v1 .. v10}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 226
    .line 227
    .line 228
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 229
    .line 230
    return-object p0

    .line 231
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
