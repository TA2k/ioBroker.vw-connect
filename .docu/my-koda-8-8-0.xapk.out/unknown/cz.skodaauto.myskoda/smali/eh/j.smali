.class public final synthetic Leh/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxh/e;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Llx0/e;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lyj/b;Lxh/e;Lh2/d6;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Leh/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Leh/j;->f:Ljava/lang/Object;

    iput-object p2, p0, Leh/j;->h:Llx0/e;

    iput-object p3, p0, Leh/j;->e:Lxh/e;

    iput-object p4, p0, Leh/j;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Lxh/e;Lxh/e;Lay0/k;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Leh/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Leh/j;->f:Ljava/lang/Object;

    iput-object p2, p0, Leh/j;->e:Lxh/e;

    iput-object p3, p0, Leh/j;->g:Ljava/lang/Object;

    iput-object p4, p0, Leh/j;->h:Llx0/e;

    return-void
.end method

.method public synthetic constructor <init>(Ll2/b1;Ll2/b1;Lyj/b;Lxh/e;)V
    .locals 1

    .line 3
    const/4 v0, 0x0

    iput v0, p0, Leh/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Leh/j;->f:Ljava/lang/Object;

    iput-object p2, p0, Leh/j;->g:Ljava/lang/Object;

    iput-object p3, p0, Leh/j;->h:Llx0/e;

    iput-object p4, p0, Leh/j;->e:Lxh/e;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Leh/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Leh/j;->f:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, Leh/j;->h:Llx0/e;

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Lyj/b;

    .line 15
    .line 16
    iget-object v0, p0, Leh/j;->g:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v4, v0

    .line 19
    check-cast v4, Lh2/d6;

    .line 20
    .line 21
    check-cast p1, Lb1/n;

    .line 22
    .line 23
    check-cast p2, Lz9/k;

    .line 24
    .line 25
    move-object v6, p3

    .line 26
    check-cast v6, Ll2/o;

    .line 27
    .line 28
    check-cast p4, Ljava/lang/Integer;

    .line 29
    .line 30
    const-string p3, "$this$composable"

    .line 31
    .line 32
    const-string v0, "entry"

    .line 33
    .line 34
    invoke-static {p4, p1, p3, p2, v0}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-object p1, p2, Lz9/k;->l:Llx0/q;

    .line 38
    .line 39
    invoke-virtual {p1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    check-cast p1, Landroidx/lifecycle/s0;

    .line 44
    .line 45
    const-string p2, "navigate_with_result"

    .line 46
    .line 47
    invoke-virtual {p1, p2}, Landroidx/lifecycle/s0;->b(Ljava/lang/String;)Lyy0/l1;

    .line 48
    .line 49
    .line 50
    move-result-object v5

    .line 51
    const/4 v7, 0x0

    .line 52
    iget-object v3, p0, Leh/j;->e:Lxh/e;

    .line 53
    .line 54
    invoke-static/range {v1 .. v7}, Ljp/pf;->a(Ljava/lang/String;Lyj/b;Lxh/e;Lh2/d6;Lyy0/l1;Ll2/o;I)V

    .line 55
    .line 56
    .line 57
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 58
    .line 59
    return-object p0

    .line 60
    :pswitch_0
    iget-object v0, p0, Leh/j;->f:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v0, Ljava/util/List;

    .line 63
    .line 64
    iget-object v1, p0, Leh/j;->g:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v1, Lxh/e;

    .line 67
    .line 68
    iget-object v2, p0, Leh/j;->h:Llx0/e;

    .line 69
    .line 70
    check-cast v2, Lay0/k;

    .line 71
    .line 72
    check-cast p1, Lp1/p;

    .line 73
    .line 74
    check-cast p2, Ljava/lang/Integer;

    .line 75
    .line 76
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    check-cast p3, Ll2/o;

    .line 81
    .line 82
    check-cast p4, Ljava/lang/Integer;

    .line 83
    .line 84
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    const-string p4, "$this$HorizontalPager"

    .line 88
    .line 89
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-interface {v0, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    check-cast p1, Lbd/a;

    .line 97
    .line 98
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 99
    .line 100
    .line 101
    move-result p1

    .line 102
    const/4 p2, 0x0

    .line 103
    if-eqz p1, :cond_1

    .line 104
    .line 105
    const/4 p0, 0x1

    .line 106
    if-ne p1, p0, :cond_0

    .line 107
    .line 108
    check-cast p3, Ll2/t;

    .line 109
    .line 110
    const p0, 0x42ca699c

    .line 111
    .line 112
    .line 113
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 114
    .line 115
    .line 116
    invoke-static {v1, v2, p3, p2}, Llp/kd;->a(Lxh/e;Lay0/k;Ll2/o;I)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {p3, p2}, Ll2/t;->q(Z)V

    .line 120
    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_0
    const p0, -0x482b1eb6

    .line 124
    .line 125
    .line 126
    check-cast p3, Ll2/t;

    .line 127
    .line 128
    invoke-static {p0, p3, p2}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    throw p0

    .line 133
    :cond_1
    check-cast p3, Ll2/t;

    .line 134
    .line 135
    const p1, 0x42c84e23

    .line 136
    .line 137
    .line 138
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 139
    .line 140
    .line 141
    iget-object p0, p0, Leh/j;->e:Lxh/e;

    .line 142
    .line 143
    invoke-static {p0, p3, p2}, Ljp/ja;->c(Lxh/e;Ll2/o;I)V

    .line 144
    .line 145
    .line 146
    invoke-virtual {p3, p2}, Ll2/t;->q(Z)V

    .line 147
    .line 148
    .line 149
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 150
    .line 151
    return-object p0

    .line 152
    :pswitch_1
    iget-object v0, p0, Leh/j;->f:Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v0, Ll2/b1;

    .line 155
    .line 156
    iget-object v1, p0, Leh/j;->g:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v1, Ll2/b1;

    .line 159
    .line 160
    iget-object v2, p0, Leh/j;->h:Llx0/e;

    .line 161
    .line 162
    move-object v3, v2

    .line 163
    check-cast v3, Lyj/b;

    .line 164
    .line 165
    check-cast p1, Lb1/n;

    .line 166
    .line 167
    check-cast p2, Lz9/k;

    .line 168
    .line 169
    check-cast p3, Ll2/o;

    .line 170
    .line 171
    check-cast p4, Ljava/lang/Integer;

    .line 172
    .line 173
    const-string v2, "$this$composable"

    .line 174
    .line 175
    const-string v4, "it"

    .line 176
    .line 177
    invoke-static {p4, p1, v2, p2, v4}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    move-object v5, p1

    .line 185
    check-cast v5, Lzg/c1;

    .line 186
    .line 187
    const/4 p1, 0x0

    .line 188
    if-nez v5, :cond_2

    .line 189
    .line 190
    check-cast p3, Ll2/t;

    .line 191
    .line 192
    const p0, -0x7d58044

    .line 193
    .line 194
    .line 195
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {p3, p1}, Ll2/t;->q(Z)V

    .line 199
    .line 200
    .line 201
    goto :goto_3

    .line 202
    :cond_2
    move-object v7, p3

    .line 203
    check-cast v7, Ll2/t;

    .line 204
    .line 205
    const p2, -0x7d58043

    .line 206
    .line 207
    .line 208
    invoke-virtual {v7, p2}, Ll2/t;->Y(I)V

    .line 209
    .line 210
    .line 211
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p2

    .line 215
    check-cast p2, Lai/a;

    .line 216
    .line 217
    if-eqz p2, :cond_3

    .line 218
    .line 219
    iget-object p2, p2, Lai/a;->b:Lai/b;

    .line 220
    .line 221
    :goto_1
    move-object v6, p2

    .line 222
    goto :goto_2

    .line 223
    :cond_3
    const/4 p2, 0x0

    .line 224
    goto :goto_1

    .line 225
    :goto_2
    const/4 v8, 0x0

    .line 226
    iget-object v4, p0, Leh/j;->e:Lxh/e;

    .line 227
    .line 228
    invoke-static/range {v3 .. v8}, Llp/ob;->c(Lyj/b;Lxh/e;Lzg/c1;Lai/b;Ll2/o;I)V

    .line 229
    .line 230
    .line 231
    invoke-virtual {v7, p1}, Ll2/t;->q(Z)V

    .line 232
    .line 233
    .line 234
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 235
    .line 236
    return-object p0

    .line 237
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
