.class public final synthetic Leh/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lxh/e;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Llx0/e;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Lxh/e;Lay0/k;Llx0/e;Llx0/e;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p7, p0, Leh/g;->d:I

    iput-object p1, p0, Leh/g;->f:Ljava/lang/Object;

    iput-object p2, p0, Leh/g;->e:Lxh/e;

    iput-object p3, p0, Leh/g;->g:Ljava/lang/Object;

    iput-object p4, p0, Leh/g;->h:Ljava/lang/Object;

    iput-object p5, p0, Leh/g;->i:Llx0/e;

    iput-object p6, p0, Leh/g;->j:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ll2/b1;Ll2/b1;Ll2/b1;Ly1/i;Lxh/e;Lzb/d;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Leh/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Leh/g;->f:Ljava/lang/Object;

    iput-object p2, p0, Leh/g;->g:Ljava/lang/Object;

    iput-object p3, p0, Leh/g;->h:Ljava/lang/Object;

    iput-object p4, p0, Leh/g;->i:Llx0/e;

    iput-object p5, p0, Leh/g;->e:Lxh/e;

    iput-object p6, p0, Leh/g;->j:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Leh/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Leh/g;->f:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v1, v0

    .line 9
    check-cast v1, Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, Leh/g;->g:Ljava/lang/Object;

    .line 12
    .line 13
    move-object v3, v0

    .line 14
    check-cast v3, Lxh/e;

    .line 15
    .line 16
    iget-object v0, p0, Leh/g;->h:Ljava/lang/Object;

    .line 17
    .line 18
    move-object v4, v0

    .line 19
    check-cast v4, Lxh/e;

    .line 20
    .line 21
    iget-object v0, p0, Leh/g;->i:Llx0/e;

    .line 22
    .line 23
    move-object v5, v0

    .line 24
    check-cast v5, Lyj/b;

    .line 25
    .line 26
    iget-object v0, p0, Leh/g;->j:Ljava/lang/Object;

    .line 27
    .line 28
    move-object v6, v0

    .line 29
    check-cast v6, Lxh/e;

    .line 30
    .line 31
    check-cast p1, Lb1/n;

    .line 32
    .line 33
    check-cast p2, Lz9/k;

    .line 34
    .line 35
    move-object v7, p3

    .line 36
    check-cast v7, Ll2/o;

    .line 37
    .line 38
    move-object/from16 v0, p4

    .line 39
    .line 40
    check-cast v0, Ljava/lang/Integer;

    .line 41
    .line 42
    const-string v2, "$this$composable"

    .line 43
    .line 44
    const-string v8, "it"

    .line 45
    .line 46
    invoke-static {v0, p1, v2, p2, v8}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    const/4 v8, 0x0

    .line 50
    iget-object v2, p0, Leh/g;->e:Lxh/e;

    .line 51
    .line 52
    invoke-static/range {v1 .. v8}, Llp/n1;->a(Ljava/lang/String;Lxh/e;Lxh/e;Lxh/e;Lyj/b;Lxh/e;Ll2/o;I)V

    .line 53
    .line 54
    .line 55
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_0
    iget-object v0, p0, Leh/g;->f:Ljava/lang/Object;

    .line 59
    .line 60
    move-object v1, v0

    .line 61
    check-cast v1, Ljava/util/List;

    .line 62
    .line 63
    iget-object v0, p0, Leh/g;->g:Ljava/lang/Object;

    .line 64
    .line 65
    move-object v3, v0

    .line 66
    check-cast v3, Lay0/k;

    .line 67
    .line 68
    iget-object v0, p0, Leh/g;->h:Ljava/lang/Object;

    .line 69
    .line 70
    move-object v4, v0

    .line 71
    check-cast v4, Lyj/b;

    .line 72
    .line 73
    iget-object v0, p0, Leh/g;->i:Llx0/e;

    .line 74
    .line 75
    move-object v5, v0

    .line 76
    check-cast v5, Lxh/e;

    .line 77
    .line 78
    iget-object v0, p0, Leh/g;->j:Ljava/lang/Object;

    .line 79
    .line 80
    move-object v6, v0

    .line 81
    check-cast v6, Lbd/a;

    .line 82
    .line 83
    check-cast p1, Lb1/n;

    .line 84
    .line 85
    check-cast p2, Lz9/k;

    .line 86
    .line 87
    move-object v7, p3

    .line 88
    check-cast v7, Ll2/o;

    .line 89
    .line 90
    move-object/from16 v0, p4

    .line 91
    .line 92
    check-cast v0, Ljava/lang/Integer;

    .line 93
    .line 94
    const-string v2, "$this$composable"

    .line 95
    .line 96
    const-string v8, "it"

    .line 97
    .line 98
    invoke-static {v0, p1, v2, p2, v8}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    const/16 v8, 0x180

    .line 102
    .line 103
    iget-object v2, p0, Leh/g;->e:Lxh/e;

    .line 104
    .line 105
    invoke-static/range {v1 .. v8}, Llp/kf;->a(Ljava/util/List;Lxh/e;Lay0/k;Lyj/b;Lxh/e;Lbd/a;Ll2/o;I)V

    .line 106
    .line 107
    .line 108
    goto :goto_0

    .line 109
    :pswitch_1
    iget-object v0, p0, Leh/g;->f:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v0, Ll2/b1;

    .line 112
    .line 113
    iget-object v1, p0, Leh/g;->g:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v1, Ll2/b1;

    .line 116
    .line 117
    iget-object v2, p0, Leh/g;->h:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast v2, Ll2/b1;

    .line 120
    .line 121
    iget-object v3, p0, Leh/g;->i:Llx0/e;

    .line 122
    .line 123
    move-object v4, v3

    .line 124
    check-cast v4, Ly1/i;

    .line 125
    .line 126
    iget-object v3, p0, Leh/g;->j:Ljava/lang/Object;

    .line 127
    .line 128
    move-object v8, v3

    .line 129
    check-cast v8, Lzb/d;

    .line 130
    .line 131
    check-cast p1, Lb1/n;

    .line 132
    .line 133
    check-cast p2, Lz9/k;

    .line 134
    .line 135
    move-object v3, p3

    .line 136
    check-cast v3, Ll2/o;

    .line 137
    .line 138
    move-object/from16 v5, p4

    .line 139
    .line 140
    check-cast v5, Ljava/lang/Integer;

    .line 141
    .line 142
    const-string v6, "$this$composable"

    .line 143
    .line 144
    const-string v7, "it"

    .line 145
    .line 146
    invoke-static {v5, p1, v6, p2, v7}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    move-object v9, p1

    .line 154
    check-cast v9, Lzg/c1;

    .line 155
    .line 156
    const/4 p1, 0x0

    .line 157
    if-nez v9, :cond_0

    .line 158
    .line 159
    check-cast v3, Ll2/t;

    .line 160
    .line 161
    const p0, -0x74937b2f

    .line 162
    .line 163
    .line 164
    invoke-virtual {v3, p0}, Ll2/t;->Y(I)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v3, p1}, Ll2/t;->q(Z)V

    .line 168
    .line 169
    .line 170
    goto :goto_3

    .line 171
    :cond_0
    move-object v10, v3

    .line 172
    check-cast v10, Ll2/t;

    .line 173
    .line 174
    const p2, -0x74937b2e

    .line 175
    .line 176
    .line 177
    invoke-virtual {v10, p2}, Ll2/t;->Y(I)V

    .line 178
    .line 179
    .line 180
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p2

    .line 184
    move-object v5, p2

    .line 185
    check-cast v5, Lzg/h;

    .line 186
    .line 187
    if-nez v5, :cond_1

    .line 188
    .line 189
    const p0, -0x2b30d507

    .line 190
    .line 191
    .line 192
    invoke-virtual {v10, p0}, Ll2/t;->Y(I)V

    .line 193
    .line 194
    .line 195
    :goto_1
    invoke-virtual {v10, p1}, Ll2/t;->q(Z)V

    .line 196
    .line 197
    .line 198
    goto :goto_2

    .line 199
    :cond_1
    const p2, -0x2b30d506

    .line 200
    .line 201
    .line 202
    invoke-virtual {v10, p2}, Ll2/t;->Y(I)V

    .line 203
    .line 204
    .line 205
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object p2

    .line 209
    move-object v6, p2

    .line 210
    check-cast v6, Lai/a;

    .line 211
    .line 212
    const/4 v11, 0x0

    .line 213
    iget-object v7, p0, Leh/g;->e:Lxh/e;

    .line 214
    .line 215
    invoke-static/range {v4 .. v11}, Ljp/ra;->i(Ly1/i;Lzg/h;Lai/a;Lxh/e;Lzb/d;Lzg/c1;Ll2/o;I)V

    .line 216
    .line 217
    .line 218
    goto :goto_1

    .line 219
    :goto_2
    invoke-virtual {v10, p1}, Ll2/t;->q(Z)V

    .line 220
    .line 221
    .line 222
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 223
    .line 224
    return-object p0

    .line 225
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
