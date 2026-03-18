.class public final synthetic Lj41/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lz70/b;

.field public final synthetic f:Lw31/h;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lw31/h;Lz70/b;Lay0/k;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lj41/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lj41/a;->f:Lw31/h;

    iput-object p2, p0, Lj41/a;->e:Lz70/b;

    iput-object p3, p0, Lj41/a;->g:Lay0/k;

    return-void
.end method

.method public synthetic constructor <init>(Lz70/b;Lw31/h;Lay0/k;I)V
    .locals 0

    .line 2
    const/4 p4, 0x1

    iput p4, p0, Lj41/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lj41/a;->e:Lz70/b;

    iput-object p2, p0, Lj41/a;->f:Lw31/h;

    iput-object p3, p0, Lj41/a;->g:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lj41/a;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/16 p2, 0x41

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget-object v0, p0, Lj41/a;->e:Lz70/b;

    .line 20
    .line 21
    iget-object v1, p0, Lj41/a;->f:Lw31/h;

    .line 22
    .line 23
    iget-object p0, p0, Lj41/a;->g:Lay0/k;

    .line 24
    .line 25
    invoke-static {v0, v1, p0, p1, p2}, Llp/lb;->b(Lz70/b;Lw31/h;Lay0/k;Ll2/o;I)V

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    and-int/lit8 v0, p2, 0x3

    .line 36
    .line 37
    const/4 v1, 0x2

    .line 38
    const/4 v2, 0x1

    .line 39
    const/4 v3, 0x0

    .line 40
    if-eq v0, v1, :cond_0

    .line 41
    .line 42
    move v0, v2

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    move v0, v3

    .line 45
    :goto_0
    and-int/2addr p2, v2

    .line 46
    move-object v11, p1

    .line 47
    check-cast v11, Ll2/t;

    .line 48
    .line 49
    invoke-virtual {v11, p2, v0}, Ll2/t;->O(IZ)Z

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    if-eqz p1, :cond_6

    .line 54
    .line 55
    iget-object p1, p0, Lj41/a;->f:Lw31/h;

    .line 56
    .line 57
    iget-boolean p2, p1, Lw31/h;->a:Z

    .line 58
    .line 59
    if-eqz p2, :cond_1

    .line 60
    .line 61
    const p0, 0x264d20c1

    .line 62
    .line 63
    .line 64
    invoke-virtual {v11, p0}, Ll2/t;->Y(I)V

    .line 65
    .line 66
    .line 67
    invoke-static {v11, v3}, Ljp/bd;->a(Ll2/o;I)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 71
    .line 72
    .line 73
    goto/16 :goto_2

    .line 74
    .line 75
    :cond_1
    iget-object p2, p1, Lw31/h;->b:Ljava/util/List;

    .line 76
    .line 77
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 78
    .line 79
    .line 80
    move-result p2

    .line 81
    iget-object v0, p0, Lj41/a;->e:Lz70/b;

    .line 82
    .line 83
    iget-object p0, p0, Lj41/a;->g:Lay0/k;

    .line 84
    .line 85
    if-nez p2, :cond_3

    .line 86
    .line 87
    iget-object p2, p1, Lw31/h;->c:Ljava/util/List;

    .line 88
    .line 89
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    .line 90
    .line 91
    .line 92
    move-result p2

    .line 93
    if-eqz p2, :cond_2

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_2
    const p2, 0x26572547

    .line 97
    .line 98
    .line 99
    invoke-virtual {v11, p2}, Ll2/t;->Y(I)V

    .line 100
    .line 101
    .line 102
    const/16 p2, 0x40

    .line 103
    .line 104
    invoke-static {v0, p1, p0, v11, p2}, Llp/lb;->b(Lz70/b;Lw31/h;Lay0/k;Ll2/o;I)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 108
    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_3
    :goto_1
    const p2, 0x264eb364

    .line 112
    .line 113
    .line 114
    invoke-virtual {v11, p2}, Ll2/t;->Y(I)V

    .line 115
    .line 116
    .line 117
    iget-object p2, v0, Lz70/b;->a:Lij0/a;

    .line 118
    .line 119
    new-array v0, v3, [Ljava/lang/Object;

    .line 120
    .line 121
    check-cast p2, Ljj0/f;

    .line 122
    .line 123
    const v1, 0x7f121145

    .line 124
    .line 125
    .line 126
    invoke-virtual {p2, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v4

    .line 130
    const v0, 0x7f121144

    .line 131
    .line 132
    .line 133
    new-array v1, v3, [Ljava/lang/Object;

    .line 134
    .line 135
    invoke-virtual {p2, v0, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v5

    .line 139
    const v0, 0x7f121146

    .line 140
    .line 141
    .line 142
    new-array v1, v3, [Ljava/lang/Object;

    .line 143
    .line 144
    invoke-virtual {p2, v0, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v8

    .line 148
    const-string v0, "8.8.0"

    .line 149
    .line 150
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    const v1, 0x7f1202b6

    .line 155
    .line 156
    .line 157
    invoke-virtual {p2, v1, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v7

    .line 161
    iget-object v6, p1, Lw31/h;->d:Ljava/lang/String;

    .line 162
    .line 163
    invoke-virtual {v11, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result p1

    .line 167
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object p2

    .line 171
    if-nez p1, :cond_4

    .line 172
    .line 173
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 174
    .line 175
    if-ne p2, p1, :cond_5

    .line 176
    .line 177
    :cond_4
    new-instance p2, Lik/b;

    .line 178
    .line 179
    const/4 p1, 0x5

    .line 180
    invoke-direct {p2, p1, p0}, Lik/b;-><init>(ILay0/k;)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v11, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    :cond_5
    move-object v10, p2

    .line 187
    check-cast v10, Lay0/a;

    .line 188
    .line 189
    const/4 v12, 0x0

    .line 190
    const/4 v9, 0x0

    .line 191
    invoke-static/range {v4 .. v12}, Ljp/ad;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lx2/s;Lay0/a;Ll2/o;I)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 195
    .line 196
    .line 197
    goto :goto_2

    .line 198
    :cond_6
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 199
    .line 200
    .line 201
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 202
    .line 203
    return-object p0

    .line 204
    nop

    .line 205
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
