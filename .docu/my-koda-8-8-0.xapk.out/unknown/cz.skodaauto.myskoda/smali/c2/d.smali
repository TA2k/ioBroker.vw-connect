.class public final synthetic Lc2/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc2/e;


# direct methods
.method public synthetic constructor <init>(Lc2/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc2/d;->d:I

    iput-object p1, p0, Lc2/d;->e:Lc2/e;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lc2/e;Ld4/l;)V
    .locals 0

    .line 2
    const/4 p2, 0x3

    iput p2, p0, Lc2/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc2/d;->e:Lc2/e;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lc2/d;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    iget-object p0, p0, Lc2/d;->e:Lc2/e;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast p1, Lg4/g;

    .line 11
    .line 12
    iget-boolean v0, p0, Lc2/e;->w:Z

    .line 13
    .line 14
    if-nez v0, :cond_2

    .line 15
    .line 16
    iget-boolean v0, p0, Lc2/e;->x:Z

    .line 17
    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_0
    iget-object v0, p0, Lc2/e;->v:Lt1/p0;

    .line 22
    .line 23
    iget-object v0, v0, Lt1/p0;->e:Ll4/a0;

    .line 24
    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    new-instance v3, Ll4/h;

    .line 28
    .line 29
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    new-instance v4, Ll4/a;

    .line 33
    .line 34
    invoke-direct {v4, p1, v2}, Ll4/a;-><init>(Lg4/g;I)V

    .line 35
    .line 36
    .line 37
    const/4 p1, 0x2

    .line 38
    new-array p1, p1, [Ll4/g;

    .line 39
    .line 40
    aput-object v3, p1, v1

    .line 41
    .line 42
    aput-object v4, p1, v2

    .line 43
    .line 44
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    iget-object p0, p0, Lc2/e;->v:Lt1/p0;

    .line 49
    .line 50
    iget-object v1, p0, Lt1/p0;->d:Lb81/a;

    .line 51
    .line 52
    iget-object p0, p0, Lt1/p0;->v:Lt1/r;

    .line 53
    .line 54
    invoke-virtual {v1, p1}, Lb81/a;->k(Ljava/util/List;)Ll4/v;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    const/4 v1, 0x0

    .line 59
    invoke-virtual {v0, v1, p1}, Ll4/a0;->a(Ll4/v;Ll4/v;)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0, p1}, Lt1/r;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    :goto_0
    move v1, v2

    .line 66
    goto :goto_1

    .line 67
    :cond_1
    iget-object v0, p0, Lc2/e;->u:Ll4/v;

    .line 68
    .line 69
    iget-object v1, v0, Ll4/v;->a:Lg4/g;

    .line 70
    .line 71
    iget-object v1, v1, Lg4/g;->e:Ljava/lang/String;

    .line 72
    .line 73
    iget-wide v3, v0, Ll4/v;->b:J

    .line 74
    .line 75
    sget v0, Lg4/o0;->c:I

    .line 76
    .line 77
    const/16 v0, 0x20

    .line 78
    .line 79
    shr-long v5, v3, v0

    .line 80
    .line 81
    long-to-int v5, v5

    .line 82
    const-wide v6, 0xffffffffL

    .line 83
    .line 84
    .line 85
    .line 86
    .line 87
    and-long/2addr v3, v6

    .line 88
    long-to-int v3, v3

    .line 89
    invoke-static {v1, v5, v3, p1}, Lly0/p;->U(Ljava/lang/CharSequence;IILjava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    iget-object v3, p0, Lc2/e;->u:Ll4/v;

    .line 98
    .line 99
    iget-wide v3, v3, Ll4/v;->b:J

    .line 100
    .line 101
    shr-long/2addr v3, v0

    .line 102
    long-to-int v0, v3

    .line 103
    iget-object p1, p1, Lg4/g;->e:Ljava/lang/String;

    .line 104
    .line 105
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 106
    .line 107
    .line 108
    move-result p1

    .line 109
    add-int/2addr p1, v0

    .line 110
    invoke-static {p1, p1}, Lg4/f0;->b(II)J

    .line 111
    .line 112
    .line 113
    move-result-wide v3

    .line 114
    iget-object p0, p0, Lc2/e;->v:Lt1/p0;

    .line 115
    .line 116
    iget-object p0, p0, Lt1/p0;->v:Lt1/r;

    .line 117
    .line 118
    new-instance p1, Ll4/v;

    .line 119
    .line 120
    const/4 v0, 0x4

    .line 121
    invoke-direct {p1, v3, v4, v1, v0}, Ll4/v;-><init>(JLjava/lang/String;I)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0, p1}, Lt1/r;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    goto :goto_0

    .line 128
    :cond_2
    :goto_1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    return-object p0

    .line 133
    :pswitch_0
    check-cast p1, Lg4/g;

    .line 134
    .line 135
    iget-object v0, p0, Lc2/e;->v:Lt1/p0;

    .line 136
    .line 137
    iget-object p1, p1, Lg4/g;->e:Ljava/lang/String;

    .line 138
    .line 139
    iget-boolean v1, p0, Lc2/e;->w:Z

    .line 140
    .line 141
    iget-boolean p0, p0, Lc2/e;->x:Z

    .line 142
    .line 143
    invoke-static {v0, p1, v1, p0}, Lc2/e;->a1(Lt1/p0;Ljava/lang/String;ZZ)V

    .line 144
    .line 145
    .line 146
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 147
    .line 148
    return-object p0

    .line 149
    :pswitch_1
    check-cast p1, Ljava/util/List;

    .line 150
    .line 151
    iget-object v0, p0, Lc2/e;->v:Lt1/p0;

    .line 152
    .line 153
    invoke-virtual {v0}, Lt1/p0;->d()Lt1/j1;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    if-eqz v0, :cond_3

    .line 158
    .line 159
    iget-object p0, p0, Lc2/e;->v:Lt1/p0;

    .line 160
    .line 161
    invoke-virtual {p0}, Lt1/p0;->d()Lt1/j1;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    iget-object p0, p0, Lt1/j1;->a:Lg4/l0;

    .line 169
    .line 170
    invoke-interface {p1, p0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move v1, v2

    .line 174
    :cond_3
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    return-object p0

    .line 179
    :pswitch_2
    check-cast p1, Lg4/g;

    .line 180
    .line 181
    iget-object v0, p0, Lc2/e;->v:Lt1/p0;

    .line 182
    .line 183
    iget-object v0, v0, Lt1/p0;->t:Ll2/j1;

    .line 184
    .line 185
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 186
    .line 187
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    iget-object v0, p0, Lc2/e;->v:Lt1/p0;

    .line 191
    .line 192
    iget-object v0, v0, Lt1/p0;->s:Ll2/j1;

    .line 193
    .line 194
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    iget-object v0, p0, Lc2/e;->v:Lt1/p0;

    .line 198
    .line 199
    iget-object p1, p1, Lg4/g;->e:Ljava/lang/String;

    .line 200
    .line 201
    iget-boolean v2, p0, Lc2/e;->w:Z

    .line 202
    .line 203
    iget-boolean p0, p0, Lc2/e;->x:Z

    .line 204
    .line 205
    invoke-static {v0, p1, v2, p0}, Lc2/e;->a1(Lt1/p0;Ljava/lang/String;ZZ)V

    .line 206
    .line 207
    .line 208
    return-object v1

    .line 209
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
