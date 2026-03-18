.class public final synthetic Lca/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V
    .locals 0

    .line 1
    iput p1, p0, Lca/e;->d:I

    iput-boolean p6, p0, Lca/e;->e:Z

    iput-object p2, p0, Lca/e;->f:Ljava/lang/Object;

    iput-object p3, p0, Lca/e;->g:Ljava/lang/Object;

    iput-object p4, p0, Lca/e;->h:Ljava/lang/Object;

    iput-object p5, p0, Lca/e;->i:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/b0;Lkotlin/jvm/internal/b0;Lca/g;ZLmx0/l;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lca/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lca/e;->f:Ljava/lang/Object;

    iput-object p2, p0, Lca/e;->g:Ljava/lang/Object;

    iput-object p3, p0, Lca/e;->h:Ljava/lang/Object;

    iput-boolean p4, p0, Lca/e;->e:Z

    iput-object p5, p0, Lca/e;->i:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lca/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lca/e;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lc1/n0;

    .line 9
    .line 10
    iget-object v0, v0, Lc1/n0;->g:Ll2/j1;

    .line 11
    .line 12
    iget-object v1, p0, Lca/e;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Ll2/b1;

    .line 15
    .line 16
    iget-object v2, p0, Lca/e;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v2, Ll2/t2;

    .line 19
    .line 20
    iget-object v3, p0, Lca/e;->i:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v3, Ll2/t2;

    .line 23
    .line 24
    check-cast p1, Le3/k0;

    .line 25
    .line 26
    iget-boolean p0, p0, Lca/e;->e:Z

    .line 27
    .line 28
    const v4, 0x3f4ccccd    # 0.8f

    .line 29
    .line 30
    .line 31
    const/high16 v5, 0x3f800000    # 1.0f

    .line 32
    .line 33
    if-nez p0, :cond_0

    .line 34
    .line 35
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v6

    .line 39
    check-cast v6, Ljava/lang/Number;

    .line 40
    .line 41
    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v6

    .line 50
    check-cast v6, Ljava/lang/Boolean;

    .line 51
    .line 52
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 53
    .line 54
    .line 55
    move-result v6

    .line 56
    if-eqz v6, :cond_1

    .line 57
    .line 58
    move v6, v5

    .line 59
    goto :goto_0

    .line 60
    :cond_1
    move v6, v4

    .line 61
    :goto_0
    invoke-virtual {p1, v6}, Le3/k0;->l(F)V

    .line 62
    .line 63
    .line 64
    if-nez p0, :cond_2

    .line 65
    .line 66
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    check-cast v2, Ljava/lang/Number;

    .line 71
    .line 72
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    goto :goto_1

    .line 77
    :cond_2
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    check-cast v2, Ljava/lang/Boolean;

    .line 82
    .line 83
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    if-eqz v2, :cond_3

    .line 88
    .line 89
    move v4, v5

    .line 90
    :cond_3
    :goto_1
    invoke-virtual {p1, v4}, Le3/k0;->p(F)V

    .line 91
    .line 92
    .line 93
    if-nez p0, :cond_4

    .line 94
    .line 95
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Ljava/lang/Number;

    .line 100
    .line 101
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    goto :goto_2

    .line 106
    :cond_4
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    check-cast p0, Ljava/lang/Boolean;

    .line 111
    .line 112
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    if-eqz p0, :cond_5

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_5
    const/4 v5, 0x0

    .line 120
    :goto_2
    invoke-virtual {p1, v5}, Le3/k0;->b(F)V

    .line 121
    .line 122
    .line 123
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    check-cast p0, Le3/q0;

    .line 128
    .line 129
    iget-wide v0, p0, Le3/q0;->a:J

    .line 130
    .line 131
    invoke-virtual {p1, v0, v1}, Le3/k0;->A(J)V

    .line 132
    .line 133
    .line 134
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 135
    .line 136
    return-object p0

    .line 137
    :pswitch_0
    iget-object v0, p0, Lca/e;->f:Ljava/lang/Object;

    .line 138
    .line 139
    move-object v3, v0

    .line 140
    check-cast v3, Lkw/j;

    .line 141
    .line 142
    iget-object v0, p0, Lca/e;->g:Ljava/lang/Object;

    .line 143
    .line 144
    move-object v4, v0

    .line 145
    check-cast v4, Lkw/l;

    .line 146
    .line 147
    iget-object v0, p0, Lca/e;->h:Ljava/lang/Object;

    .line 148
    .line 149
    move-object v5, v0

    .line 150
    check-cast v5, Lj9/d;

    .line 151
    .line 152
    iget-object v0, p0, Lca/e;->i:Ljava/lang/Object;

    .line 153
    .line 154
    move-object v6, v0

    .line 155
    check-cast v6, Lc1/j;

    .line 156
    .line 157
    check-cast p1, Llx0/l;

    .line 158
    .line 159
    const-string v0, "<destruct>"

    .line 160
    .line 161
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    iget-object v0, p1, Llx0/l;->d:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast v0, Ljava/lang/Number;

    .line 167
    .line 168
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 169
    .line 170
    .line 171
    move-result v7

    .line 172
    iget-object p1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast p1, Ljava/lang/Boolean;

    .line 175
    .line 176
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 177
    .line 178
    .line 179
    move-result v8

    .line 180
    new-instance v1, Lew/i;

    .line 181
    .line 182
    iget-boolean v2, p0, Lca/e;->e:Z

    .line 183
    .line 184
    invoke-direct/range {v1 .. v8}, Lew/i;-><init>(ZLkw/j;Lkw/l;Lj9/d;Lc1/j;FZ)V

    .line 185
    .line 186
    .line 187
    return-object v1

    .line 188
    :pswitch_1
    iget-object v0, p0, Lca/e;->f:Ljava/lang/Object;

    .line 189
    .line 190
    check-cast v0, Lkotlin/jvm/internal/b0;

    .line 191
    .line 192
    iget-object v1, p0, Lca/e;->g:Ljava/lang/Object;

    .line 193
    .line 194
    check-cast v1, Lkotlin/jvm/internal/b0;

    .line 195
    .line 196
    iget-object v2, p0, Lca/e;->h:Ljava/lang/Object;

    .line 197
    .line 198
    check-cast v2, Lca/g;

    .line 199
    .line 200
    iget-object v3, p0, Lca/e;->i:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast v3, Lmx0/l;

    .line 203
    .line 204
    check-cast p1, Lz9/k;

    .line 205
    .line 206
    const-string v4, "entry"

    .line 207
    .line 208
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    const/4 v4, 0x1

    .line 212
    iput-boolean v4, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 213
    .line 214
    iput-boolean v4, v1, Lkotlin/jvm/internal/b0;->d:Z

    .line 215
    .line 216
    iget-boolean p0, p0, Lca/e;->e:Z

    .line 217
    .line 218
    invoke-virtual {v2, p1, p0, v3}, Lca/g;->q(Lz9/k;ZLmx0/l;)V

    .line 219
    .line 220
    .line 221
    goto :goto_3

    .line 222
    nop

    .line 223
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
