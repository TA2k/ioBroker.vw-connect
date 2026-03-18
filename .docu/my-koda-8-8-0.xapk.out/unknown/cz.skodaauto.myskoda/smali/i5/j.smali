.class public final Li5/j;
.super Li5/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a(Li5/e;)V
    .locals 2

    .line 1
    iget-object p1, p0, Li5/p;->h:Li5/g;

    .line 2
    .line 3
    iget-boolean v0, p1, Li5/g;->c:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget-boolean v0, p1, Li5/g;->j:Z

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    :goto_0
    return-void

    .line 13
    :cond_1
    iget-object v0, p1, Li5/g;->l:Ljava/util/ArrayList;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Li5/g;

    .line 21
    .line 22
    iget-object p0, p0, Li5/p;->b:Lh5/d;

    .line 23
    .line 24
    check-cast p0, Lh5/h;

    .line 25
    .line 26
    iget v0, v0, Li5/g;->g:I

    .line 27
    .line 28
    int-to-float v0, v0

    .line 29
    iget p0, p0, Lh5/h;->r0:F

    .line 30
    .line 31
    mul-float/2addr v0, p0

    .line 32
    const/high16 p0, 0x3f000000    # 0.5f

    .line 33
    .line 34
    add-float/2addr v0, p0

    .line 35
    float-to-int p0, v0

    .line 36
    invoke-virtual {p1, p0}, Li5/g;->d(I)V

    .line 37
    .line 38
    .line 39
    return-void
.end method

.method public final d()V
    .locals 7

    .line 1
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lh5/h;

    .line 5
    .line 6
    iget v2, v1, Lh5/h;->s0:I

    .line 7
    .line 8
    iget v3, v1, Lh5/h;->t0:I

    .line 9
    .line 10
    iget v1, v1, Lh5/h;->v0:I

    .line 11
    .line 12
    const/4 v4, -0x1

    .line 13
    iget-object v5, p0, Li5/p;->h:Li5/g;

    .line 14
    .line 15
    const/4 v6, 0x1

    .line 16
    if-ne v1, v6, :cond_2

    .line 17
    .line 18
    if-eq v2, v4, :cond_0

    .line 19
    .line 20
    iget-object v1, v5, Li5/g;->l:Ljava/util/ArrayList;

    .line 21
    .line 22
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 23
    .line 24
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 25
    .line 26
    iget-object v0, v0, Li5/p;->h:Li5/g;

    .line 27
    .line 28
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 32
    .line 33
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 34
    .line 35
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 36
    .line 37
    iget-object v0, v0, Li5/p;->h:Li5/g;

    .line 38
    .line 39
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 40
    .line 41
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    iput v2, v5, Li5/g;->f:I

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    if-eq v3, v4, :cond_1

    .line 48
    .line 49
    iget-object v1, v5, Li5/g;->l:Ljava/util/ArrayList;

    .line 50
    .line 51
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 52
    .line 53
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 54
    .line 55
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 56
    .line 57
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 61
    .line 62
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 63
    .line 64
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 65
    .line 66
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 67
    .line 68
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 69
    .line 70
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    neg-int v0, v3

    .line 74
    iput v0, v5, Li5/g;->f:I

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_1
    iput-boolean v6, v5, Li5/g;->b:Z

    .line 78
    .line 79
    iget-object v1, v5, Li5/g;->l:Ljava/util/ArrayList;

    .line 80
    .line 81
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 82
    .line 83
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 84
    .line 85
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 86
    .line 87
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 91
    .line 92
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 93
    .line 94
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 95
    .line 96
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 97
    .line 98
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 99
    .line 100
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    :goto_0
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 104
    .line 105
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 106
    .line 107
    iget-object v0, v0, Li5/p;->h:Li5/g;

    .line 108
    .line 109
    invoke-virtual {p0, v0}, Li5/j;->m(Li5/g;)V

    .line 110
    .line 111
    .line 112
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 113
    .line 114
    iget-object v0, v0, Lh5/d;->d:Li5/l;

    .line 115
    .line 116
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 117
    .line 118
    invoke-virtual {p0, v0}, Li5/j;->m(Li5/g;)V

    .line 119
    .line 120
    .line 121
    return-void

    .line 122
    :cond_2
    if-eq v2, v4, :cond_3

    .line 123
    .line 124
    iget-object v1, v5, Li5/g;->l:Ljava/util/ArrayList;

    .line 125
    .line 126
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 127
    .line 128
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 129
    .line 130
    iget-object v0, v0, Li5/p;->h:Li5/g;

    .line 131
    .line 132
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 136
    .line 137
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 138
    .line 139
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 140
    .line 141
    iget-object v0, v0, Li5/p;->h:Li5/g;

    .line 142
    .line 143
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 144
    .line 145
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    iput v2, v5, Li5/g;->f:I

    .line 149
    .line 150
    goto :goto_1

    .line 151
    :cond_3
    if-eq v3, v4, :cond_4

    .line 152
    .line 153
    iget-object v1, v5, Li5/g;->l:Ljava/util/ArrayList;

    .line 154
    .line 155
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 156
    .line 157
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 158
    .line 159
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 160
    .line 161
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 165
    .line 166
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 167
    .line 168
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 169
    .line 170
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 171
    .line 172
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 173
    .line 174
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    neg-int v0, v3

    .line 178
    iput v0, v5, Li5/g;->f:I

    .line 179
    .line 180
    goto :goto_1

    .line 181
    :cond_4
    iput-boolean v6, v5, Li5/g;->b:Z

    .line 182
    .line 183
    iget-object v1, v5, Li5/g;->l:Ljava/util/ArrayList;

    .line 184
    .line 185
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 186
    .line 187
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 188
    .line 189
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 190
    .line 191
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 192
    .line 193
    .line 194
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 195
    .line 196
    iget-object v0, v0, Lh5/d;->U:Lh5/e;

    .line 197
    .line 198
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 199
    .line 200
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 201
    .line 202
    iget-object v0, v0, Li5/g;->k:Ljava/util/ArrayList;

    .line 203
    .line 204
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    :goto_1
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 208
    .line 209
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 210
    .line 211
    iget-object v0, v0, Li5/p;->h:Li5/g;

    .line 212
    .line 213
    invoke-virtual {p0, v0}, Li5/j;->m(Li5/g;)V

    .line 214
    .line 215
    .line 216
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 217
    .line 218
    iget-object v0, v0, Lh5/d;->e:Li5/n;

    .line 219
    .line 220
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 221
    .line 222
    invoke-virtual {p0, v0}, Li5/j;->m(Li5/g;)V

    .line 223
    .line 224
    .line 225
    return-void
.end method

.method public final e()V
    .locals 3

    .line 1
    iget-object v0, p0, Li5/p;->b:Lh5/d;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lh5/h;

    .line 5
    .line 6
    iget v1, v1, Lh5/h;->v0:I

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    iget-object p0, p0, Li5/p;->h:Li5/g;

    .line 10
    .line 11
    if-ne v1, v2, :cond_0

    .line 12
    .line 13
    iget p0, p0, Li5/g;->g:I

    .line 14
    .line 15
    iput p0, v0, Lh5/d;->Z:I

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget p0, p0, Li5/g;->g:I

    .line 19
    .line 20
    iput p0, v0, Lh5/d;->a0:I

    .line 21
    .line 22
    return-void
.end method

.method public final f()V
    .locals 0

    .line 1
    iget-object p0, p0, Li5/p;->h:Li5/g;

    .line 2
    .line 3
    invoke-virtual {p0}, Li5/g;->c()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final k()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final m(Li5/g;)V
    .locals 1

    .line 1
    iget-object p0, p0, Li5/p;->h:Li5/g;

    .line 2
    .line 3
    iget-object v0, p0, Li5/g;->k:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    iget-object p1, p1, Li5/g;->l:Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-void
.end method
