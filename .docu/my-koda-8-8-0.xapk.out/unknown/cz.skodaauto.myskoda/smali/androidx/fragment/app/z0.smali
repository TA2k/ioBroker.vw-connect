.class public final Landroidx/fragment/app/z0;
.super Lb/a0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic b:Landroidx/fragment/app/j1;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/j1;)V
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/fragment/app/z0;->b:Landroidx/fragment/app/j1;

    .line 2
    .line 3
    const/4 p1, 0x0

    .line 4
    invoke-direct {p0, p1}, Lb/a0;-><init>(Z)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final handleOnBackCancelled()V
    .locals 4

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    iget-object p0, p0, Landroidx/fragment/app/z0;->b:Landroidx/fragment/app/j1;

    .line 7
    .line 8
    const-string v2, "FragmentManager"

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    new-instance v1, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v3, "handleOnBackCancelled. PREDICTIVE_BACK = true fragment manager "

    .line 15
    .line 16
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-static {v2, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :cond_0
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    new-instance v0, Ljava/lang/StringBuilder;

    .line 36
    .line 37
    const-string v1, "cancelBackStackTransition for transition "

    .line 38
    .line 39
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    iget-object v1, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 52
    .line 53
    .line 54
    :cond_1
    iget-object v0, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 55
    .line 56
    if-eqz v0, :cond_3

    .line 57
    .line 58
    const/4 v1, 0x0

    .line 59
    iput-boolean v1, v0, Landroidx/fragment/app/a;->r:Z

    .line 60
    .line 61
    invoke-virtual {v0}, Landroidx/fragment/app/a;->d()V

    .line 62
    .line 63
    .line 64
    iget-object v0, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 65
    .line 66
    new-instance v2, Landroidx/fragment/app/y;

    .line 67
    .line 68
    const/4 v3, 0x4

    .line 69
    invoke-direct {v2, p0, v3}, Landroidx/fragment/app/y;-><init>(Ljava/lang/Object;I)V

    .line 70
    .line 71
    .line 72
    iget-object v3, v0, Landroidx/fragment/app/a;->p:Ljava/util/ArrayList;

    .line 73
    .line 74
    if-nez v3, :cond_2

    .line 75
    .line 76
    new-instance v3, Ljava/util/ArrayList;

    .line 77
    .line 78
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 79
    .line 80
    .line 81
    iput-object v3, v0, Landroidx/fragment/app/a;->p:Ljava/util/ArrayList;

    .line 82
    .line 83
    :cond_2
    iget-object v0, v0, Landroidx/fragment/app/a;->p:Ljava/util/ArrayList;

    .line 84
    .line 85
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    iget-object v0, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 89
    .line 90
    const/4 v2, 0x1

    .line 91
    invoke-virtual {v0, v1, v2}, Landroidx/fragment/app/a;->e(ZZ)I

    .line 92
    .line 93
    .line 94
    iput-boolean v2, p0, Landroidx/fragment/app/j1;->i:Z

    .line 95
    .line 96
    invoke-virtual {p0, v2}, Landroidx/fragment/app/j1;->z(Z)Z

    .line 97
    .line 98
    .line 99
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->F()V

    .line 100
    .line 101
    .line 102
    iput-boolean v1, p0, Landroidx/fragment/app/j1;->i:Z

    .line 103
    .line 104
    const/4 v0, 0x0

    .line 105
    iput-object v0, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 106
    .line 107
    :cond_3
    return-void
.end method

.method public final handleOnBackPressed()V
    .locals 10

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    iget-object p0, p0, Landroidx/fragment/app/z0;->b:Landroidx/fragment/app/j1;

    .line 7
    .line 8
    const-string v2, "FragmentManager"

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    new-instance v1, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v3, "handleOnBackPressed. PREDICTIVE_BACK = true fragment manager "

    .line 15
    .line 16
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-static {v2, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object v1, p0, Landroidx/fragment/app/j1;->j:Landroidx/fragment/app/z0;

    .line 30
    .line 31
    iget-object v3, p0, Landroidx/fragment/app/j1;->n:Ljava/util/ArrayList;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    iput-boolean v4, p0, Landroidx/fragment/app/j1;->i:Z

    .line 35
    .line 36
    invoke-virtual {p0, v4}, Landroidx/fragment/app/j1;->z(Z)Z

    .line 37
    .line 38
    .line 39
    const/4 v5, 0x0

    .line 40
    iput-boolean v5, p0, Landroidx/fragment/app/j1;->i:Z

    .line 41
    .line 42
    iget-object v6, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 43
    .line 44
    if-eqz v6, :cond_b

    .line 45
    .line 46
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    .line 47
    .line 48
    .line 49
    move-result v6

    .line 50
    const/4 v7, 0x0

    .line 51
    if-nez v6, :cond_3

    .line 52
    .line 53
    new-instance v6, Ljava/util/LinkedHashSet;

    .line 54
    .line 55
    iget-object v8, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 56
    .line 57
    invoke-static {v8}, Landroidx/fragment/app/j1;->G(Landroidx/fragment/app/a;)Ljava/util/HashSet;

    .line 58
    .line 59
    .line 60
    move-result-object v8

    .line 61
    invoke-direct {v6, v8}, Ljava/util/LinkedHashSet;-><init>(Ljava/util/Collection;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 69
    .line 70
    .line 71
    move-result v8

    .line 72
    if-eqz v8, :cond_3

    .line 73
    .line 74
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v8

    .line 78
    if-nez v8, :cond_2

    .line 79
    .line 80
    invoke-interface {v6}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 81
    .line 82
    .line 83
    move-result-object v8

    .line 84
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 85
    .line 86
    .line 87
    move-result v9

    .line 88
    if-nez v9, :cond_1

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_1
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    check-cast p0, Landroidx/fragment/app/j0;

    .line 96
    .line 97
    throw v7

    .line 98
    :cond_2
    new-instance p0, Ljava/lang/ClassCastException;

    .line 99
    .line 100
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 101
    .line 102
    .line 103
    throw p0

    .line 104
    :cond_3
    iget-object v3, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 105
    .line 106
    iget-object v3, v3, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 107
    .line 108
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 109
    .line 110
    .line 111
    move-result-object v3

    .line 112
    :cond_4
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 113
    .line 114
    .line 115
    move-result v6

    .line 116
    if-eqz v6, :cond_5

    .line 117
    .line 118
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v6

    .line 122
    check-cast v6, Landroidx/fragment/app/t1;

    .line 123
    .line 124
    iget-object v6, v6, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 125
    .line 126
    if-eqz v6, :cond_4

    .line 127
    .line 128
    iput-boolean v5, v6, Landroidx/fragment/app/j0;->mTransitioning:Z

    .line 129
    .line 130
    goto :goto_1

    .line 131
    :cond_5
    new-instance v3, Ljava/util/ArrayList;

    .line 132
    .line 133
    iget-object v6, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 134
    .line 135
    invoke-static {v6}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 136
    .line 137
    .line 138
    move-result-object v6

    .line 139
    invoke-direct {v3, v6}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {p0, v3, v5, v4}, Landroidx/fragment/app/j1;->f(Ljava/util/ArrayList;II)Ljava/util/HashSet;

    .line 143
    .line 144
    .line 145
    move-result-object v3

    .line 146
    invoke-virtual {v3}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 151
    .line 152
    .line 153
    move-result v4

    .line 154
    if-eqz v4, :cond_7

    .line 155
    .line 156
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v4

    .line 160
    check-cast v4, Landroidx/fragment/app/r;

    .line 161
    .line 162
    iget-object v5, v4, Landroidx/fragment/app/r;->c:Ljava/util/ArrayList;

    .line 163
    .line 164
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 165
    .line 166
    .line 167
    move-result v6

    .line 168
    if-eqz v6, :cond_6

    .line 169
    .line 170
    const-string v6, "SpecialEffectsController: Completing Back "

    .line 171
    .line 172
    invoke-static {v2, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 173
    .line 174
    .line 175
    :cond_6
    invoke-virtual {v4, v5}, Landroidx/fragment/app/r;->m(Ljava/util/List;)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v4, v5}, Landroidx/fragment/app/r;->c(Ljava/util/List;)V

    .line 179
    .line 180
    .line 181
    goto :goto_2

    .line 182
    :cond_7
    iget-object v3, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 183
    .line 184
    iget-object v3, v3, Landroidx/fragment/app/a;->a:Ljava/util/ArrayList;

    .line 185
    .line 186
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 187
    .line 188
    .line 189
    move-result-object v3

    .line 190
    :cond_8
    :goto_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 191
    .line 192
    .line 193
    move-result v4

    .line 194
    if-eqz v4, :cond_9

    .line 195
    .line 196
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v4

    .line 200
    check-cast v4, Landroidx/fragment/app/t1;

    .line 201
    .line 202
    iget-object v4, v4, Landroidx/fragment/app/t1;->b:Landroidx/fragment/app/j0;

    .line 203
    .line 204
    if-eqz v4, :cond_8

    .line 205
    .line 206
    iget-object v5, v4, Landroidx/fragment/app/j0;->mContainer:Landroid/view/ViewGroup;

    .line 207
    .line 208
    if-nez v5, :cond_8

    .line 209
    .line 210
    invoke-virtual {p0, v4}, Landroidx/fragment/app/j1;->g(Landroidx/fragment/app/j0;)Landroidx/fragment/app/r1;

    .line 211
    .line 212
    .line 213
    move-result-object v4

    .line 214
    invoke-virtual {v4}, Landroidx/fragment/app/r1;->k()V

    .line 215
    .line 216
    .line 217
    goto :goto_3

    .line 218
    :cond_9
    iput-object v7, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 219
    .line 220
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->g0()V

    .line 221
    .line 222
    .line 223
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 224
    .line 225
    .line 226
    move-result v0

    .line 227
    if-eqz v0, :cond_a

    .line 228
    .line 229
    const-string v0, "Op is being set to null"

    .line 230
    .line 231
    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 232
    .line 233
    .line 234
    new-instance v0, Ljava/lang/StringBuilder;

    .line 235
    .line 236
    const-string v3, "OnBackPressedCallback enabled="

    .line 237
    .line 238
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v1}, Lb/a0;->isEnabled()Z

    .line 242
    .line 243
    .line 244
    move-result v1

    .line 245
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 246
    .line 247
    .line 248
    const-string v1, " for  FragmentManager "

    .line 249
    .line 250
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 251
    .line 252
    .line 253
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 254
    .line 255
    .line 256
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 257
    .line 258
    .line 259
    move-result-object p0

    .line 260
    invoke-static {v2, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 261
    .line 262
    .line 263
    :cond_a
    return-void

    .line 264
    :cond_b
    invoke-virtual {v1}, Lb/a0;->isEnabled()Z

    .line 265
    .line 266
    .line 267
    move-result v1

    .line 268
    if-eqz v1, :cond_d

    .line 269
    .line 270
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 271
    .line 272
    .line 273
    move-result v0

    .line 274
    if-eqz v0, :cond_c

    .line 275
    .line 276
    const-string v0, "Calling popBackStackImmediate via onBackPressed callback"

    .line 277
    .line 278
    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 279
    .line 280
    .line 281
    :cond_c
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->S()Z

    .line 282
    .line 283
    .line 284
    return-void

    .line 285
    :cond_d
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 286
    .line 287
    .line 288
    move-result v0

    .line 289
    if-eqz v0, :cond_e

    .line 290
    .line 291
    const-string v0, "Calling onBackPressed via onBackPressed callback"

    .line 292
    .line 293
    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 294
    .line 295
    .line 296
    :cond_e
    iget-object p0, p0, Landroidx/fragment/app/j1;->g:Lb/h0;

    .line 297
    .line 298
    invoke-virtual {p0}, Lb/h0;->c()V

    .line 299
    .line 300
    .line 301
    return-void
.end method

.method public final handleOnBackProgressed(Lb/c;)V
    .locals 10

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    const-string v2, "FragmentManager"

    .line 7
    .line 8
    iget-object p0, p0, Landroidx/fragment/app/z0;->b:Landroidx/fragment/app/j1;

    .line 9
    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    new-instance v1, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v3, "handleOnBackProgressed. PREDICTIVE_BACK = true fragment manager "

    .line 15
    .line 16
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-static {v2, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :cond_0
    iget-object v1, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 30
    .line 31
    if-eqz v1, :cond_6

    .line 32
    .line 33
    new-instance v1, Ljava/util/ArrayList;

    .line 34
    .line 35
    iget-object v3, p0, Landroidx/fragment/app/j1;->h:Landroidx/fragment/app/a;

    .line 36
    .line 37
    invoke-static {v3}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 42
    .line 43
    .line 44
    const/4 v3, 0x0

    .line 45
    const/4 v4, 0x1

    .line 46
    invoke-virtual {p0, v1, v3, v4}, Landroidx/fragment/app/j1;->f(Ljava/util/ArrayList;II)Ljava/util/HashSet;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    :cond_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v4

    .line 58
    if-eqz v4, :cond_4

    .line 59
    .line 60
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    check-cast v4, Landroidx/fragment/app/r;

    .line 65
    .line 66
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    const-string v5, "backEvent"

    .line 70
    .line 71
    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-static {v0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    if-eqz v5, :cond_2

    .line 79
    .line 80
    new-instance v5, Ljava/lang/StringBuilder;

    .line 81
    .line 82
    const-string v6, "SpecialEffectsController: Processing Progress "

    .line 83
    .line 84
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    iget v6, p1, Lb/c;->c:F

    .line 88
    .line 89
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v5

    .line 96
    invoke-static {v2, v5}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 97
    .line 98
    .line 99
    :cond_2
    iget-object v5, v4, Landroidx/fragment/app/r;->c:Ljava/util/ArrayList;

    .line 100
    .line 101
    new-instance v6, Ljava/util/ArrayList;

    .line 102
    .line 103
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 107
    .line 108
    .line 109
    move-result-object v5

    .line 110
    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 111
    .line 112
    .line 113
    move-result v7

    .line 114
    if-eqz v7, :cond_3

    .line 115
    .line 116
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v7

    .line 120
    check-cast v7, Landroidx/fragment/app/g2;

    .line 121
    .line 122
    iget-object v7, v7, Landroidx/fragment/app/g2;->k:Ljava/util/ArrayList;

    .line 123
    .line 124
    invoke-static {v7, v6}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 125
    .line 126
    .line 127
    goto :goto_0

    .line 128
    :cond_3
    invoke-static {v6}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    check-cast v5, Ljava/lang/Iterable;

    .line 133
    .line 134
    invoke-static {v5}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 135
    .line 136
    .line 137
    move-result-object v5

    .line 138
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 139
    .line 140
    .line 141
    move-result v6

    .line 142
    move v7, v3

    .line 143
    :goto_1
    if-ge v7, v6, :cond_1

    .line 144
    .line 145
    invoke-interface {v5, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v8

    .line 149
    check-cast v8, Landroidx/fragment/app/f2;

    .line 150
    .line 151
    iget-object v9, v4, Landroidx/fragment/app/r;->a:Landroid/view/ViewGroup;

    .line 152
    .line 153
    invoke-virtual {v8, p1, v9}, Landroidx/fragment/app/f2;->d(Lb/c;Landroid/view/ViewGroup;)V

    .line 154
    .line 155
    .line 156
    add-int/lit8 v7, v7, 0x1

    .line 157
    .line 158
    goto :goto_1

    .line 159
    :cond_4
    iget-object p0, p0, Landroidx/fragment/app/j1;->n:Ljava/util/ArrayList;

    .line 160
    .line 161
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 166
    .line 167
    .line 168
    move-result p1

    .line 169
    if-nez p1, :cond_5

    .line 170
    .line 171
    goto :goto_2

    .line 172
    :cond_5
    invoke-static {p0}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    throw p0

    .line 177
    :cond_6
    :goto_2
    return-void
.end method

.method public final handleOnBackStarted(Lb/c;)V
    .locals 1

    .line 1
    const/4 p1, 0x3

    .line 2
    invoke-static {p1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 3
    .line 4
    .line 5
    move-result p1

    .line 6
    iget-object p0, p0, Landroidx/fragment/app/z0;->b:Landroidx/fragment/app/j1;

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    new-instance p1, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v0, "handleOnBackStarted. PREDICTIVE_BACK = true fragment manager "

    .line 13
    .line 14
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    const-string v0, "FragmentManager"

    .line 25
    .line 26
    invoke-static {v0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 27
    .line 28
    .line 29
    :cond_0
    invoke-virtual {p0}, Landroidx/fragment/app/j1;->w()V

    .line 30
    .line 31
    .line 32
    new-instance p1, Landroidx/fragment/app/i1;

    .line 33
    .line 34
    invoke-direct {p1, p0}, Landroidx/fragment/app/i1;-><init>(Landroidx/fragment/app/j1;)V

    .line 35
    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-virtual {p0, p1, v0}, Landroidx/fragment/app/j1;->x(Landroidx/fragment/app/g1;Z)V

    .line 39
    .line 40
    .line 41
    return-void
.end method
