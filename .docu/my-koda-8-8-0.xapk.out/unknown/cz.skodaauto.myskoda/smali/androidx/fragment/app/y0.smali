.class public final Landroidx/fragment/app/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le/b;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Landroidx/fragment/app/j1;


# direct methods
.method public synthetic constructor <init>(Landroidx/fragment/app/j1;I)V
    .locals 0

    .line 1
    iput p2, p0, Landroidx/fragment/app/y0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Landroidx/fragment/app/y0;->e:Landroidx/fragment/app/j1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)V
    .locals 5

    .line 1
    iget v0, p0, Landroidx/fragment/app/y0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Le/a;

    .line 7
    .line 8
    iget-object v0, p0, Landroidx/fragment/app/y0;->e:Landroidx/fragment/app/j1;

    .line 9
    .line 10
    iget-object v1, v0, Landroidx/fragment/app/j1;->F:Ljava/util/ArrayDeque;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->pollFirst()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    check-cast v1, Landroidx/fragment/app/f1;

    .line 17
    .line 18
    const-string v2, "FragmentManager"

    .line 19
    .line 20
    if-nez v1, :cond_0

    .line 21
    .line 22
    new-instance p1, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v0, "No IntentSenders were started for "

    .line 25
    .line 26
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {v2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    iget-object p0, v1, Landroidx/fragment/app/f1;->d:Ljava/lang/String;

    .line 41
    .line 42
    iget v1, v1, Landroidx/fragment/app/f1;->e:I

    .line 43
    .line 44
    iget-object v0, v0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 45
    .line 46
    invoke-virtual {v0, p0}, Landroidx/fragment/app/s1;->c(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    if-nez v0, :cond_1

    .line 51
    .line 52
    new-instance p1, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    const-string v0, "Intent Sender result delivered for unknown Fragment "

    .line 55
    .line 56
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-static {v2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_1
    iget p0, p1, Le/a;->d:I

    .line 71
    .line 72
    iget-object p1, p1, Le/a;->e:Landroid/content/Intent;

    .line 73
    .line 74
    invoke-virtual {v0, v1, p0, p1}, Landroidx/fragment/app/j0;->onActivityResult(IILandroid/content/Intent;)V

    .line 75
    .line 76
    .line 77
    :goto_0
    return-void

    .line 78
    :pswitch_0
    check-cast p1, Le/a;

    .line 79
    .line 80
    iget-object v0, p0, Landroidx/fragment/app/y0;->e:Landroidx/fragment/app/j1;

    .line 81
    .line 82
    iget-object v1, v0, Landroidx/fragment/app/j1;->F:Ljava/util/ArrayDeque;

    .line 83
    .line 84
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->pollLast()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    check-cast v1, Landroidx/fragment/app/f1;

    .line 89
    .line 90
    const-string v2, "FragmentManager"

    .line 91
    .line 92
    if-nez v1, :cond_2

    .line 93
    .line 94
    new-instance p1, Ljava/lang/StringBuilder;

    .line 95
    .line 96
    const-string v0, "No Activities were started for result for "

    .line 97
    .line 98
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    invoke-static {v2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 109
    .line 110
    .line 111
    goto :goto_1

    .line 112
    :cond_2
    iget-object p0, v1, Landroidx/fragment/app/f1;->d:Ljava/lang/String;

    .line 113
    .line 114
    iget v1, v1, Landroidx/fragment/app/f1;->e:I

    .line 115
    .line 116
    iget-object v0, v0, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 117
    .line 118
    invoke-virtual {v0, p0}, Landroidx/fragment/app/s1;->c(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    if-nez v0, :cond_3

    .line 123
    .line 124
    new-instance p1, Ljava/lang/StringBuilder;

    .line 125
    .line 126
    const-string v0, "Activity result delivered for unknown Fragment "

    .line 127
    .line 128
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    invoke-static {v2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 139
    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_3
    iget p0, p1, Le/a;->d:I

    .line 143
    .line 144
    iget-object p1, p1, Le/a;->e:Landroid/content/Intent;

    .line 145
    .line 146
    invoke-virtual {v0, v1, p0, p1}, Landroidx/fragment/app/j0;->onActivityResult(IILandroid/content/Intent;)V

    .line 147
    .line 148
    .line 149
    :goto_1
    return-void

    .line 150
    :pswitch_1
    check-cast p1, Ljava/util/Map;

    .line 151
    .line 152
    invoke-interface {p1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    const/4 v1, 0x0

    .line 157
    new-array v2, v1, [Ljava/lang/String;

    .line 158
    .line 159
    invoke-interface {v0, v2}, Ljava/util/Set;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    check-cast v0, [Ljava/lang/String;

    .line 164
    .line 165
    new-instance v2, Ljava/util/ArrayList;

    .line 166
    .line 167
    invoke-interface {p1}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 168
    .line 169
    .line 170
    move-result-object p1

    .line 171
    invoke-direct {v2, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 175
    .line 176
    .line 177
    move-result p1

    .line 178
    new-array p1, p1, [I

    .line 179
    .line 180
    move v3, v1

    .line 181
    :goto_2
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 182
    .line 183
    .line 184
    move-result v4

    .line 185
    if-ge v3, v4, :cond_5

    .line 186
    .line 187
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v4

    .line 191
    check-cast v4, Ljava/lang/Boolean;

    .line 192
    .line 193
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 194
    .line 195
    .line 196
    move-result v4

    .line 197
    if-eqz v4, :cond_4

    .line 198
    .line 199
    move v4, v1

    .line 200
    goto :goto_3

    .line 201
    :cond_4
    const/4 v4, -0x1

    .line 202
    :goto_3
    aput v4, p1, v3

    .line 203
    .line 204
    add-int/lit8 v3, v3, 0x1

    .line 205
    .line 206
    goto :goto_2

    .line 207
    :cond_5
    iget-object v1, p0, Landroidx/fragment/app/y0;->e:Landroidx/fragment/app/j1;

    .line 208
    .line 209
    iget-object v2, v1, Landroidx/fragment/app/j1;->F:Ljava/util/ArrayDeque;

    .line 210
    .line 211
    invoke-virtual {v2}, Ljava/util/ArrayDeque;->pollFirst()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v2

    .line 215
    check-cast v2, Landroidx/fragment/app/f1;

    .line 216
    .line 217
    const-string v3, "FragmentManager"

    .line 218
    .line 219
    if-nez v2, :cond_6

    .line 220
    .line 221
    new-instance p1, Ljava/lang/StringBuilder;

    .line 222
    .line 223
    const-string v0, "No permissions were requested for "

    .line 224
    .line 225
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    invoke-static {v3, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 236
    .line 237
    .line 238
    goto :goto_4

    .line 239
    :cond_6
    iget-object p0, v2, Landroidx/fragment/app/f1;->d:Ljava/lang/String;

    .line 240
    .line 241
    iget v2, v2, Landroidx/fragment/app/f1;->e:I

    .line 242
    .line 243
    iget-object v1, v1, Landroidx/fragment/app/j1;->c:Landroidx/fragment/app/s1;

    .line 244
    .line 245
    invoke-virtual {v1, p0}, Landroidx/fragment/app/s1;->c(Ljava/lang/String;)Landroidx/fragment/app/j0;

    .line 246
    .line 247
    .line 248
    move-result-object v1

    .line 249
    if-nez v1, :cond_7

    .line 250
    .line 251
    new-instance p1, Ljava/lang/StringBuilder;

    .line 252
    .line 253
    const-string v0, "Permission request result delivered for unknown Fragment "

    .line 254
    .line 255
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 259
    .line 260
    .line 261
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 262
    .line 263
    .line 264
    move-result-object p0

    .line 265
    invoke-static {v3, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 266
    .line 267
    .line 268
    goto :goto_4

    .line 269
    :cond_7
    invoke-virtual {v1, v2, v0, p1}, Landroidx/fragment/app/j0;->onRequestPermissionsResult(I[Ljava/lang/String;[I)V

    .line 270
    .line 271
    .line 272
    :goto_4
    return-void

    .line 273
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
