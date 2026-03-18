.class public final Landroidx/fragment/app/o;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p5, p0, Landroidx/fragment/app/o;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Landroidx/fragment/app/o;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Landroidx/fragment/app/o;->h:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Landroidx/fragment/app/o;->i:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Landroidx/fragment/app/o;->j:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Landroidx/fragment/app/o;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/o;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lx4/r;

    .line 9
    .line 10
    iget-object v1, p0, Landroidx/fragment/app/o;->h:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lay0/a;

    .line 13
    .line 14
    iget-object v2, p0, Landroidx/fragment/app/o;->i:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Lx4/p;

    .line 17
    .line 18
    iget-object p0, p0, Landroidx/fragment/app/o;->j:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lt4/m;

    .line 21
    .line 22
    invoke-virtual {v0, v1, v2, p0}, Lx4/r;->d(Lay0/a;Lx4/p;Lt4/m;)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_0
    iget-object v0, p0, Landroidx/fragment/app/o;->g:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v0, Lkn/k0;

    .line 31
    .line 32
    iget-object v1, p0, Landroidx/fragment/app/o;->h:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lay0/a;

    .line 35
    .line 36
    iget-object v2, p0, Landroidx/fragment/app/o;->i:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v2, Lkn/j0;

    .line 39
    .line 40
    iget-object p0, p0, Landroidx/fragment/app/o;->j:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Lt4/m;

    .line 43
    .line 44
    invoke-virtual {v0, v1, v2, p0}, Lkn/k0;->d(Lay0/a;Lkn/j0;Lt4/m;)V

    .line 45
    .line 46
    .line 47
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_1
    iget-object v0, p0, Landroidx/fragment/app/o;->i:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v0, Landroid/content/Intent;

    .line 53
    .line 54
    iget-object v1, p0, Landroidx/fragment/app/o;->h:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v1, Landroid/app/Activity;

    .line 57
    .line 58
    iget-object v2, p0, Landroidx/fragment/app/o;->g:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v2, Ljava/lang/String;

    .line 61
    .line 62
    if-eqz v2, :cond_9

    .line 63
    .line 64
    const-string v3, "ACTIVITY"

    .line 65
    .line 66
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    if-eqz v3, :cond_0

    .line 71
    .line 72
    const/4 v2, 0x1

    .line 73
    goto :goto_0

    .line 74
    :cond_0
    const-string v3, "BROADCAST"

    .line 75
    .line 76
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    if-eqz v3, :cond_1

    .line 81
    .line 82
    const/4 v2, 0x2

    .line 83
    goto :goto_0

    .line 84
    :cond_1
    const-string v3, "SERVICE"

    .line 85
    .line 86
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    if-eqz v3, :cond_2

    .line 91
    .line 92
    const/4 v2, 0x3

    .line 93
    goto :goto_0

    .line 94
    :cond_2
    const-string v3, "FOREGROUND_SERVICE"

    .line 95
    .line 96
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    if-eqz v3, :cond_3

    .line 101
    .line 102
    const/4 v2, 0x4

    .line 103
    goto :goto_0

    .line 104
    :cond_3
    const-string v3, "CALLBACK"

    .line 105
    .line 106
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v3

    .line 110
    if-eqz v3, :cond_8

    .line 111
    .line 112
    const/4 v2, 0x5

    .line 113
    :goto_0
    invoke-static {v2}, Lu/w;->o(I)I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    if-eqz v2, :cond_7

    .line 118
    .line 119
    const/4 p0, 0x1

    .line 120
    if-eq v2, p0, :cond_6

    .line 121
    .line 122
    const/4 p0, 0x2

    .line 123
    if-eq v2, p0, :cond_5

    .line 124
    .line 125
    const/4 p0, 0x3

    .line 126
    if-eq v2, p0, :cond_4

    .line 127
    .line 128
    const/4 p0, 0x4

    .line 129
    if-eq v2, p0, :cond_6

    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_4
    sget-object p0, Lb7/c;->a:Lb7/c;

    .line 133
    .line 134
    invoke-virtual {p0, v1, v0}, Lb7/c;->a(Landroid/content/Context;Landroid/content/Intent;)V

    .line 135
    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_5
    invoke-virtual {v1, v0}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    .line 139
    .line 140
    .line 141
    goto :goto_1

    .line 142
    :cond_6
    invoke-virtual {v1, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V

    .line 143
    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_7
    iget-object p0, p0, Landroidx/fragment/app/o;->j:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast p0, Landroid/os/Bundle;

    .line 149
    .line 150
    invoke-virtual {v1, v0, p0}, Landroid/app/Activity;->startActivity(Landroid/content/Intent;Landroid/os/Bundle;)V

    .line 151
    .line 152
    .line 153
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 154
    .line 155
    return-object p0

    .line 156
    :cond_8
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 157
    .line 158
    const-string v0, "No enum constant androidx.glance.appwidget.action.ActionTrampolineType."

    .line 159
    .line 160
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    throw p0

    .line 168
    :cond_9
    new-instance p0, Ljava/lang/NullPointerException;

    .line 169
    .line 170
    const-string v0, "Name is null"

    .line 171
    .line 172
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    throw p0

    .line 176
    :pswitch_2
    iget-object v0, p0, Landroidx/fragment/app/o;->h:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v0, Landroid/view/ViewGroup;

    .line 179
    .line 180
    iget-object v1, p0, Landroidx/fragment/app/o;->g:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast v1, Landroidx/fragment/app/p;

    .line 183
    .line 184
    const/4 v2, 0x2

    .line 185
    invoke-static {v2}, Landroidx/fragment/app/j1;->L(I)Z

    .line 186
    .line 187
    .line 188
    move-result v3

    .line 189
    const-string v4, "FragmentManager"

    .line 190
    .line 191
    if-eqz v3, :cond_a

    .line 192
    .line 193
    const-string v3, "Attempting to create TransitionSeekController"

    .line 194
    .line 195
    invoke-static {v4, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 196
    .line 197
    .line 198
    :cond_a
    iget-object v3, v1, Landroidx/fragment/app/p;->f:Landroidx/fragment/app/b2;

    .line 199
    .line 200
    iget-object v5, p0, Landroidx/fragment/app/o;->i:Ljava/lang/Object;

    .line 201
    .line 202
    invoke-virtual {v3, v0, v5}, Landroidx/fragment/app/b2;->i(Landroid/view/ViewGroup;Ljava/lang/Object;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v3

    .line 206
    iput-object v3, v1, Landroidx/fragment/app/p;->q:Ljava/lang/Object;

    .line 207
    .line 208
    if-nez v3, :cond_c

    .line 209
    .line 210
    invoke-static {v2}, Landroidx/fragment/app/j1;->L(I)Z

    .line 211
    .line 212
    .line 213
    move-result p0

    .line 214
    if-eqz p0, :cond_b

    .line 215
    .line 216
    const-string p0, "TransitionSeekController was not created."

    .line 217
    .line 218
    invoke-static {v4, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 219
    .line 220
    .line 221
    :cond_b
    const/4 p0, 0x1

    .line 222
    iput-boolean p0, v1, Landroidx/fragment/app/p;->r:Z

    .line 223
    .line 224
    goto :goto_2

    .line 225
    :cond_c
    iget-object p0, p0, Landroidx/fragment/app/o;->j:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast p0, Lkotlin/jvm/internal/f0;

    .line 228
    .line 229
    new-instance v3, Landroidx/fragment/app/n;

    .line 230
    .line 231
    invoke-direct {v3, v1, v5, v0}, Landroidx/fragment/app/n;-><init>(Landroidx/fragment/app/p;Ljava/lang/Object;Landroid/view/ViewGroup;)V

    .line 232
    .line 233
    .line 234
    iput-object v3, p0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 235
    .line 236
    invoke-static {v2}, Landroidx/fragment/app/j1;->L(I)Z

    .line 237
    .line 238
    .line 239
    move-result p0

    .line 240
    if-eqz p0, :cond_d

    .line 241
    .line 242
    new-instance p0, Ljava/lang/StringBuilder;

    .line 243
    .line 244
    const-string v0, "Started executing operations from "

    .line 245
    .line 246
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    iget-object v0, v1, Landroidx/fragment/app/p;->d:Landroidx/fragment/app/g2;

    .line 250
    .line 251
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 252
    .line 253
    .line 254
    const-string v0, " to "

    .line 255
    .line 256
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 257
    .line 258
    .line 259
    iget-object v0, v1, Landroidx/fragment/app/p;->e:Landroidx/fragment/app/g2;

    .line 260
    .line 261
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 262
    .line 263
    .line 264
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 265
    .line 266
    .line 267
    move-result-object p0

    .line 268
    invoke-static {v4, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 269
    .line 270
    .line 271
    :cond_d
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 272
    .line 273
    return-object p0

    .line 274
    nop

    .line 275
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
