.class public final synthetic La8/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(La8/q0;IZ)V
    .locals 0

    .line 1
    const/4 p3, 0x0

    iput p3, p0, La8/j0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/j0;->f:Ljava/lang/Object;

    iput p2, p0, La8/j0;->e:I

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;II)V
    .locals 0

    .line 2
    iput p3, p0, La8/j0;->d:I

    iput-object p1, p0, La8/j0;->f:Ljava/lang/Object;

    iput p2, p0, La8/j0;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 6

    .line 1
    iget v0, p0, La8/j0;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    packed-switch v0, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, La8/j0;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 10
    .line 11
    iget p0, p0, La8/j0;->e:I

    .line 12
    .line 13
    iget-object v2, v0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 14
    .line 15
    invoke-virtual {v2}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Landroid/view/View;

    .line 20
    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    invoke-virtual {v0, v2, p0, v1}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->t(Landroid/view/View;IZ)V

    .line 24
    .line 25
    .line 26
    :cond_0
    return-void

    .line 27
    :pswitch_0
    iget-object v0, p0, La8/j0;->f:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v0, Ljava/util/LinkedHashSet;

    .line 30
    .line 31
    iget p0, p0, La8/j0;->e:I

    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_3

    .line 42
    .line 43
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    check-cast v1, Lu/g1;

    .line 48
    .line 49
    const/4 v2, 0x5

    .line 50
    if-ne p0, v2, :cond_2

    .line 51
    .line 52
    iget-object v2, v1, Lu/g1;->o:Ljava/lang/Object;

    .line 53
    .line 54
    monitor-enter v2

    .line 55
    :try_start_0
    invoke-virtual {v1}, Lu/g1;->l()Z

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-eqz v3, :cond_1

    .line 60
    .line 61
    iget-object v3, v1, Lu/g1;->p:Ljava/util/ArrayList;

    .line 62
    .line 63
    if-eqz v3, :cond_1

    .line 64
    .line 65
    const-string v3, "Close DeferrableSurfaces for CameraDevice error."

    .line 66
    .line 67
    invoke-virtual {v1, v3}, Lu/g1;->k(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    iget-object v1, v1, Lu/g1;->p:Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    if-eqz v3, :cond_1

    .line 81
    .line 82
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    check-cast v3, Lh0/t0;

    .line 87
    .line 88
    invoke-virtual {v3}, Lh0/t0;->a()V

    .line 89
    .line 90
    .line 91
    goto :goto_1

    .line 92
    :catchall_0
    move-exception p0

    .line 93
    goto :goto_2

    .line 94
    :cond_1
    monitor-exit v2

    .line 95
    goto :goto_0

    .line 96
    :goto_2
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 97
    throw p0

    .line 98
    :cond_2
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_3
    return-void

    .line 103
    :pswitch_1
    iget-object v0, p0, La8/j0;->f:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast v0, Lh0/m;

    .line 106
    .line 107
    iget p0, p0, La8/j0;->e:I

    .line 108
    .line 109
    invoke-virtual {v0, p0}, Lh0/m;->a(I)V

    .line 110
    .line 111
    .line 112
    return-void

    .line 113
    :pswitch_2
    iget-object v0, p0, La8/j0;->f:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v0, Lp5/b;

    .line 116
    .line 117
    iget p0, p0, La8/j0;->e:I

    .line 118
    .line 119
    invoke-virtual {v0, p0}, Lp5/b;->h(I)V

    .line 120
    .line 121
    .line 122
    return-void

    .line 123
    :pswitch_3
    iget-object v0, p0, La8/j0;->f:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v0, Lc2/k;

    .line 126
    .line 127
    iget p0, p0, La8/j0;->e:I

    .line 128
    .line 129
    const-string v1, "$updateType"

    .line 130
    .line 131
    invoke-static {p0, v1}, Lia/b;->q(ILjava/lang/String;)V

    .line 132
    .line 133
    .line 134
    sget-object v1, Ldx/l;->d:Ldx/l;

    .line 135
    .line 136
    invoke-virtual {v0, p0, v1}, Lc2/k;->y(ILdx/l;)V

    .line 137
    .line 138
    .line 139
    return-void

    .line 140
    :pswitch_4
    iget-object v0, p0, La8/j0;->f:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v0, Lb81/d;

    .line 143
    .line 144
    iget p0, p0, La8/j0;->e:I

    .line 145
    .line 146
    iget-object v0, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast v0, La8/f0;

    .line 149
    .line 150
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 151
    .line 152
    iget-object v0, v0, La8/f0;->d:La8/i0;

    .line 153
    .line 154
    iget-object v0, v0, La8/i0;->J:Lca/j;

    .line 155
    .line 156
    new-instance v2, La8/w;

    .line 157
    .line 158
    const/4 v3, 0x2

    .line 159
    invoke-direct {v2, p0, v3}, La8/w;-><init>(II)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 163
    .line 164
    .line 165
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 166
    .line 167
    .line 168
    move-result-object v3

    .line 169
    iget-object v4, v0, Lca/j;->c:Ljava/lang/Object;

    .line 170
    .line 171
    check-cast v4, Lw7/t;

    .line 172
    .line 173
    iget-object v4, v4, Lw7/t;->a:Landroid/os/Handler;

    .line 174
    .line 175
    invoke-virtual {v4}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 176
    .line 177
    .line 178
    move-result-object v4

    .line 179
    const/4 v5, 0x1

    .line 180
    if-ne v3, v4, :cond_4

    .line 181
    .line 182
    move v1, v5

    .line 183
    :cond_4
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 184
    .line 185
    .line 186
    iget v1, v0, Lca/j;->a:I

    .line 187
    .line 188
    add-int/2addr v1, v5

    .line 189
    iput v1, v0, Lca/j;->a:I

    .line 190
    .line 191
    new-instance v1, Lno/nordicsemi/android/ble/o0;

    .line 192
    .line 193
    const/16 v3, 0x18

    .line 194
    .line 195
    invoke-direct {v1, v3, v0, v2}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v0, v1}, Lca/j;->k(Ljava/lang/Runnable;)V

    .line 199
    .line 200
    .line 201
    iget-object v1, v0, Lca/j;->e:Ljava/lang/Object;

    .line 202
    .line 203
    check-cast v1, Ljava/lang/Integer;

    .line 204
    .line 205
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    invoke-virtual {v0, p0}, Lca/j;->q(Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    return-void

    .line 213
    :pswitch_5
    iget-object v0, p0, La8/j0;->f:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast v0, Ljava/util/function/IntConsumer;

    .line 216
    .line 217
    iget p0, p0, La8/j0;->e:I

    .line 218
    .line 219
    invoke-interface {v0, p0}, Ljava/util/function/IntConsumer;->accept(I)V

    .line 220
    .line 221
    .line 222
    return-void

    .line 223
    :pswitch_6
    iget-object v0, p0, La8/j0;->f:Ljava/lang/Object;

    .line 224
    .line 225
    check-cast v0, La8/q0;

    .line 226
    .line 227
    iget p0, p0, La8/j0;->e:I

    .line 228
    .line 229
    iget-object v1, v0, La8/q0;->z:Lb8/e;

    .line 230
    .line 231
    iget-object v0, v0, La8/q0;->d:[La8/p1;

    .line 232
    .line 233
    aget-object p0, v0, p0

    .line 234
    .line 235
    iget-object p0, p0, La8/p1;->e:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast p0, La8/f;

    .line 238
    .line 239
    iget p0, p0, La8/f;->e:I

    .line 240
    .line 241
    invoke-virtual {v1}, Lb8/e;->L()Lb8/a;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    new-instance v0, La6/a;

    .line 246
    .line 247
    const/16 v2, 0x10

    .line 248
    .line 249
    invoke-direct {v0, v2}, La6/a;-><init>(I)V

    .line 250
    .line 251
    .line 252
    const/16 v2, 0x409

    .line 253
    .line 254
    invoke-virtual {v1, p0, v2, v0}, Lb8/e;->M(Lb8/a;ILw7/j;)V

    .line 255
    .line 256
    .line 257
    return-void

    .line 258
    nop

    .line 259
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
