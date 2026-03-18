.class public final synthetic Lvp/g4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lvp/g4;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lvp/g4;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 9

    .line 1
    iget v0, p0, Lvp/g4;->d:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x1

    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lvp/g4;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lcom/google/android/material/textfield/TextInputLayout;

    .line 11
    .line 12
    iget-object p0, p0, Lcom/google/android/material/textfield/TextInputLayout;->f:Lzq/l;

    .line 13
    .line 14
    iget-object p0, p0, Lzq/l;->j:Lcom/google/android/material/internal/CheckableImageButton;

    .line 15
    .line 16
    invoke-virtual {p0}, Landroid/view/View;->performClick()Z

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/view/View;->jumpDrawablesToCurrentState()V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :pswitch_0
    iget-object p0, p0, Lvp/g4;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Lzp/a;

    .line 26
    .line 27
    iget-object v1, p0, Lzp/a;->a:Ljava/lang/Object;

    .line 28
    .line 29
    monitor-enter v1

    .line 30
    :try_start_0
    invoke-virtual {p0}, Lzp/a;->b()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-nez v0, :cond_0

    .line 35
    .line 36
    monitor-exit v1

    .line 37
    goto :goto_0

    .line 38
    :catchall_0
    move-exception v0

    .line 39
    move-object p0, v0

    .line 40
    goto :goto_1

    .line 41
    :cond_0
    const-string v0, "WakeLock"

    .line 42
    .line 43
    iget-object v3, p0, Lzp/a;->j:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    const-string v4, " ** IS FORCE-RELEASED ON TIMEOUT **"

    .line 50
    .line 51
    invoke-virtual {v3, v4}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    invoke-static {v0, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 56
    .line 57
    .line 58
    invoke-virtual {p0}, Lzp/a;->d()V

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0}, Lzp/a;->b()Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-nez v0, :cond_1

    .line 66
    .line 67
    monitor-exit v1

    .line 68
    goto :goto_0

    .line 69
    :cond_1
    iput v2, p0, Lzp/a;->c:I

    .line 70
    .line 71
    invoke-virtual {p0}, Lzp/a;->e()V

    .line 72
    .line 73
    .line 74
    monitor-exit v1

    .line 75
    :goto_0
    return-void

    .line 76
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 77
    throw p0

    .line 78
    :pswitch_1
    iget-object p0, p0, Lvp/g4;->e:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p0, Lvy0/l;

    .line 81
    .line 82
    invoke-static {p0}, Lwy0/d;->a(Lvy0/l;)V

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    :pswitch_2
    sget-object p0, Lw51/c;->a:Lw51/b;

    .line 87
    .line 88
    sget-object p0, Lw51/c;->b:Ljava/util/concurrent/CopyOnWriteArraySet;

    .line 89
    .line 90
    invoke-virtual {p0}, Ljava/util/concurrent/CopyOnWriteArraySet;->iterator()Ljava/util/Iterator;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    if-nez v0, :cond_2

    .line 99
    .line 100
    return-void

    .line 101
    :cond_2
    invoke-static {p0}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    throw p0

    .line 106
    :pswitch_3
    iget-object v0, p0, Lvp/g4;->e:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v0, Lw3/t;

    .line 109
    .line 110
    invoke-virtual {v0, p0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 111
    .line 112
    .line 113
    iget-object v4, v0, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 114
    .line 115
    if-eqz v4, :cond_6

    .line 116
    .line 117
    const/4 v0, 0x0

    .line 118
    invoke-virtual {v4, v0}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 119
    .line 120
    .line 121
    move-result v3

    .line 122
    if-ne v3, v1, :cond_3

    .line 123
    .line 124
    move v0, v2

    .line 125
    :cond_3
    invoke-virtual {v4}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 126
    .line 127
    .line 128
    move-result v1

    .line 129
    if-eqz v0, :cond_4

    .line 130
    .line 131
    const/16 v0, 0xa

    .line 132
    .line 133
    if-eq v1, v0, :cond_6

    .line 134
    .line 135
    if-eq v1, v2, :cond_6

    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_4
    if-eq v1, v2, :cond_6

    .line 139
    .line 140
    :goto_2
    const/4 v0, 0x7

    .line 141
    if-eq v1, v0, :cond_5

    .line 142
    .line 143
    const/16 v2, 0x9

    .line 144
    .line 145
    if-eq v1, v2, :cond_5

    .line 146
    .line 147
    const/4 v0, 0x2

    .line 148
    :cond_5
    move v5, v0

    .line 149
    iget-object p0, p0, Lvp/g4;->e:Ljava/lang/Object;

    .line 150
    .line 151
    move-object v3, p0

    .line 152
    check-cast v3, Lw3/t;

    .line 153
    .line 154
    iget-wide v6, v3, Lw3/t;->F1:J

    .line 155
    .line 156
    const/4 v8, 0x0

    .line 157
    invoke-virtual/range {v3 .. v8}, Lw3/t;->F(Landroid/view/MotionEvent;IJZ)V

    .line 158
    .line 159
    .line 160
    :cond_6
    return-void

    .line 161
    :pswitch_4
    iget-object p0, p0, Lvp/g4;->e:Ljava/lang/Object;

    .line 162
    .line 163
    check-cast p0, Lvp/g1;

    .line 164
    .line 165
    iget-object v0, p0, Lvp/g1;->l:Lvp/d4;

    .line 166
    .line 167
    iget-object v2, p0, Lvp/g1;->p:Lvp/j2;

    .line 168
    .line 169
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 170
    .line 171
    .line 172
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v0}, Lvp/d4;->v0()J

    .line 176
    .line 177
    .line 178
    move-result-wide v3

    .line 179
    const-wide/16 v5, 0x1

    .line 180
    .line 181
    cmp-long v0, v3, v5

    .line 182
    .line 183
    if-nez v0, :cond_8

    .line 184
    .line 185
    invoke-static {v2}, Lvp/g1;->i(Lvp/b0;)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v2}, Lvp/x;->a0()V

    .line 189
    .line 190
    .line 191
    iget-object p0, v2, Lvp/j2;->p:Lvp/x1;

    .line 192
    .line 193
    if-eqz p0, :cond_7

    .line 194
    .line 195
    invoke-virtual {p0}, Lvp/o;->c()V

    .line 196
    .line 197
    .line 198
    :cond_7
    new-instance p0, Ljava/lang/Thread;

    .line 199
    .line 200
    invoke-static {v2}, Lvp/g1;->i(Lvp/b0;)V

    .line 201
    .line 202
    .line 203
    new-instance v0, Lvp/w1;

    .line 204
    .line 205
    invoke-direct {v0, v2, v1}, Lvp/w1;-><init>(Lvp/j2;I)V

    .line 206
    .line 207
    .line 208
    invoke-direct {p0, v0}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {p0}, Ljava/lang/Thread;->start()V

    .line 212
    .line 213
    .line 214
    goto :goto_3

    .line 215
    :cond_8
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 216
    .line 217
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 218
    .line 219
    .line 220
    iget-object p0, p0, Lvp/p0;->m:Lvp/n0;

    .line 221
    .line 222
    const-string v0, "registerTrigger called but app not eligible"

    .line 223
    .line 224
    invoke-virtual {p0, v0}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    :goto_3
    return-void

    .line 228
    :pswitch_5
    iget-object p0, p0, Lvp/g4;->e:Ljava/lang/Object;

    .line 229
    .line 230
    check-cast p0, Lc8/e;

    .line 231
    .line 232
    iget-object p0, p0, Lc8/e;->b:Ljava/lang/Object;

    .line 233
    .line 234
    check-cast p0, Lvp/g1;

    .line 235
    .line 236
    iget-object v0, p0, Lvp/g1;->x:Lvp/o2;

    .line 237
    .line 238
    invoke-static {v0}, Lvp/g1;->e(Lvp/x;)V

    .line 239
    .line 240
    .line 241
    iget-object p0, p0, Lvp/g1;->x:Lvp/o2;

    .line 242
    .line 243
    sget-object v0, Lvp/z;->D:Lvp/y;

    .line 244
    .line 245
    const/4 v1, 0x0

    .line 246
    invoke-virtual {v0, v1}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object v0

    .line 250
    check-cast v0, Ljava/lang/Long;

    .line 251
    .line 252
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 253
    .line 254
    .line 255
    move-result-wide v0

    .line 256
    invoke-virtual {p0, v0, v1}, Lvp/o2;->e0(J)V

    .line 257
    .line 258
    .line 259
    return-void

    .line 260
    nop

    .line 261
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 7

    .line 1
    iget v0, p0, Lvp/g4;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lvp/g4;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lw51/f;

    .line 14
    .line 15
    iget-object v0, p0, Lw51/f;->a:Lw51/b;

    .line 16
    .line 17
    iget-object v0, v0, Lw51/b;->a:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v1, p0, Lw51/f;->d:Ljava/lang/String;

    .line 20
    .line 21
    iget v2, p0, Lw51/f;->e:I

    .line 22
    .line 23
    iget-object v3, p0, Lw51/f;->f:Ljava/lang/String;

    .line 24
    .line 25
    const-string v4, "] "

    .line 26
    .line 27
    const-string v5, ":"

    .line 28
    .line 29
    const-string v6, "["

    .line 30
    .line 31
    invoke-static {v6, v0, v4, v1, v5}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string v1, " ("

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v1, ")"

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    iget-object v2, p0, Lw51/f;->b:Lw51/e;

    .line 56
    .line 57
    iget v2, v2, Lw51/e;->d:I

    .line 58
    .line 59
    iget-object v3, p0, Lw51/f;->g:Ljava/lang/Throwable;

    .line 60
    .line 61
    sget-object v4, Lw51/c;->a:Lw51/b;

    .line 62
    .line 63
    iget-object p0, p0, Lw51/f;->c:Lay0/a;

    .line 64
    .line 65
    invoke-static {p0}, Lw51/c;->e(Lay0/a;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const-string v4, "\', priority="

    .line 70
    .line 71
    const-string v5, ", throwable="

    .line 72
    .line 73
    const-string v6, "LogMessageRunnable(tag=\'"

    .line 74
    .line 75
    invoke-static {v6, v2, v0, v4, v5}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v2, ", message="

    .line 83
    .line 84
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    return-object p0

    .line 98
    nop

    .line 99
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method
