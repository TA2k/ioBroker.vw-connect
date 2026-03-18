.class public final synthetic Lht/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lht/c;


# direct methods
.method public synthetic constructor <init>(Lht/c;I)V
    .locals 0

    .line 1
    iput p2, p0, Lht/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lht/b;->e:Lht/c;

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
    .locals 7

    .line 1
    iget v0, p0, Lht/b;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lht/b;->e:Lht/c;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v0, Lht/c;->m:Ljava/lang/Object;

    .line 9
    .line 10
    monitor-enter v0

    .line 11
    :try_start_0
    iget-object v1, p0, Lht/c;->a:Lsr/f;

    .line 12
    .line 13
    invoke-virtual {v1}, Lsr/f;->a()V

    .line 14
    .line 15
    .line 16
    iget-object v1, v1, Lsr/f;->a:Landroid/content/Context;

    .line 17
    .line 18
    invoke-static {v1}, Lb81/b;->h(Landroid/content/Context;)Lb81/b;

    .line 19
    .line 20
    .line 21
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    :try_start_1
    iget-object v2, p0, Lht/c;->c:Lc2/k;

    .line 23
    .line 24
    invoke-virtual {v2}, Lc2/k;->z()Ljt/b;

    .line 25
    .line 26
    .line 27
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_5

    .line 28
    if-eqz v1, :cond_0

    .line 29
    .line 30
    :try_start_2
    invoke-virtual {v1}, Lb81/b;->u()V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    goto/16 :goto_c

    .line 36
    .line 37
    :cond_0
    :goto_0
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 38
    :try_start_3
    iget v1, v2, Ljt/b;->b:I

    .line 39
    .line 40
    const/4 v3, 0x0

    .line 41
    const/4 v4, 0x5

    .line 42
    const/4 v5, 0x1

    .line 43
    if-ne v1, v4, :cond_1

    .line 44
    .line 45
    move v6, v5

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    move v6, v3

    .line 48
    :goto_1
    if-nez v6, :cond_4

    .line 49
    .line 50
    const/4 v6, 0x3

    .line 51
    if-ne v1, v6, :cond_2

    .line 52
    .line 53
    move v3, v5

    .line 54
    :cond_2
    if-eqz v3, :cond_3

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_3
    iget-object v1, p0, Lht/c;->d:Lht/j;

    .line 58
    .line 59
    invoke-virtual {v1, v2}, Lht/j;->a(Ljt/b;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-eqz v1, :cond_e

    .line 64
    .line 65
    invoke-virtual {p0, v2}, Lht/c;->b(Ljt/b;)Ljt/b;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    goto :goto_3

    .line 70
    :catch_0
    move-exception v0

    .line 71
    goto/16 :goto_a

    .line 72
    .line 73
    :cond_4
    :goto_2
    invoke-virtual {p0, v2}, Lht/c;->g(Ljt/b;)Ljt/b;

    .line 74
    .line 75
    .line 76
    move-result-object v1
    :try_end_3
    .catch Lht/e; {:try_start_3 .. :try_end_3} :catch_0

    .line 77
    :goto_3
    monitor-enter v0

    .line 78
    :try_start_4
    iget-object v3, p0, Lht/c;->a:Lsr/f;

    .line 79
    .line 80
    invoke-virtual {v3}, Lsr/f;->a()V

    .line 81
    .line 82
    .line 83
    iget-object v3, v3, Lsr/f;->a:Landroid/content/Context;

    .line 84
    .line 85
    invoke-static {v3}, Lb81/b;->h(Landroid/content/Context;)Lb81/b;

    .line 86
    .line 87
    .line 88
    move-result-object v3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 89
    :try_start_5
    iget-object v6, p0, Lht/c;->c:Lc2/k;

    .line 90
    .line 91
    invoke-virtual {v6, v1}, Lc2/k;->x(Ljt/b;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 92
    .line 93
    .line 94
    if-eqz v3, :cond_5

    .line 95
    .line 96
    :try_start_6
    invoke-virtual {v3}, Lb81/b;->u()V

    .line 97
    .line 98
    .line 99
    goto :goto_4

    .line 100
    :catchall_1
    move-exception p0

    .line 101
    goto/16 :goto_9

    .line 102
    .line 103
    :cond_5
    :goto_4
    monitor-exit v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 104
    monitor-enter p0

    .line 105
    :try_start_7
    iget-object v0, p0, Lht/c;->k:Ljava/util/HashSet;

    .line 106
    .line 107
    invoke-virtual {v0}, Ljava/util/HashSet;->size()I

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    if-eqz v0, :cond_8

    .line 112
    .line 113
    iget-object v0, v2, Ljt/b;->a:Ljava/lang/String;

    .line 114
    .line 115
    iget-object v2, v1, Ljt/b;->a:Ljava/lang/String;

    .line 116
    .line 117
    invoke-static {v0, v2}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    if-nez v0, :cond_8

    .line 122
    .line 123
    iget-object v0, p0, Lht/c;->k:Ljava/util/HashSet;

    .line 124
    .line 125
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 130
    .line 131
    .line 132
    move-result v2

    .line 133
    if-nez v2, :cond_6

    .line 134
    .line 135
    goto :goto_5

    .line 136
    :cond_6
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    if-nez v0, :cond_7

    .line 141
    .line 142
    const/4 v0, 0x0

    .line 143
    throw v0

    .line 144
    :catchall_2
    move-exception v0

    .line 145
    goto :goto_8

    .line 146
    :cond_7
    new-instance v0, Ljava/lang/ClassCastException;

    .line 147
    .line 148
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 149
    .line 150
    .line 151
    throw v0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 152
    :cond_8
    :goto_5
    monitor-exit p0

    .line 153
    iget v0, v1, Ljt/b;->b:I

    .line 154
    .line 155
    const/4 v2, 0x4

    .line 156
    if-ne v0, v2, :cond_9

    .line 157
    .line 158
    iget-object v0, v1, Ljt/b;->a:Ljava/lang/String;

    .line 159
    .line 160
    monitor-enter p0

    .line 161
    :try_start_8
    iput-object v0, p0, Lht/c;->j:Ljava/lang/String;
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 162
    .line 163
    monitor-exit p0

    .line 164
    goto :goto_6

    .line 165
    :catchall_3
    move-exception v0

    .line 166
    :try_start_9
    monitor-exit p0
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_3

    .line 167
    throw v0

    .line 168
    :cond_9
    :goto_6
    iget v0, v1, Ljt/b;->b:I

    .line 169
    .line 170
    if-ne v0, v4, :cond_a

    .line 171
    .line 172
    new-instance v0, Lht/e;

    .line 173
    .line 174
    invoke-direct {v0}, Ljava/lang/Exception;-><init>()V

    .line 175
    .line 176
    .line 177
    invoke-virtual {p0, v0}, Lht/c;->h(Ljava/lang/Exception;)V

    .line 178
    .line 179
    .line 180
    goto :goto_b

    .line 181
    :cond_a
    const/4 v2, 0x2

    .line 182
    if-eq v0, v2, :cond_c

    .line 183
    .line 184
    if-ne v0, v5, :cond_b

    .line 185
    .line 186
    goto :goto_7

    .line 187
    :cond_b
    invoke-virtual {p0, v1}, Lht/c;->i(Ljt/b;)V

    .line 188
    .line 189
    .line 190
    goto :goto_b

    .line 191
    :cond_c
    :goto_7
    new-instance v0, Ljava/io/IOException;

    .line 192
    .line 193
    const-string v1, "Installation ID could not be validated with the Firebase servers (maybe it was deleted). Firebase Installations will need to create a new Installation ID and auth token. Please retry your last request."

    .line 194
    .line 195
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {p0, v0}, Lht/c;->h(Ljava/lang/Exception;)V

    .line 199
    .line 200
    .line 201
    goto :goto_b

    .line 202
    :goto_8
    :try_start_a
    monitor-exit p0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_2

    .line 203
    throw v0

    .line 204
    :catchall_4
    move-exception p0

    .line 205
    if-eqz v3, :cond_d

    .line 206
    .line 207
    :try_start_b
    invoke-virtual {v3}, Lb81/b;->u()V

    .line 208
    .line 209
    .line 210
    :cond_d
    throw p0

    .line 211
    :goto_9
    monitor-exit v0
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_1

    .line 212
    throw p0

    .line 213
    :goto_a
    invoke-virtual {p0, v0}, Lht/c;->h(Ljava/lang/Exception;)V

    .line 214
    .line 215
    .line 216
    :cond_e
    :goto_b
    return-void

    .line 217
    :catchall_5
    move-exception p0

    .line 218
    if-eqz v1, :cond_f

    .line 219
    .line 220
    :try_start_c
    invoke-virtual {v1}, Lb81/b;->u()V

    .line 221
    .line 222
    .line 223
    :cond_f
    throw p0

    .line 224
    :goto_c
    monitor-exit v0
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_0

    .line 225
    throw p0

    .line 226
    :pswitch_0
    invoke-virtual {p0}, Lht/c;->a()V

    .line 227
    .line 228
    .line 229
    return-void

    .line 230
    :pswitch_1
    invoke-virtual {p0}, Lht/c;->a()V

    .line 231
    .line 232
    .line 233
    return-void

    .line 234
    nop

    .line 235
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
