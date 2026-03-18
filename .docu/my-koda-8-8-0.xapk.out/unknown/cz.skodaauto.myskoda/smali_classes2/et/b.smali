.class public final synthetic Let/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Let/c;


# direct methods
.method public synthetic constructor <init>(Let/c;I)V
    .locals 0

    .line 1
    iput p2, p0, Let/b;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Let/b;->b:Let/c;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final call()Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Let/b;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Let/b;->b:Let/c;

    .line 7
    .line 8
    monitor-enter v1

    .line 9
    :try_start_0
    iget-object p0, v1, Let/c;->a:Lgs/o;

    .line 10
    .line 11
    invoke-virtual {p0}, Lgs/o;->get()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    move-object v3, p0

    .line 16
    check-cast v3, Let/h;

    .line 17
    .line 18
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 19
    .line 20
    .line 21
    move-result-wide v4

    .line 22
    iget-object p0, v1, Let/c;->c:Lgt/b;

    .line 23
    .line 24
    invoke-interface {p0}, Lgt/b;->get()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Lbu/b;

    .line 29
    .line 30
    invoke-virtual {p0}, Lbu/b;->a()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    monitor-enter v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    :try_start_1
    invoke-virtual {v3, v4, v5}, Let/h;->b(J)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    invoke-static {p0}, Ljp/ne;->c(Ljava/lang/String;)Lq6/e;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    iget-object v0, v3, Let/h;->a:Lws/c;

    .line 44
    .line 45
    new-instance v2, Lbg/a;

    .line 46
    .line 47
    const/4 v7, 0x7

    .line 48
    move-object v5, p0

    .line 49
    invoke-direct/range {v2 .. v7}, Lbg/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v0, v2}, Lws/c;->a(Lay0/k;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 53
    .line 54
    .line 55
    :try_start_2
    monitor-exit v3

    .line 56
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 57
    const/4 p0, 0x0

    .line 58
    return-object p0

    .line 59
    :catchall_0
    move-exception v0

    .line 60
    move-object p0, v0

    .line 61
    goto :goto_0

    .line 62
    :catchall_1
    move-exception v0

    .line 63
    move-object p0, v0

    .line 64
    :try_start_3
    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 65
    :try_start_4
    throw p0

    .line 66
    :goto_0
    monitor-exit v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 67
    throw p0

    .line 68
    :pswitch_0
    iget-object p0, p0, Let/b;->b:Let/c;

    .line 69
    .line 70
    monitor-enter p0

    .line 71
    :try_start_5
    iget-object v0, p0, Let/c;->a:Lgs/o;

    .line 72
    .line 73
    invoke-virtual {v0}, Lgs/o;->get()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    move-object v1, v0

    .line 78
    check-cast v1, Let/h;

    .line 79
    .line 80
    invoke-virtual {v1}, Let/h;->a()Ljava/util/ArrayList;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    monitor-enter v1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 85
    :try_start_6
    iget-object v2, v1, Let/h;->a:Lws/c;

    .line 86
    .line 87
    new-instance v3, Le81/w;

    .line 88
    .line 89
    const/4 v4, 0x1

    .line 90
    invoke-direct {v3, v1, v4}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v2, v3}, Lws/c;->a(Lay0/k;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_7

    .line 94
    .line 95
    .line 96
    :try_start_7
    monitor-exit v1

    .line 97
    new-instance v1, Lorg/json/JSONArray;

    .line 98
    .line 99
    invoke-direct {v1}, Lorg/json/JSONArray;-><init>()V

    .line 100
    .line 101
    .line 102
    const/4 v2, 0x0

    .line 103
    :goto_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    if-ge v2, v3, :cond_0

    .line 108
    .line 109
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    check-cast v3, Let/a;

    .line 114
    .line 115
    new-instance v4, Lorg/json/JSONObject;

    .line 116
    .line 117
    invoke-direct {v4}, Lorg/json/JSONObject;-><init>()V

    .line 118
    .line 119
    .line 120
    const-string v5, "agent"

    .line 121
    .line 122
    iget-object v6, v3, Let/a;->a:Ljava/lang/String;

    .line 123
    .line 124
    invoke-virtual {v4, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 125
    .line 126
    .line 127
    const-string v5, "dates"

    .line 128
    .line 129
    new-instance v6, Lorg/json/JSONArray;

    .line 130
    .line 131
    iget-object v3, v3, Let/a;->b:Ljava/util/ArrayList;

    .line 132
    .line 133
    invoke-direct {v6, v3}, Lorg/json/JSONArray;-><init>(Ljava/util/Collection;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v4, v5, v6}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 137
    .line 138
    .line 139
    invoke-virtual {v1, v4}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;

    .line 140
    .line 141
    .line 142
    add-int/lit8 v2, v2, 0x1

    .line 143
    .line 144
    goto :goto_1

    .line 145
    :catchall_2
    move-exception v0

    .line 146
    goto :goto_5

    .line 147
    :cond_0
    new-instance v0, Lorg/json/JSONObject;

    .line 148
    .line 149
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 150
    .line 151
    .line 152
    const-string v2, "heartbeats"

    .line 153
    .line 154
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 155
    .line 156
    .line 157
    const-string v1, "version"

    .line 158
    .line 159
    const-string v2, "2"

    .line 160
    .line 161
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 162
    .line 163
    .line 164
    new-instance v1, Ljava/io/ByteArrayOutputStream;

    .line 165
    .line 166
    invoke-direct {v1}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 167
    .line 168
    .line 169
    new-instance v2, Landroid/util/Base64OutputStream;

    .line 170
    .line 171
    const/16 v3, 0xb

    .line 172
    .line 173
    invoke-direct {v2, v1, v3}, Landroid/util/Base64OutputStream;-><init>(Ljava/io/OutputStream;I)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 174
    .line 175
    .line 176
    :try_start_8
    new-instance v3, Ljava/util/zip/GZIPOutputStream;

    .line 177
    .line 178
    invoke-direct {v3, v2}, Ljava/util/zip/GZIPOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 179
    .line 180
    .line 181
    :try_start_9
    invoke-virtual {v0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    const-string v4, "UTF-8"

    .line 186
    .line 187
    invoke-virtual {v0, v4}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    invoke-virtual {v3, v0}, Ljava/io/OutputStream;->write([B)V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 192
    .line 193
    .line 194
    :try_start_a
    invoke-virtual {v3}, Ljava/io/OutputStream;->close()V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_3

    .line 195
    .line 196
    .line 197
    :try_start_b
    invoke-virtual {v2}, Landroid/util/Base64OutputStream;->close()V

    .line 198
    .line 199
    .line 200
    const-string v0, "UTF-8"

    .line 201
    .line 202
    invoke-virtual {v1, v0}, Ljava/io/ByteArrayOutputStream;->toString(Ljava/lang/String;)Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v0

    .line 206
    monitor-exit p0
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_2

    .line 207
    return-object v0

    .line 208
    :catchall_3
    move-exception v0

    .line 209
    move-object v1, v0

    .line 210
    goto :goto_3

    .line 211
    :catchall_4
    move-exception v0

    .line 212
    move-object v1, v0

    .line 213
    :try_start_c
    invoke-virtual {v3}, Ljava/io/OutputStream;->close()V
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_5

    .line 214
    .line 215
    .line 216
    goto :goto_2

    .line 217
    :catchall_5
    move-exception v0

    .line 218
    :try_start_d
    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 219
    .line 220
    .line 221
    :goto_2
    throw v1
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_3

    .line 222
    :goto_3
    :try_start_e
    invoke-virtual {v2}, Landroid/util/Base64OutputStream;->close()V
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_6

    .line 223
    .line 224
    .line 225
    goto :goto_4

    .line 226
    :catchall_6
    move-exception v0

    .line 227
    :try_start_f
    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 228
    .line 229
    .line 230
    :goto_4
    throw v1
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_2

    .line 231
    :catchall_7
    move-exception v0

    .line 232
    :try_start_10
    monitor-exit v1
    :try_end_10
    .catchall {:try_start_10 .. :try_end_10} :catchall_7

    .line 233
    :try_start_11
    throw v0

    .line 234
    :goto_5
    monitor-exit p0
    :try_end_11
    .catchall {:try_start_11 .. :try_end_11} :catchall_2

    .line 235
    throw v0

    .line 236
    nop

    .line 237
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
