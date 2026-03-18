.class public final Lio/e;
.super Lbp/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lio/b;


# direct methods
.method public constructor <init>(Lio/b;Landroid/os/Looper;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lio/e;->a:Lio/b;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final handleMessage(Landroid/os/Message;)V
    .locals 7

    .line 1
    iget-object p0, p0, Lio/e;->a:Lio/b;

    .line 2
    .line 3
    if-eqz p1, :cond_e

    .line 4
    .line 5
    iget-object v0, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 6
    .line 7
    instance-of v1, v0, Landroid/content/Intent;

    .line 8
    .line 9
    if-eqz v1, :cond_e

    .line 10
    .line 11
    check-cast v0, Landroid/content/Intent;

    .line 12
    .line 13
    new-instance v1, Lio/f;

    .line 14
    .line 15
    invoke-direct {v1}, Lio/f;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0, v1}, Landroid/content/Intent;->setExtrasClassLoader(Ljava/lang/ClassLoader;)V

    .line 19
    .line 20
    .line 21
    const-string v1, "google.messenger"

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Landroid/content/Intent;->hasExtra(Ljava/lang/String;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_1

    .line 28
    .line 29
    const-string v1, "google.messenger"

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    instance-of v1, v0, Lio/g;

    .line 36
    .line 37
    if-eqz v1, :cond_0

    .line 38
    .line 39
    move-object v1, v0

    .line 40
    check-cast v1, Lio/g;

    .line 41
    .line 42
    iput-object v1, p0, Lio/b;->g:Lio/g;

    .line 43
    .line 44
    :cond_0
    instance-of v1, v0, Landroid/os/Messenger;

    .line 45
    .line 46
    if-eqz v1, :cond_1

    .line 47
    .line 48
    check-cast v0, Landroid/os/Messenger;

    .line 49
    .line 50
    iput-object v0, p0, Lio/b;->f:Landroid/os/Messenger;

    .line 51
    .line 52
    :cond_1
    iget-object p1, p1, Landroid/os/Message;->obj:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast p1, Landroid/content/Intent;

    .line 55
    .line 56
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    const-string v1, "com.google.android.c2dm.intent.REGISTRATION"

    .line 61
    .line 62
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    const/4 v2, 0x3

    .line 67
    if-nez v1, :cond_2

    .line 68
    .line 69
    const-string p0, "Rpc"

    .line 70
    .line 71
    invoke-static {p0, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    if-eqz p0, :cond_d

    .line 76
    .line 77
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    const-string p1, "Unexpected response action: "

    .line 82
    .line 83
    const-string v0, "Rpc"

    .line 84
    .line 85
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 90
    .line 91
    .line 92
    return-void

    .line 93
    :cond_2
    const-string v0, "registration_id"

    .line 94
    .line 95
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    if-nez v0, :cond_3

    .line 100
    .line 101
    const-string v0, "unregistered"

    .line 102
    .line 103
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    :cond_3
    const/4 v1, 0x2

    .line 108
    const/4 v3, 0x1

    .line 109
    if-nez v0, :cond_b

    .line 110
    .line 111
    const-string v0, "error"

    .line 112
    .line 113
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    if-nez v0, :cond_4

    .line 118
    .line 119
    invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    const-string p1, "Unexpected response, no error or registration id "

    .line 128
    .line 129
    const-string v0, "Rpc"

    .line 130
    .line 131
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    invoke-static {v0, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 136
    .line 137
    .line 138
    return-void

    .line 139
    :cond_4
    const-string v4, "Rpc"

    .line 140
    .line 141
    invoke-static {v4, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 142
    .line 143
    .line 144
    move-result v4

    .line 145
    if-eqz v4, :cond_5

    .line 146
    .line 147
    const-string v4, "Received InstanceID error "

    .line 148
    .line 149
    invoke-virtual {v4, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v4

    .line 153
    const-string v5, "Rpc"

    .line 154
    .line 155
    invoke-static {v5, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 156
    .line 157
    .line 158
    :cond_5
    const-string v4, "|"

    .line 159
    .line 160
    invoke-virtual {v0, v4}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 161
    .line 162
    .line 163
    move-result v4

    .line 164
    if-eqz v4, :cond_9

    .line 165
    .line 166
    const-string v4, "\\|"

    .line 167
    .line 168
    invoke-virtual {v0, v4}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v4

    .line 172
    array-length v5, v4

    .line 173
    if-le v5, v1, :cond_8

    .line 174
    .line 175
    aget-object v5, v4, v3

    .line 176
    .line 177
    const-string v6, "ID"

    .line 178
    .line 179
    invoke-static {v5, v6}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v5

    .line 183
    if-nez v5, :cond_6

    .line 184
    .line 185
    goto :goto_0

    .line 186
    :cond_6
    aget-object v0, v4, v1

    .line 187
    .line 188
    aget-object v1, v4, v2

    .line 189
    .line 190
    const-string v2, ":"

    .line 191
    .line 192
    invoke-virtual {v1, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 193
    .line 194
    .line 195
    move-result v2

    .line 196
    if-eqz v2, :cond_7

    .line 197
    .line 198
    invoke-virtual {v1, v3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v1

    .line 202
    :cond_7
    const-string v2, "error"

    .line 203
    .line 204
    invoke-virtual {p1, v2, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 205
    .line 206
    .line 207
    move-result-object p1

    .line 208
    invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 209
    .line 210
    .line 211
    move-result-object p1

    .line 212
    invoke-virtual {p0, v0, p1}, Lio/b;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 213
    .line 214
    .line 215
    return-void

    .line 216
    :cond_8
    :goto_0
    const-string p0, "Unexpected structured response "

    .line 217
    .line 218
    invoke-virtual {p0, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 219
    .line 220
    .line 221
    move-result-object p0

    .line 222
    const-string p1, "Rpc"

    .line 223
    .line 224
    invoke-static {p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 225
    .line 226
    .line 227
    return-void

    .line 228
    :cond_9
    iget-object v4, p0, Lio/b;->a:Landroidx/collection/a1;

    .line 229
    .line 230
    monitor-enter v4

    .line 231
    const/4 v0, 0x0

    .line 232
    :goto_1
    :try_start_0
    iget-object v1, p0, Lio/b;->a:Landroidx/collection/a1;

    .line 233
    .line 234
    invoke-virtual {v1}, Landroidx/collection/a1;->size()I

    .line 235
    .line 236
    .line 237
    move-result v1

    .line 238
    if-ge v0, v1, :cond_a

    .line 239
    .line 240
    iget-object v1, p0, Lio/b;->a:Landroidx/collection/a1;

    .line 241
    .line 242
    invoke-virtual {v1, v0}, Landroidx/collection/a1;->keyAt(I)Ljava/lang/Object;

    .line 243
    .line 244
    .line 245
    move-result-object v1

    .line 246
    check-cast v1, Ljava/lang/String;

    .line 247
    .line 248
    invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 249
    .line 250
    .line 251
    move-result-object v2

    .line 252
    invoke-virtual {p0, v1, v2}, Lio/b;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 253
    .line 254
    .line 255
    add-int/lit8 v0, v0, 0x1

    .line 256
    .line 257
    goto :goto_1

    .line 258
    :catchall_0
    move-exception p0

    .line 259
    goto :goto_2

    .line 260
    :cond_a
    monitor-exit v4

    .line 261
    return-void

    .line 262
    :goto_2
    monitor-exit v4
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 263
    throw p0

    .line 264
    :cond_b
    sget-object v4, Lio/b;->j:Ljava/util/regex/Pattern;

    .line 265
    .line 266
    invoke-virtual {v4, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 267
    .line 268
    .line 269
    move-result-object v4

    .line 270
    invoke-virtual {v4}, Ljava/util/regex/Matcher;->matches()Z

    .line 271
    .line 272
    .line 273
    move-result v5

    .line 274
    if-nez v5, :cond_c

    .line 275
    .line 276
    const-string p0, "Rpc"

    .line 277
    .line 278
    invoke-static {p0, v2}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 279
    .line 280
    .line 281
    move-result p0

    .line 282
    if-eqz p0, :cond_d

    .line 283
    .line 284
    const-string p0, "Unexpected response string: "

    .line 285
    .line 286
    invoke-virtual {p0, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 287
    .line 288
    .line 289
    move-result-object p0

    .line 290
    const-string p1, "Rpc"

    .line 291
    .line 292
    invoke-static {p1, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 293
    .line 294
    .line 295
    return-void

    .line 296
    :cond_c
    invoke-virtual {v4, v3}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    invoke-virtual {v4, v1}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 301
    .line 302
    .line 303
    move-result-object v1

    .line 304
    if-eqz v0, :cond_d

    .line 305
    .line 306
    invoke-virtual {p1}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;

    .line 307
    .line 308
    .line 309
    move-result-object p1

    .line 310
    const-string v2, "registration_id"

    .line 311
    .line 312
    invoke-virtual {p1, v2, v1}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 313
    .line 314
    .line 315
    invoke-virtual {p0, v0, p1}, Lio/b;->b(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 316
    .line 317
    .line 318
    :cond_d
    return-void

    .line 319
    :cond_e
    const-string p0, "Rpc"

    .line 320
    .line 321
    const-string p1, "Dropping invalid message"

    .line 322
    .line 323
    invoke-static {p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 324
    .line 325
    .line 326
    return-void
.end method
