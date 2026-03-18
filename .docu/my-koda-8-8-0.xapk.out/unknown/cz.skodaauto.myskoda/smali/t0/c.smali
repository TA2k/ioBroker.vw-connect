.class public final synthetic Lt0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lgr/e;
.implements Lo8/r;
.implements Lon/e;
.implements Ltw/l;
.implements Lgs/e;
.implements Lp/a;
.implements Lyn/f;
.implements Lcom/salesforce/marketingcloud/notifications/NotificationManager$NotificationLaunchIntentProvider;
.implements Lzq/w;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lt0/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, Lt0/c;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Lpw/f;Landroid/graphics/Path;FFFF)V
    .locals 0

    .line 1
    const-string p0, "<unused var>"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "path"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2, p3, p4}, Landroid/graphics/Path;->moveTo(FF)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2, p5, p4}, Landroid/graphics/Path;->lineTo(FF)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p2, p5, p6}, Landroid/graphics/Path;->lineTo(FF)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p2, p3, p6}, Landroid/graphics/Path;->lineTo(FF)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p2}, Landroid/graphics/Path;->close()V

    .line 24
    .line 25
    .line 26
    return-void
.end method

.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget p0, p0, Lt0/c;->d:I

    .line 2
    .line 3
    sparse-switch p0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lau/t;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    :try_start_0
    invoke-virtual {p1, p0}, Lcom/google/protobuf/p;->h(Lcom/google/protobuf/w0;)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    new-array v0, p0, [B

    .line 17
    .line 18
    new-instance v1, Lcom/google/protobuf/f;

    .line 19
    .line 20
    invoke-direct {v1, p0, v0}, Lcom/google/protobuf/f;-><init>(I[B)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p1, v1}, Lcom/google/protobuf/p;->i(Lcom/google/protobuf/f;)V

    .line 24
    .line 25
    .line 26
    iget p1, v1, Lcom/google/protobuf/f;->f:I

    .line 27
    .line 28
    sub-int/2addr p0, p1

    .line 29
    if-nez p0, :cond_0

    .line 30
    .line 31
    return-object v0

    .line 32
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    const-string p1, "Did not write as much data as expected."

    .line 35
    .line 36
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 40
    :catch_0
    move-exception p0

    .line 41
    new-instance p1, Ljava/lang/RuntimeException;

    .line 42
    .line 43
    new-instance v0, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    const-string v1, "Serializing "

    .line 46
    .line 47
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    const-class v1, Lau/t;

    .line 51
    .line 52
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, " to a byte array threw an IOException (should never happen)."

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    invoke-direct {p1, v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 69
    .line 70
    .line 71
    throw p1

    .line 72
    :sswitch_0
    check-cast p1, Landroid/database/sqlite/SQLiteDatabase;

    .line 73
    .line 74
    const/4 p0, 0x0

    .line 75
    new-array v0, p0, [Ljava/lang/String;

    .line 76
    .line 77
    const-string v1, "SELECT distinct t._id, t.backend_name, t.priority, t.extras FROM transport_contexts AS t, events AS e WHERE e.context_id = t._id"

    .line 78
    .line 79
    invoke-virtual {p1, v1, v0}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    :try_start_1
    new-instance v0, Ljava/util/ArrayList;

    .line 84
    .line 85
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 86
    .line 87
    .line 88
    :goto_0
    invoke-interface {p1}, Landroid/database/Cursor;->moveToNext()Z

    .line 89
    .line 90
    .line 91
    move-result v1

    .line 92
    if-eqz v1, :cond_2

    .line 93
    .line 94
    invoke-static {}, Lrn/j;->a()Lrn/i;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    const/4 v2, 0x1

    .line 99
    invoke-interface {p1, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    invoke-virtual {v1, v2}, Lrn/i;->B(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    const/4 v2, 0x2

    .line 107
    invoke-interface {p1, v2}, Landroid/database/Cursor;->getInt(I)I

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    invoke-static {v2}, Lbo/a;->b(I)Lon/d;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    iput-object v2, v1, Lrn/i;->g:Ljava/lang/Object;

    .line 116
    .line 117
    const/4 v2, 0x3

    .line 118
    invoke-interface {p1, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    if-nez v2, :cond_1

    .line 123
    .line 124
    const/4 v2, 0x0

    .line 125
    goto :goto_1

    .line 126
    :cond_1
    invoke-static {v2, p0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    :goto_1
    iput-object v2, v1, Lrn/i;->f:Ljava/lang/Object;

    .line 131
    .line 132
    invoke-virtual {v1}, Lrn/i;->o()Lrn/j;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 137
    .line 138
    .line 139
    goto :goto_0

    .line 140
    :cond_2
    invoke-interface {p1}, Landroid/database/Cursor;->close()V

    .line 141
    .line 142
    .line 143
    return-object v0

    .line 144
    :catchall_0
    move-exception p0

    .line 145
    invoke-interface {p1}, Landroid/database/Cursor;->close()V

    .line 146
    .line 147
    .line 148
    throw p0

    .line 149
    :sswitch_1
    check-cast p1, Ljava/util/List;

    .line 150
    .line 151
    const/4 p0, 0x0

    .line 152
    return-object p0

    .line 153
    :sswitch_2
    check-cast p1, Lv7/b;

    .line 154
    .line 155
    iget p0, p1, Lv7/b;->r:I

    .line 156
    .line 157
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    return-object p0

    .line 162
    :sswitch_3
    check-cast p1, Ljava/lang/Void;

    .line 163
    .line 164
    sget-object p0, Lv0/f;->b:Lv0/f;

    .line 165
    .line 166
    return-object p0

    .line 167
    :sswitch_4
    check-cast p1, Lps/n2;

    .line 168
    .line 169
    sget-object p0, Lts/a;->b:Lqs/a;

    .line 170
    .line 171
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 172
    .line 173
    .line 174
    sget-object p0, Lqs/a;->a:Lbu/c;

    .line 175
    .line 176
    invoke-virtual {p0, p1}, Lbu/c;->l(Ljava/lang/Object;)Ljava/lang/String;

    .line 177
    .line 178
    .line 179
    move-result-object p0

    .line 180
    const-string p1, "UTF-8"

    .line 181
    .line 182
    invoke-static {p1}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    invoke-virtual {p0, p1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    return-object p0

    .line 191
    :sswitch_5
    check-cast p1, Lt7/p;

    .line 192
    .line 193
    new-instance p0, Ljava/lang/StringBuilder;

    .line 194
    .line 195
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 196
    .line 197
    .line 198
    iget-object v0, p1, Lt7/p;->a:Ljava/lang/String;

    .line 199
    .line 200
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    const-string v0, ": "

    .line 204
    .line 205
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 206
    .line 207
    .line 208
    iget-object p1, p1, Lt7/p;->b:Ljava/lang/String;

    .line 209
    .line 210
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 211
    .line 212
    .line 213
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    return-object p0

    .line 218
    nop

    .line 219
    :sswitch_data_0
    .sparse-switch
        0x2 -> :sswitch_5
        0x4 -> :sswitch_4
        0x9 -> :sswitch_3
        0xa -> :sswitch_2
        0x16 -> :sswitch_1
        0x17 -> :sswitch_0
    .end sparse-switch
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lt0/c;->d:I

    .line 2
    .line 3
    sparse-switch p0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lcom/google/firebase/datatransport/TransportRegistrar;->a(Lin/z1;)Lon/f;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :sswitch_0
    invoke-static {p1}, Lcom/google/firebase/datatransport/TransportRegistrar;->b(Lin/z1;)Lon/f;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :sswitch_1
    invoke-static {p1}, Lcom/google/firebase/datatransport/TransportRegistrar;->c(Lin/z1;)Lon/f;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :sswitch_2
    invoke-static {p1}, Lcom/google/firebase/abt/component/AbtRegistrar;->a(Lin/z1;)Lur/a;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    nop

    .line 27
    :sswitch_data_0
    .sparse-switch
        0x8 -> :sswitch_2
        0x13 -> :sswitch_1
        0x14 -> :sswitch_0
    .end sparse-switch
.end method

.method public g()[Lo8/o;
    .locals 5

    .line 1
    iget p0, p0, Lt0/c;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/4 v1, 0x1

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    :pswitch_0
    new-instance p0, Lw9/d;

    .line 9
    .line 10
    invoke-direct {p0}, Lw9/d;-><init>()V

    .line 11
    .line 12
    .line 13
    new-array v1, v1, [Lo8/o;

    .line 14
    .line 15
    aput-object p0, v1, v0

    .line 16
    .line 17
    return-object v1

    .line 18
    :pswitch_1
    new-instance p0, Lv9/d0;

    .line 19
    .line 20
    new-instance v2, Lw7/u;

    .line 21
    .line 22
    const-wide/16 v3, 0x0

    .line 23
    .line 24
    invoke-direct {v2, v3, v4}, Lw7/u;-><init>(J)V

    .line 25
    .line 26
    .line 27
    new-instance v3, Laq/m;

    .line 28
    .line 29
    sget-object v4, Lhr/h0;->e:Lhr/f0;

    .line 30
    .line 31
    sget-object v4, Lhr/x0;->h:Lhr/x0;

    .line 32
    .line 33
    invoke-direct {v3, v4, v0}, Laq/m;-><init>(Ljava/util/List;Z)V

    .line 34
    .line 35
    .line 36
    sget-object v4, Ll9/h;->k1:Lwq/f;

    .line 37
    .line 38
    invoke-direct {p0, v1, v4, v2, v3}, Lv9/d0;-><init>(ILl9/h;Lw7/u;Laq/m;)V

    .line 39
    .line 40
    .line 41
    new-array v1, v1, [Lo8/o;

    .line 42
    .line 43
    aput-object p0, v1, v0

    .line 44
    .line 45
    return-object v1

    .line 46
    :pswitch_2
    new-instance p0, Lv9/z;

    .line 47
    .line 48
    invoke-direct {p0}, Lv9/z;-><init>()V

    .line 49
    .line 50
    .line 51
    new-array v1, v1, [Lo8/o;

    .line 52
    .line 53
    aput-object p0, v1, v0

    .line 54
    .line 55
    return-object v1

    .line 56
    :pswitch_3
    new-instance p0, Lv9/d;

    .line 57
    .line 58
    invoke-direct {p0}, Lv9/d;-><init>()V

    .line 59
    .line 60
    .line 61
    new-array v1, v1, [Lo8/o;

    .line 62
    .line 63
    aput-object p0, v1, v0

    .line 64
    .line 65
    return-object v1

    .line 66
    :pswitch_4
    new-instance p0, Lv9/c;

    .line 67
    .line 68
    invoke-direct {p0}, Lv9/c;-><init>()V

    .line 69
    .line 70
    .line 71
    new-array v1, v1, [Lo8/o;

    .line 72
    .line 73
    aput-object p0, v1, v0

    .line 74
    .line 75
    return-object v1

    .line 76
    :pswitch_5
    new-instance p0, Lv9/a;

    .line 77
    .line 78
    invoke-direct {p0}, Lv9/a;-><init>()V

    .line 79
    .line 80
    .line 81
    new-array v1, v1, [Lo8/o;

    .line 82
    .line 83
    aput-object p0, v1, v0

    .line 84
    .line 85
    return-object v1

    .line 86
    :pswitch_6
    new-instance p0, Lu8/b;

    .line 87
    .line 88
    invoke-direct {p0}, Lu8/b;-><init>()V

    .line 89
    .line 90
    .line 91
    new-array v1, v1, [Lo8/o;

    .line 92
    .line 93
    aput-object p0, v1, v0

    .line 94
    .line 95
    return-object v1

    .line 96
    :pswitch_7
    new-instance p0, Lt8/c;

    .line 97
    .line 98
    invoke-direct {p0}, Lt8/c;-><init>()V

    .line 99
    .line 100
    .line 101
    new-array v1, v1, [Lo8/o;

    .line 102
    .line 103
    aput-object p0, v1, v0

    .line 104
    .line 105
    return-object v1

    .line 106
    nop

    .line 107
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_7
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_6
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public getNotificationPendingIntent(Landroid/content/Context;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)Landroid/app/PendingIntent;
    .locals 1

    .line 1
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "notificationMessage"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p2, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->url:Ljava/lang/String;

    .line 12
    .line 13
    if-nez p0, :cond_0

    .line 14
    .line 15
    const-string p0, "myskoda://app/home"

    .line 16
    .line 17
    :cond_0
    new-instance p2, Landroidx/core/app/m0;

    .line 18
    .line 19
    invoke-direct {p2, p1}, Landroidx/core/app/m0;-><init>(Landroid/content/Context;)V

    .line 20
    .line 21
    .line 22
    new-instance p1, Landroid/content/Intent;

    .line 23
    .line 24
    const-string v0, "android.intent.action.VIEW"

    .line 25
    .line 26
    invoke-static {p0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-direct {p1, v0, p0}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p2, p1}, Landroidx/core/app/m0;->c(Landroid/content/Intent;)V

    .line 34
    .line 35
    .line 36
    new-instance p0, Ljava/security/SecureRandom;

    .line 37
    .line 38
    invoke-direct {p0}, Ljava/security/SecureRandom;-><init>()V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/util/Random;->nextInt()I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    invoke-virtual {p2, p0}, Landroidx/core/app/m0;->g(I)Landroid/app/PendingIntent;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0
.end method
