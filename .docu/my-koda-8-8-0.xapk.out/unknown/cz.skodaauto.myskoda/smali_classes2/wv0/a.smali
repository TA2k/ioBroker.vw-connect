.class public final Lwv0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvv0/b;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Landroid/content/Context;

.field public final c:Lvv0/d;

.field public final d:I


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Lvv0/d;Lvv0/d;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lwv0/a;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p1, p0, Lwv0/a;->b:Landroid/content/Context;

    .line 7
    .line 8
    iget-object p1, p3, Lvv0/d;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p1, Lc8/g;

    .line 11
    .line 12
    iget-boolean p2, p1, Lc8/g;->a:Z

    .line 13
    .line 14
    const/4 v0, 0x4

    .line 15
    if-eqz p2, :cond_1

    .line 16
    .line 17
    iget-boolean p2, p1, Lc8/g;->b:Z

    .line 18
    .line 19
    if-eqz p2, :cond_1

    .line 20
    .line 21
    iget-boolean p1, p1, Lc8/g;->c:Z

    .line 22
    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    move p1, v0

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p1, 0x3

    .line 28
    goto :goto_0

    .line 29
    :cond_1
    const/4 p1, 0x1

    .line 30
    :goto_0
    iput p1, p0, Lwv0/a;->d:I

    .line 31
    .line 32
    if-eq p1, v0, :cond_2

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_2
    if-nez p4, :cond_3

    .line 36
    .line 37
    const/4 p1, 0x0

    .line 38
    new-array p1, p1, [Ljava/lang/Object;

    .line 39
    .line 40
    const-string p2, "EncryptedKeychain: Backup key provider is required but not provided."

    .line 41
    .line 42
    invoke-static {p2, p1}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_3
    move-object p3, p4

    .line 47
    :goto_1
    iput-object p3, p0, Lwv0/a;->c:Lvv0/d;

    .line 48
    .line 49
    return-void
.end method


# virtual methods
.method public final declared-synchronized a(Ljava/lang/String;[B)V
    .locals 5

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    array-length v0, p2

    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    if-lez v0, :cond_0

    .line 6
    .line 7
    array-length v0, p2

    .line 8
    const/4 v3, 0x1

    .line 9
    add-int/2addr v0, v3

    .line 10
    new-array v0, v0, [B

    .line 11
    .line 12
    aput-byte v3, v0, v1

    .line 13
    .line 14
    array-length v4, p2

    .line 15
    invoke-static {p2, v1, v0, v3, v4}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move-object v0, v2

    .line 20
    :goto_0
    invoke-static {p1}, Llp/rd;->b(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Lwv0/a;->c()Ljavax/crypto/SecretKey;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    if-nez p2, :cond_1

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    if-eqz v0, :cond_3

    .line 31
    .line 32
    iget-object v3, p0, Lwv0/a;->a:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v0, p2, v3}, Llp/qd;->b([BLjavax/crypto/SecretKey;Ljava/lang/String;)[B

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    if-eqz p2, :cond_2

    .line 39
    .line 40
    const/4 v0, 0x2

    .line 41
    invoke-static {p2, v0}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    :cond_2
    if-nez v2, :cond_3

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_3
    iget-object p2, p0, Lwv0/a;->b:Landroid/content/Context;

    .line 49
    .line 50
    iget-object v0, p0, Lwv0/a;->a:Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {p2, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    invoke-interface {p2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 57
    .line 58
    .line 59
    move-result-object p2

    .line 60
    invoke-interface {p2, p1, v2}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->apply()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 65
    .line 66
    .line 67
    :goto_1
    monitor-exit p0

    .line 68
    return-void

    .line 69
    :catchall_0
    move-exception p1

    .line 70
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 71
    throw p1
.end method

.method public final declared-synchronized b(Ljava/lang/String;)[B
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-static {p1}, Llp/rd;->b(Ljava/lang/String;)V

    .line 3
    .line 4
    .line 5
    iget-object v0, p0, Lwv0/a;->b:Landroid/content/Context;

    .line 6
    .line 7
    iget-object v1, p0, Lwv0/a;->a:Ljava/lang/String;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    invoke-virtual {v0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-interface {v0, p1, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    if-nez p1, :cond_0

    .line 20
    .line 21
    :goto_0
    move-object p1, v1

    .line 22
    goto :goto_1

    .line 23
    :cond_0
    invoke-virtual {p0}, Lwv0/a;->c()Ljavax/crypto/SecretKey;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    if-nez v0, :cond_1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    const/4 v2, 0x2

    .line 31
    invoke-static {p1, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    array-length v2, p1

    .line 36
    if-nez v2, :cond_2

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    iget-object v2, p0, Lwv0/a;->a:Ljava/lang/String;

    .line 40
    .line 41
    invoke-static {p1, v0, v2}, Llp/qd;->a([BLjavax/crypto/SecretKey;Ljava/lang/String;)[B

    .line 42
    .line 43
    .line 44
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    :goto_1
    if-nez p1, :cond_3

    .line 46
    .line 47
    monitor-exit p0

    .line 48
    return-object v1

    .line 49
    :cond_3
    const/4 v0, 0x1

    .line 50
    :try_start_1
    invoke-static {v0, p1}, Lwe0/b;->r(B[B)V

    .line 51
    .line 52
    .line 53
    array-length v2, p1

    .line 54
    invoke-static {p1, v0, v2}, Ljava/util/Arrays;->copyOfRange([BII)[B

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    array-length v0, p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 59
    if-lez v0, :cond_4

    .line 60
    .line 61
    move-object v1, p1

    .line 62
    :cond_4
    monitor-exit p0

    .line 63
    return-object v1

    .line 64
    :catchall_0
    move-exception p1

    .line 65
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 66
    throw p1
.end method

.method public final c()Ljavax/crypto/SecretKey;
    .locals 3

    .line 1
    iget-object v0, p0, Lwv0/a;->c:Lvv0/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Lvv0/d;->g()Ljavax/crypto/SecretKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    new-instance v1, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v2, "EncryptedKeychain: "

    .line 12
    .line 13
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lwv0/a;->a:Ljava/lang/String;

    .line 17
    .line 18
    const-string v2, ": Unable to acquire master key."

    .line 19
    .line 20
    invoke-static {v1, p0, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    const/4 v1, 0x0

    .line 25
    new-array v1, v1, [Ljava/lang/Object;

    .line 26
    .line 27
    invoke-static {p0, v1}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    return-object v0
.end method

.method public final d(Landroid/content/SharedPreferences$Editor;)V
    .locals 2

    .line 1
    const-string v0, "com.wultra.PowerAuthKeychain.IsEncrypted"

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-interface {p1, v0, v1}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    .line 5
    .line 6
    .line 7
    const-string v0, "com.wultra.PowerAuthKeychain.EncryptionMode"

    .line 8
    .line 9
    iget p0, p0, Lwv0/a;->d:I

    .line 10
    .line 11
    invoke-interface {p1, v0, p0}, Landroid/content/SharedPreferences$Editor;->putInt(Ljava/lang/String;I)Landroid/content/SharedPreferences$Editor;

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final e(Landroid/content/SharedPreferences;Ljavax/crypto/SecretKey;Ljavax/crypto/SecretKey;)Z
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    new-instance v2, Ljava/util/HashMap;

    .line 6
    .line 7
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-interface/range {p1 .. p1}, Landroid/content/SharedPreferences;->getAll()Ljava/util/Map;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    invoke-interface {v3}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    const/4 v6, 0x2

    .line 27
    const-string v7, "\'. Data migration will fail."

    .line 28
    .line 29
    iget-object v8, v0, Lwv0/a;->a:Ljava/lang/String;

    .line 30
    .line 31
    const-string v9, "EncryptedKeychain: "

    .line 32
    .line 33
    const/4 v10, 0x0

    .line 34
    const/4 v11, 0x1

    .line 35
    if-eqz v4, :cond_4

    .line 36
    .line 37
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    check-cast v4, Ljava/util/Map$Entry;

    .line 42
    .line 43
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v12

    .line 47
    check-cast v12, Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {v12}, Llp/rd;->c(Ljava/lang/String;)Z

    .line 50
    .line 51
    .line 52
    move-result v13

    .line 53
    if-eqz v13, :cond_0

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    instance-of v13, v4, Ljava/lang/String;

    .line 61
    .line 62
    if-nez v13, :cond_1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    check-cast v4, Ljava/lang/String;

    .line 66
    .line 67
    invoke-static {v4, v6}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    array-length v13, v4

    .line 72
    if-nez v13, :cond_2

    .line 73
    .line 74
    move-object/from16 v13, p2

    .line 75
    .line 76
    const/4 v4, 0x0

    .line 77
    goto :goto_1

    .line 78
    :cond_2
    move-object/from16 v13, p2

    .line 79
    .line 80
    invoke-static {v4, v13, v8}, Llp/qd;->a([BLjavax/crypto/SecretKey;Ljava/lang/String;)[B

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    :goto_1
    if-nez v4, :cond_3

    .line 85
    .line 86
    const-string v3, ": Failed to decrypt data for key \'"

    .line 87
    .line 88
    invoke-static {v9, v8, v3, v12, v7}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    new-array v4, v10, [Ljava/lang/Object;

    .line 93
    .line 94
    invoke-static {v3, v4}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    move v3, v10

    .line 98
    goto :goto_2

    .line 99
    :cond_3
    invoke-virtual {v2, v12, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_4
    move v3, v11

    .line 104
    :goto_2
    invoke-interface/range {p1 .. p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 105
    .line 106
    .line 107
    move-result-object v4

    .line 108
    if-eqz v3, :cond_d

    .line 109
    .line 110
    invoke-virtual {v2}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 115
    .line 116
    .line 117
    move-result-object v2

    .line 118
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 119
    .line 120
    .line 121
    move-result v12

    .line 122
    if-eqz v12, :cond_b

    .line 123
    .line 124
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v12

    .line 128
    check-cast v12, Ljava/util/Map$Entry;

    .line 129
    .line 130
    invoke-interface {v12}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v13

    .line 134
    check-cast v13, Ljava/lang/String;

    .line 135
    .line 136
    invoke-interface {v12}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v12

    .line 140
    check-cast v12, [B

    .line 141
    .line 142
    if-eqz v1, :cond_7

    .line 143
    .line 144
    invoke-static {v12, v1, v8}, Llp/qd;->b([BLjavax/crypto/SecretKey;Ljava/lang/String;)[B

    .line 145
    .line 146
    .line 147
    move-result-object v12

    .line 148
    if-eqz v12, :cond_5

    .line 149
    .line 150
    invoke-static {v12, v6}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v12

    .line 154
    goto :goto_4

    .line 155
    :cond_5
    const/4 v12, 0x0

    .line 156
    :goto_4
    if-nez v12, :cond_6

    .line 157
    .line 158
    const-string v1, ": Failed to encrypt data for key \'"

    .line 159
    .line 160
    invoke-static {v9, v8, v1, v13, v7}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    new-array v2, v10, [Ljava/lang/Object;

    .line 165
    .line 166
    invoke-static {v1, v2}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    goto/16 :goto_8

    .line 170
    .line 171
    :cond_6
    invoke-interface {v4, v13, v12}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 172
    .line 173
    .line 174
    goto :goto_3

    .line 175
    :cond_7
    :try_start_0
    array-length v14, v12

    .line 176
    if-eqz v14, :cond_a

    .line 177
    .line 178
    aget-byte v14, v12, v10

    .line 179
    .line 180
    if-lt v14, v11, :cond_a

    .line 181
    .line 182
    const/4 v15, 0x6

    .line 183
    if-gt v14, v15, :cond_a

    .line 184
    .line 185
    const/4 v15, 0x4

    .line 186
    packed-switch v14, :pswitch_data_0

    .line 187
    .line 188
    .line 189
    goto/16 :goto_7

    .line 190
    .line 191
    :pswitch_0
    invoke-static {v12}, Lwe0/b;->t([B)Ljava/util/HashSet;

    .line 192
    .line 193
    .line 194
    move-result-object v12

    .line 195
    invoke-interface {v4, v13, v12}, Landroid/content/SharedPreferences$Editor;->putStringSet(Ljava/lang/String;Ljava/util/Set;)Landroid/content/SharedPreferences$Editor;

    .line 196
    .line 197
    .line 198
    goto :goto_3

    .line 199
    :pswitch_1
    const/4 v14, 0x5

    .line 200
    invoke-static {v14, v12}, Lwe0/b;->r(B[B)V

    .line 201
    .line 202
    .line 203
    invoke-static {v12, v11, v15}, Ljava/nio/ByteBuffer;->wrap([BII)Ljava/nio/ByteBuffer;

    .line 204
    .line 205
    .line 206
    move-result-object v12

    .line 207
    invoke-virtual {v12}, Ljava/nio/ByteBuffer;->getFloat()F

    .line 208
    .line 209
    .line 210
    move-result v12

    .line 211
    invoke-interface {v4, v13, v12}, Landroid/content/SharedPreferences$Editor;->putFloat(Ljava/lang/String;F)Landroid/content/SharedPreferences$Editor;

    .line 212
    .line 213
    .line 214
    goto :goto_3

    .line 215
    :pswitch_2
    invoke-static {v15, v12}, Lwe0/b;->r(B[B)V

    .line 216
    .line 217
    .line 218
    const/16 v14, 0x8

    .line 219
    .line 220
    invoke-static {v12, v11, v14}, Ljava/nio/ByteBuffer;->wrap([BII)Ljava/nio/ByteBuffer;

    .line 221
    .line 222
    .line 223
    move-result-object v12

    .line 224
    invoke-virtual {v12}, Ljava/nio/ByteBuffer;->getLong()J

    .line 225
    .line 226
    .line 227
    move-result-wide v14

    .line 228
    invoke-interface {v4, v13, v14, v15}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    .line 229
    .line 230
    .line 231
    goto :goto_3

    .line 232
    :pswitch_3
    const/4 v14, 0x3

    .line 233
    invoke-static {v14, v12}, Lwe0/b;->r(B[B)V

    .line 234
    .line 235
    .line 236
    aget-byte v12, v12, v11

    .line 237
    .line 238
    if-eqz v12, :cond_8

    .line 239
    .line 240
    move v12, v11

    .line 241
    goto :goto_5

    .line 242
    :cond_8
    move v12, v10

    .line 243
    :goto_5
    invoke-interface {v4, v13, v12}, Landroid/content/SharedPreferences$Editor;->putBoolean(Ljava/lang/String;Z)Landroid/content/SharedPreferences$Editor;

    .line 244
    .line 245
    .line 246
    goto/16 :goto_3

    .line 247
    .line 248
    :pswitch_4
    invoke-static {v6, v12}, Lwe0/b;->r(B[B)V

    .line 249
    .line 250
    .line 251
    new-instance v14, Ljava/lang/String;

    .line 252
    .line 253
    array-length v15, v12

    .line 254
    sub-int/2addr v15, v11

    .line 255
    invoke-static {}, Ljava/nio/charset/Charset;->defaultCharset()Ljava/nio/charset/Charset;

    .line 256
    .line 257
    .line 258
    move-result-object v5

    .line 259
    invoke-direct {v14, v12, v11, v15, v5}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 260
    .line 261
    .line 262
    invoke-interface {v4, v13, v14}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 263
    .line 264
    .line 265
    goto/16 :goto_3

    .line 266
    .line 267
    :pswitch_5
    invoke-static {v11, v12}, Lwe0/b;->r(B[B)V

    .line 268
    .line 269
    .line 270
    array-length v5, v12

    .line 271
    invoke-static {v12, v11, v5}, Ljava/util/Arrays;->copyOfRange([BII)[B

    .line 272
    .line 273
    .line 274
    move-result-object v5

    .line 275
    array-length v12, v5

    .line 276
    if-lez v12, :cond_9

    .line 277
    .line 278
    invoke-static {v5, v10}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object v5

    .line 282
    goto :goto_6

    .line 283
    :cond_9
    const/4 v5, 0x0

    .line 284
    :goto_6
    invoke-interface {v4, v13, v5}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 285
    .line 286
    .line 287
    goto/16 :goto_3

    .line 288
    .line 289
    :cond_a
    new-instance v1, Lvv0/a;

    .line 290
    .line 291
    const-string v2, "Invalid encoded keychain content"

    .line 292
    .line 293
    invoke-direct {v1, v2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 294
    .line 295
    .line 296
    throw v1
    :try_end_0
    .catch Lvv0/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 297
    :catch_0
    :goto_7
    const-string v1, ": Failed to decode data for key \'"

    .line 298
    .line 299
    invoke-static {v9, v8, v1, v13, v7}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 300
    .line 301
    .line 302
    move-result-object v1

    .line 303
    new-array v2, v10, [Ljava/lang/Object;

    .line 304
    .line 305
    invoke-static {v1, v2}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 306
    .line 307
    .line 308
    goto :goto_8

    .line 309
    :cond_b
    move v10, v3

    .line 310
    :goto_8
    if-eqz v10, :cond_c

    .line 311
    .line 312
    invoke-virtual {v0, v4}, Lwv0/a;->d(Landroid/content/SharedPreferences$Editor;)V

    .line 313
    .line 314
    .line 315
    :cond_c
    move v3, v10

    .line 316
    :cond_d
    invoke-interface {v4}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 317
    .line 318
    .line 319
    return v3

    .line 320
    nop

    .line 321
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
