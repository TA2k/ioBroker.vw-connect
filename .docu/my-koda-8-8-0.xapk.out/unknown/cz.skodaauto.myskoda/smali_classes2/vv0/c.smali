.class public final Lvv0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Lvv0/c;


# instance fields
.field public final a:Ljava/util/HashMap;

.field public b:Lc8/g;

.field public c:Lvv0/d;

.field public d:Lvv0/d;

.field public e:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lvv0/c;

    .line 2
    .line 3
    invoke-direct {v0}, Lvv0/c;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lvv0/c;->f:Lvv0/c;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lvv0/c;->a:Ljava/util/HashMap;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final a(Landroid/content/Context;)Lvv0/d;
    .locals 2

    .line 1
    iget-object v0, p0, Lvv0/c;->d:Lvv0/d;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lvv0/c;->b:Lc8/g;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    new-instance v0, Lc8/g;

    .line 10
    .line 11
    invoke-direct {v0, p1}, Lc8/g;-><init>(Landroid/content/Context;)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lvv0/c;->b:Lc8/g;

    .line 15
    .line 16
    :cond_0
    iget-object p1, p0, Lvv0/c;->b:Lc8/g;

    .line 17
    .line 18
    iget-boolean v0, p1, Lc8/g;->c:Z

    .line 19
    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    const-string v0, "com.wultra.PowerAuthKeychain.BackupKey"

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    invoke-static {v0, v1, p1}, Lvv0/d;->e(Ljava/lang/String;ZLc8/g;)Lvv0/d;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iput-object p1, p0, Lvv0/c;->d:Lvv0/d;

    .line 30
    .line 31
    if-nez p1, :cond_1

    .line 32
    .line 33
    const-string p1, "KeychainFactory: Unable to acquire common backup key provider for EncryptedKeychain."

    .line 34
    .line 35
    new-array v0, v1, [Ljava/lang/Object;

    .line 36
    .line 37
    invoke-static {p1, v0}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    :cond_1
    iget-object p0, p0, Lvv0/c;->d:Lvv0/d;

    .line 41
    .line 42
    return-object p0
.end method

.method public final b(Landroid/content/Context;)I
    .locals 7

    .line 1
    iget v0, p0, Lvv0/c;->e:I

    .line 2
    .line 3
    if-nez v0, :cond_10

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lvv0/c;->c(Landroid/content/Context;)Lvv0/d;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0, p1}, Lvv0/c;->a(Landroid/content/Context;)Lvv0/d;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    const/4 v1, 0x0

    .line 14
    const/4 v2, 0x0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    move-object v0, v1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    iget-object v3, v0, Lvv0/d;->e:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v3, Lc8/g;

    .line 22
    .line 23
    iget-boolean v4, v3, Lc8/g;->a:Z

    .line 24
    .line 25
    if-eqz v4, :cond_2

    .line 26
    .line 27
    iget-boolean v4, v3, Lc8/g;->b:Z

    .line 28
    .line 29
    if-eqz v4, :cond_2

    .line 30
    .line 31
    iget-boolean v3, v3, Lc8/g;->c:Z

    .line 32
    .line 33
    if-eqz v3, :cond_2

    .line 34
    .line 35
    if-nez p1, :cond_1

    .line 36
    .line 37
    const-string p1, "EncryptedKeychain: Backup key provider is required but not provided."

    .line 38
    .line 39
    new-array v3, v2, [Ljava/lang/Object;

    .line 40
    .line 41
    invoke-static {p1, v3}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    move-object v0, p1

    .line 46
    :cond_2
    :goto_0
    if-eqz v0, :cond_3

    .line 47
    .line 48
    invoke-virtual {v0}, Lvv0/d;->g()Ljavax/crypto/SecretKey;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    goto :goto_1

    .line 53
    :cond_3
    move-object p1, v1

    .line 54
    :goto_1
    if-eqz v0, :cond_4

    .line 55
    .line 56
    const-class v3, Lvv0/d;

    .line 57
    .line 58
    monitor-enter v3

    .line 59
    :try_start_0
    invoke-virtual {v0}, Lvv0/d;->g()Ljavax/crypto/SecretKey;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-virtual {v0, v1}, Lvv0/d;->f(Ljavax/crypto/SecretKey;)Landroid/security/keystore/KeyInfo;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    monitor-exit v3

    .line 68
    goto :goto_2

    .line 69
    :catchall_0
    move-exception p0

    .line 70
    monitor-exit v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 71
    throw p0

    .line 72
    :cond_4
    :goto_2
    const/4 v3, 0x1

    .line 73
    if-eqz p1, :cond_f

    .line 74
    .line 75
    if-eqz v1, :cond_f

    .line 76
    .line 77
    iget-object p1, v0, Lvv0/d;->e:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p1, Lc8/g;

    .line 80
    .line 81
    iget-boolean v4, p1, Lc8/g;->a:Z

    .line 82
    .line 83
    if-eqz v4, :cond_e

    .line 84
    .line 85
    iget-boolean v5, p1, Lc8/g;->b:Z

    .line 86
    .line 87
    if-eqz v5, :cond_e

    .line 88
    .line 89
    const-string v4, "TestIdentifier"

    .line 90
    .line 91
    invoke-virtual {v0}, Lvv0/d;->g()Ljavax/crypto/SecretKey;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    if-nez v0, :cond_5

    .line 96
    .line 97
    const-string p1, "verifyKeystoreEncryption: Failed to acquire secret key."

    .line 98
    .line 99
    new-array v0, v2, [Ljava/lang/Object;

    .line 100
    .line 101
    invoke-static {p1, v0}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    goto/16 :goto_5

    .line 105
    .line 106
    :cond_5
    new-array v5, v2, [B

    .line 107
    .line 108
    invoke-static {v5, v0, v4}, Llp/qd;->b([BLjavax/crypto/SecretKey;Ljava/lang/String;)[B

    .line 109
    .line 110
    .line 111
    move-result-object v6

    .line 112
    if-nez v6, :cond_6

    .line 113
    .line 114
    const-string p1, "verifyKeystoreEncryption: Empty data encryption failed."

    .line 115
    .line 116
    new-array v0, v2, [Ljava/lang/Object;

    .line 117
    .line 118
    invoke-static {p1, v0}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    goto/16 :goto_5

    .line 122
    .line 123
    :cond_6
    invoke-static {v6, v0, v4}, Llp/qd;->a([BLjavax/crypto/SecretKey;Ljava/lang/String;)[B

    .line 124
    .line 125
    .line 126
    move-result-object v6

    .line 127
    if-eqz v6, :cond_d

    .line 128
    .line 129
    invoke-static {v5, v6}, Ljava/util/Arrays;->equals([B[B)Z

    .line 130
    .line 131
    .line 132
    move-result v5

    .line 133
    if-nez v5, :cond_7

    .line 134
    .line 135
    goto :goto_4

    .line 136
    :cond_7
    const-string v5, "com.wultra.PowerAuthKeychain.IsEncrypted"

    .line 137
    .line 138
    invoke-static {}, Ljava/nio/charset/Charset;->defaultCharset()Ljava/nio/charset/Charset;

    .line 139
    .line 140
    .line 141
    move-result-object v6

    .line 142
    invoke-virtual {v5, v6}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 143
    .line 144
    .line 145
    move-result-object v5

    .line 146
    invoke-static {v5, v0, v4}, Llp/qd;->b([BLjavax/crypto/SecretKey;Ljava/lang/String;)[B

    .line 147
    .line 148
    .line 149
    move-result-object v6

    .line 150
    if-nez v6, :cond_8

    .line 151
    .line 152
    const-string p1, "verifyKeystoreEncryption: Non-empty data encryption failed."

    .line 153
    .line 154
    new-array v0, v2, [Ljava/lang/Object;

    .line 155
    .line 156
    invoke-static {p1, v0}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    goto :goto_5

    .line 160
    :cond_8
    invoke-static {v6, v0, v4}, Llp/qd;->a([BLjavax/crypto/SecretKey;Ljava/lang/String;)[B

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    if-eqz v0, :cond_c

    .line 165
    .line 166
    invoke-static {v5, v0}, Ljava/util/Arrays;->equals([B[B)Z

    .line 167
    .line 168
    .line 169
    move-result v0

    .line 170
    if-nez v0, :cond_9

    .line 171
    .line 172
    goto :goto_3

    .line 173
    :cond_9
    invoke-virtual {v1}, Landroid/security/keystore/KeyInfo;->isInsideSecureHardware()Z

    .line 174
    .line 175
    .line 176
    move-result v0

    .line 177
    if-eqz v0, :cond_b

    .line 178
    .line 179
    iget-boolean p1, p1, Lc8/g;->c:Z

    .line 180
    .line 181
    const/4 v0, 0x3

    .line 182
    if-eqz p1, :cond_a

    .line 183
    .line 184
    const-string p1, "KeychainFactory: StrongBox is supported but not enabled on this device."

    .line 185
    .line 186
    new-array v1, v2, [Ljava/lang/Object;

    .line 187
    .line 188
    invoke-static {p1, v1}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    iput v0, p0, Lvv0/c;->e:I

    .line 192
    .line 193
    goto :goto_5

    .line 194
    :cond_a
    iput v0, p0, Lvv0/c;->e:I

    .line 195
    .line 196
    goto :goto_5

    .line 197
    :cond_b
    const/4 p1, 0x2

    .line 198
    iput p1, p0, Lvv0/c;->e:I

    .line 199
    .line 200
    goto :goto_5

    .line 201
    :cond_c
    :goto_3
    const-string p1, "verifyKeystoreEncryption: Non-empty data decryption failed."

    .line 202
    .line 203
    new-array v0, v2, [Ljava/lang/Object;

    .line 204
    .line 205
    invoke-static {p1, v0}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    goto :goto_5

    .line 209
    :cond_d
    :goto_4
    const-string p1, "verifyKeystoreEncryption: Empty data decryption failed."

    .line 210
    .line 211
    new-array v0, v2, [Ljava/lang/Object;

    .line 212
    .line 213
    invoke-static {p1, v0}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 214
    .line 215
    .line 216
    goto :goto_5

    .line 217
    :cond_e
    if-eqz v4, :cond_f

    .line 218
    .line 219
    const-string p1, "KeychainFactory: Android KeyStore is supported but not enabled on this device."

    .line 220
    .line 221
    new-array v0, v2, [Ljava/lang/Object;

    .line 222
    .line 223
    invoke-static {p1, v0}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    iput v3, p0, Lvv0/c;->e:I

    .line 227
    .line 228
    :cond_f
    :goto_5
    iget p1, p0, Lvv0/c;->e:I

    .line 229
    .line 230
    if-nez p1, :cond_10

    .line 231
    .line 232
    iput v3, p0, Lvv0/c;->e:I

    .line 233
    .line 234
    :cond_10
    iget p0, p0, Lvv0/c;->e:I

    .line 235
    .line 236
    return p0
.end method

.method public final c(Landroid/content/Context;)Lvv0/d;
    .locals 2

    .line 1
    iget-object v0, p0, Lvv0/c;->c:Lvv0/d;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lvv0/c;->b:Lc8/g;

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    new-instance v0, Lc8/g;

    .line 10
    .line 11
    invoke-direct {v0, p1}, Lc8/g;-><init>(Landroid/content/Context;)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lvv0/c;->b:Lc8/g;

    .line 15
    .line 16
    :cond_0
    iget-object p1, p0, Lvv0/c;->b:Lc8/g;

    .line 17
    .line 18
    const-string v0, "com.wultra.PowerAuthKeychain.MasterKey"

    .line 19
    .line 20
    const/4 v1, 0x1

    .line 21
    invoke-static {v0, v1, p1}, Lvv0/d;->e(Ljava/lang/String;ZLc8/g;)Lvv0/d;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iput-object p1, p0, Lvv0/c;->c:Lvv0/d;

    .line 26
    .line 27
    if-nez p1, :cond_1

    .line 28
    .line 29
    const/4 p1, 0x0

    .line 30
    new-array p1, p1, [Ljava/lang/Object;

    .line 31
    .line 32
    const-string v0, "KeychainFactory: Unable to acquire common master key provider for EncryptedKeychain."

    .line 33
    .line 34
    invoke-static {v0, p1}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    :cond_1
    iget-object p0, p0, Lvv0/c;->c:Lvv0/d;

    .line 38
    .line 39
    return-object p0
.end method
