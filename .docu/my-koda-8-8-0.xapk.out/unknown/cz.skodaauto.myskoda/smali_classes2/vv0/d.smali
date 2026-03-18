.class public final Lvv0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llv/f;


# instance fields
.field public a:Z

.field public b:Ljava/lang/Object;

.field public c:Ljava/lang/Object;

.field public d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    new-instance v0, Landroid/content/Intent;

    const-string v1, "android.intent.action.VIEW"

    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    iput-object v0, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 9
    new-instance v0, Lpy/a;

    const/16 v1, 0xc

    .line 10
    invoke-direct {v0, v1}, Lpy/a;-><init>(I)V

    .line 11
    iput-object v0, p0, Lvv0/d;->c:Ljava/lang/Object;

    const/4 v0, 0x1

    .line 12
    iput-boolean v0, p0, Lvv0/d;->a:Z

    return-void
.end method

.method public constructor <init>(Ljava/security/KeyStore;Ljava/lang/String;ZLc8/g;La61/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 3
    iput-object p2, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 4
    iput-object p5, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 5
    iput-boolean p3, p0, Lvv0/d;->a:Z

    .line 6
    iput-object p4, p0, Lvv0/d;->e:Ljava/lang/Object;

    return-void
.end method

.method public static e(Ljava/lang/String;ZLc8/g;)Lvv0/d;
    .locals 7

    .line 1
    new-instance v5, La61/a;

    .line 2
    .line 3
    const/16 v0, 0x19

    .line 4
    .line 5
    invoke-direct {v5, v0}, La61/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    const/4 v6, 0x0

    .line 9
    :try_start_0
    const-string v0, "AndroidKeyStore"

    .line 10
    .line 11
    invoke-static {v0}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {v1, v6}, Ljava/security/KeyStore;->load(Ljava/security/KeyStore$LoadStoreParameter;)V

    .line 16
    .line 17
    .line 18
    new-instance v0, Lvv0/d;
    :try_end_0
    .catch Ljava/security/KeyStoreException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/security/cert/CertificateException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_0 .. :try_end_0} :catch_1

    .line 19
    .line 20
    move-object v2, p0

    .line 21
    move v3, p1

    .line 22
    move-object v4, p2

    .line 23
    :try_start_1
    invoke-direct/range {v0 .. v5}, Lvv0/d;-><init>(Ljava/security/KeyStore;Ljava/lang/String;ZLc8/g;La61/a;)V
    :try_end_1
    .catch Ljava/security/KeyStoreException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/security/cert/CertificateException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_1 .. :try_end_1} :catch_0

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :catch_0
    move-exception v0

    .line 28
    :goto_0
    move-object p0, v0

    .line 29
    goto :goto_1

    .line 30
    :catch_1
    move-exception v0

    .line 31
    move-object v2, p0

    .line 32
    goto :goto_0

    .line 33
    :goto_1
    const-string p1, "SymmetricKeyProvider: "

    .line 34
    .line 35
    const-string p2, ": Unable to initialize Android KeyStore. Exception: "

    .line 36
    .line 37
    invoke-static {p1, v2, p2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    const/4 p1, 0x0

    .line 53
    new-array p1, p1, [Ljava/lang/Object;

    .line 54
    .line 55
    invoke-static {p0, p1}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-object v6
.end method

.method public static h(Landroid/security/keystore/KeyInfo;)V
    .locals 2

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/security/keystore/KeyInfo;->isInsideSecureHardware()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    const-string v1, "secure-hw"

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    :cond_1
    invoke-virtual {p0}, Landroid/security/keystore/KeyInfo;->isInvalidatedByBiometricEnrollment()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_2

    .line 25
    .line 26
    const-string v1, "inv-by-bio-enrollment"

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    :cond_2
    invoke-virtual {p0}, Landroid/security/keystore/KeyInfo;->isUserAuthenticationRequired()Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-eqz v1, :cond_3

    .line 36
    .line 37
    const-string v1, "user-auth-required"

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    :cond_3
    invoke-virtual {p0}, Landroid/security/keystore/KeyInfo;->isUserConfirmationRequired()Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_4

    .line 47
    .line 48
    const-string p0, "user-conf-required"

    .line 49
    .line 50
    invoke-virtual {v0, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    :cond_4
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    if-eqz p0, :cond_5

    .line 58
    .line 59
    return-void

    .line 60
    :cond_5
    const-string p0, ", "

    .line 61
    .line 62
    invoke-static {p0, v0}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    return-void
.end method


# virtual methods
.method public a(Lmv/a;)Ljava/util/ArrayList;
    .locals 8

    .line 1
    const-string v0, "Unsupported image format: "

    .line 2
    .line 3
    iget-object v1, p0, Lvv0/d;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Ljp/c;

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lvv0/d;->j()Z

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lvv0/d;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Ljp/c;

    .line 15
    .line 16
    if-eqz p0, :cond_6

    .line 17
    .line 18
    new-instance v1, Ljp/g;

    .line 19
    .line 20
    iget v4, p1, Lmv/a;->c:I

    .line 21
    .line 22
    iget v5, p1, Lmv/a;->d:I

    .line 23
    .line 24
    iget v2, p1, Lmv/a;->e:I

    .line 25
    .line 26
    invoke-static {v2}, Ljp/xa;->a(I)I

    .line 27
    .line 28
    .line 29
    move-result v7

    .line 30
    const-wide/16 v2, 0x0

    .line 31
    .line 32
    const/4 v6, 0x0

    .line 33
    invoke-direct/range {v1 .. v7}, Ljp/g;-><init>(JIIII)V

    .line 34
    .line 35
    .line 36
    :try_start_0
    iget v2, p1, Lmv/a;->f:I

    .line 37
    .line 38
    const/4 v3, -0x1

    .line 39
    const/4 v4, 0x0

    .line 40
    if-eq v2, v3, :cond_4

    .line 41
    .line 42
    const/16 v3, 0x11

    .line 43
    .line 44
    if-eq v2, v3, :cond_3

    .line 45
    .line 46
    const/16 v3, 0x23

    .line 47
    .line 48
    if-eq v2, v3, :cond_2

    .line 49
    .line 50
    const v3, 0x32315659

    .line 51
    .line 52
    .line 53
    if-ne v2, v3, :cond_1

    .line 54
    .line 55
    invoke-static {p1}, Ljp/ya;->a(Lmv/a;)Ljava/nio/ByteBuffer;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    new-instance v0, Lyo/b;

    .line 60
    .line 61
    invoke-direct {v0, p1}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0, v0, v1}, Ljp/c;->W(Lyo/b;Ljp/g;)[Ljp/ve;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    goto :goto_0

    .line 69
    :cond_1
    new-instance p0, Lbv/a;

    .line 70
    .line 71
    iget p1, p1, Lmv/a;->f:I

    .line 72
    .line 73
    new-instance v1, Ljava/lang/StringBuilder;

    .line 74
    .line 75
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    const/4 v0, 0x3

    .line 86
    invoke-direct {p0, p1, v0}, Lbv/a;-><init>(Ljava/lang/String;I)V

    .line 87
    .line 88
    .line 89
    throw p0

    .line 90
    :cond_2
    invoke-virtual {p1}, Lmv/a;->b()[Landroid/media/Image$Plane;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    aget-object v0, p1, v4

    .line 98
    .line 99
    invoke-virtual {v0}, Landroid/media/Image$Plane;->getRowStride()I

    .line 100
    .line 101
    .line 102
    move-result v0

    .line 103
    iput v0, v1, Ljp/g;->d:I

    .line 104
    .line 105
    aget-object p1, p1, v4

    .line 106
    .line 107
    invoke-virtual {p1}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    new-instance v0, Lyo/b;

    .line 112
    .line 113
    invoke-direct {v0, p1}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p0, v0, v1}, Ljp/c;->W(Lyo/b;Ljp/g;)[Ljp/ve;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    goto :goto_0

    .line 121
    :cond_3
    new-instance p1, Lyo/b;

    .line 122
    .line 123
    const/4 v0, 0x0

    .line 124
    invoke-direct {p1, v0}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0, p1, v1}, Ljp/c;->W(Lyo/b;Ljp/g;)[Ljp/ve;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    goto :goto_0

    .line 132
    :cond_4
    iget-object p1, p1, Lmv/a;->a:Landroid/graphics/Bitmap;

    .line 133
    .line 134
    new-instance v0, Lyo/b;

    .line 135
    .line 136
    invoke-direct {v0, p1}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {p0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 140
    .line 141
    .line 142
    move-result-object p1

    .line 143
    sget v2, Ljp/q;->a:I

    .line 144
    .line 145
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 146
    .line 147
    .line 148
    const/4 v0, 0x1

    .line 149
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v1, p1, v4}, Ljp/g;->writeToParcel(Landroid/os/Parcel;I)V

    .line 153
    .line 154
    .line 155
    const/4 v0, 0x2

    .line 156
    invoke-virtual {p0, p1, v0}, Lbp/a;->T(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    sget-object p1, Ljp/ve;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 161
    .line 162
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->createTypedArray(Landroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    check-cast p1, [Ljp/ve;

    .line 167
    .line 168
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 169
    .line 170
    .line 171
    move-object p0, p1

    .line 172
    :goto_0
    new-instance p1, Ljava/util/ArrayList;

    .line 173
    .line 174
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 175
    .line 176
    .line 177
    array-length v0, p0

    .line 178
    :goto_1
    if-ge v4, v0, :cond_5

    .line 179
    .line 180
    aget-object v1, p0, v4

    .line 181
    .line 182
    new-instance v2, Ljv/a;

    .line 183
    .line 184
    new-instance v3, Lhu/q;

    .line 185
    .line 186
    const/16 v5, 0x12

    .line 187
    .line 188
    invoke-direct {v3, v1, v5}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    .line 189
    .line 190
    .line 191
    invoke-direct {v2, v3}, Ljv/a;-><init>(Lkv/a;)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 195
    .line 196
    .line 197
    add-int/lit8 v4, v4, 0x1

    .line 198
    .line 199
    goto :goto_1

    .line 200
    :cond_5
    return-object p1

    .line 201
    :catch_0
    move-exception v0

    .line 202
    move-object p0, v0

    .line 203
    new-instance p1, Lbv/a;

    .line 204
    .line 205
    const-string v0, "Failed to detect with legacy barcode detector"

    .line 206
    .line 207
    invoke-direct {p1, v0, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 208
    .line 209
    .line 210
    throw p1

    .line 211
    :cond_6
    new-instance p0, Lbv/a;

    .line 212
    .line 213
    const-string p1, "Error initializing the legacy barcode scanner."

    .line 214
    .line 215
    const/16 v0, 0xe

    .line 216
    .line 217
    invoke-direct {p0, p1, v0}, Lbv/a;-><init>(Ljava/lang/String;I)V

    .line 218
    .line 219
    .line 220
    throw p0
.end method

.method public b()V
    .locals 2

    .line 1
    iget-object v0, p0, Lvv0/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ld01/g;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-boolean v1, p0, Lvv0/d;->a:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    monitor-exit v0

    .line 11
    return-void

    .line 12
    :cond_0
    const/4 v1, 0x1

    .line 13
    :try_start_1
    iput-boolean v1, p0, Lvv0/d;->a:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 14
    .line 15
    monitor-exit v0

    .line 16
    iget-object v0, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lu01/f0;

    .line 19
    .line 20
    invoke-static {v0}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 21
    .line 22
    .line 23
    :try_start_2
    iget-object p0, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, La8/b;

    .line 26
    .line 27
    invoke-virtual {p0}, La8/b;->b()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 28
    .line 29
    .line 30
    :catch_0
    return-void

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    monitor-exit v0

    .line 33
    throw p0
.end method

.method public c()Lc2/k;
    .locals 9

    .line 1
    iget-object v0, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/content/Intent;

    .line 4
    .line 5
    const-string v1, "android.support.customtabs.extra.SESSION"

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Landroid/content/Intent;->hasExtra(Ljava/lang/String;)Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/4 v3, 0x0

    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    new-instance v2, Landroid/os/Bundle;

    .line 15
    .line 16
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v2, v1, v3}, Landroid/os/Bundle;->putBinder(Ljava/lang/String;Landroid/os/IBinder;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0, v2}, Landroid/content/Intent;->putExtras(Landroid/os/Bundle;)Landroid/content/Intent;

    .line 23
    .line 24
    .line 25
    :cond_0
    const-string v1, "android.support.customtabs.extra.EXTRA_ENABLE_INSTANT_APPS"

    .line 26
    .line 27
    iget-boolean v2, p0, Lvv0/d;->a:Z

    .line 28
    .line 29
    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Z)Landroid/content/Intent;

    .line 30
    .line 31
    .line 32
    iget-object v1, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lpy/a;

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    new-instance v1, Landroid/os/Bundle;

    .line 40
    .line 41
    invoke-direct {v1}, Landroid/os/Bundle;-><init>()V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0, v1}, Landroid/content/Intent;->putExtras(Landroid/os/Bundle;)Landroid/content/Intent;

    .line 45
    .line 46
    .line 47
    iget-object v1, p0, Lvv0/d;->e:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v1, Landroid/os/Bundle;

    .line 50
    .line 51
    if-eqz v1, :cond_1

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Landroid/content/Intent;->putExtras(Landroid/os/Bundle;)Landroid/content/Intent;

    .line 54
    .line 55
    .line 56
    :cond_1
    const-string v1, "androidx.browser.customtabs.extra.SHARE_STATE"

    .line 57
    .line 58
    const/4 v2, 0x0

    .line 59
    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 60
    .line 61
    .line 62
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 63
    .line 64
    invoke-static {}, Landroid/os/LocaleList;->getAdjustedDefault()Landroid/os/LocaleList;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    invoke-virtual {v4}, Landroid/os/LocaleList;->size()I

    .line 69
    .line 70
    .line 71
    move-result v5

    .line 72
    if-lez v5, :cond_2

    .line 73
    .line 74
    invoke-virtual {v4, v2}, Landroid/os/LocaleList;->get(I)Ljava/util/Locale;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    invoke-virtual {v4}, Ljava/util/Locale;->toLanguageTag()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    goto :goto_0

    .line 83
    :cond_2
    move-object v4, v3

    .line 84
    :goto_0
    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 85
    .line 86
    .line 87
    move-result v5

    .line 88
    if-nez v5, :cond_4

    .line 89
    .line 90
    const-string v5, "com.android.browser.headers"

    .line 91
    .line 92
    invoke-virtual {v0, v5}, Landroid/content/Intent;->hasExtra(Ljava/lang/String;)Z

    .line 93
    .line 94
    .line 95
    move-result v6

    .line 96
    if-eqz v6, :cond_3

    .line 97
    .line 98
    invoke-virtual {v0, v5}, Landroid/content/Intent;->getBundleExtra(Ljava/lang/String;)Landroid/os/Bundle;

    .line 99
    .line 100
    .line 101
    move-result-object v6

    .line 102
    goto :goto_1

    .line 103
    :cond_3
    new-instance v6, Landroid/os/Bundle;

    .line 104
    .line 105
    invoke-direct {v6}, Landroid/os/Bundle;-><init>()V

    .line 106
    .line 107
    .line 108
    :goto_1
    const-string v7, "Accept-Language"

    .line 109
    .line 110
    invoke-virtual {v6, v7}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 111
    .line 112
    .line 113
    move-result v8

    .line 114
    if-nez v8, :cond_4

    .line 115
    .line 116
    invoke-virtual {v6, v7, v4}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v0, v5, v6}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Bundle;)Landroid/content/Intent;

    .line 120
    .line 121
    .line 122
    :cond_4
    const/16 v4, 0x22

    .line 123
    .line 124
    if-lt v1, v4, :cond_6

    .line 125
    .line 126
    iget-object v4, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v4, Landroid/app/ActivityOptions;

    .line 129
    .line 130
    if-nez v4, :cond_5

    .line 131
    .line 132
    invoke-static {}, Landroid/app/ActivityOptions;->makeBasic()Landroid/app/ActivityOptions;

    .line 133
    .line 134
    .line 135
    move-result-object v4

    .line 136
    iput-object v4, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 137
    .line 138
    :cond_5
    iget-object v4, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 139
    .line 140
    check-cast v4, Landroid/app/ActivityOptions;

    .line 141
    .line 142
    invoke-static {v4}, Lb/a;->p(Landroid/app/ActivityOptions;)V

    .line 143
    .line 144
    .line 145
    :cond_6
    const/16 v4, 0x24

    .line 146
    .line 147
    if-lt v1, v4, :cond_8

    .line 148
    .line 149
    iget-object v1, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 150
    .line 151
    check-cast v1, Landroid/app/ActivityOptions;

    .line 152
    .line 153
    if-nez v1, :cond_7

    .line 154
    .line 155
    invoke-static {}, Landroid/app/ActivityOptions;->makeBasic()Landroid/app/ActivityOptions;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    iput-object v1, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 160
    .line 161
    :cond_7
    const-string v1, "androidx.browser.customtabs.extra.DISABLE_BACKGROUND_INTERACTION"

    .line 162
    .line 163
    invoke-virtual {v0, v1, v2}, Landroid/content/Intent;->getBooleanExtra(Ljava/lang/String;Z)Z

    .line 164
    .line 165
    .line 166
    move-result v1

    .line 167
    xor-int/lit8 v1, v1, 0x1

    .line 168
    .line 169
    iget-object v2, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 170
    .line 171
    check-cast v2, Landroid/app/ActivityOptions;

    .line 172
    .line 173
    invoke-static {v2, v1}, Lb/b;->f(Landroid/app/ActivityOptions;Z)V

    .line 174
    .line 175
    .line 176
    :cond_8
    iget-object p0, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast p0, Landroid/app/ActivityOptions;

    .line 179
    .line 180
    if-eqz p0, :cond_9

    .line 181
    .line 182
    invoke-virtual {p0}, Landroid/app/ActivityOptions;->toBundle()Landroid/os/Bundle;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    :cond_9
    new-instance p0, Lc2/k;

    .line 187
    .line 188
    const/16 v1, 0x15

    .line 189
    .line 190
    invoke-direct {p0, v1, v0, v3}, Lc2/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    return-object p0
.end method

.method public d()Ljavax/crypto/SecretKey;
    .locals 5

    .line 1
    iget-object v0, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/String;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    :try_start_0
    const-string v2, "AES"

    .line 7
    .line 8
    const-string v3, "AndroidKeyStore"

    .line 9
    .line 10
    invoke-static {v2, v3}, Ljavax/crypto/KeyGenerator;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    new-instance v3, Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 15
    .line 16
    const/4 v4, 0x3

    .line 17
    invoke-direct {v3, v0, v4}, Landroid/security/keystore/KeyGenParameterSpec$Builder;-><init>(Ljava/lang/String;I)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, La61/a;

    .line 23
    .line 24
    invoke-virtual {p0, v3}, La61/a;->c(Landroid/security/keystore/KeyGenParameterSpec$Builder;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v3, v1}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setIsStrongBoxBacked(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v3}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->build()Landroid/security/keystore/KeyGenParameterSpec;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {v2, p0}, Ljavax/crypto/KeyGenerator;->init(Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v2}, Ljavax/crypto/KeyGenerator;->generateKey()Ljavax/crypto/SecretKey;

    .line 38
    .line 39
    .line 40
    move-result-object p0
    :try_end_0
    .catch Ljava/security/ProviderException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/NoSuchProviderException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/InvalidAlgorithmParameterException; {:try_start_0 .. :try_end_0} :catch_0

    .line 41
    return-object p0

    .line 42
    :catch_0
    move-exception p0

    .line 43
    new-instance v2, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    const-string v3, "SymmetricKeyProvider: "

    .line 46
    .line 47
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v0, ": Failed to generate new key. Exception: "

    .line 54
    .line 55
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    new-array v0, v1, [Ljava/lang/Object;

    .line 70
    .line 71
    invoke-static {p0, v0}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    const/4 p0, 0x0

    .line 75
    return-object p0
.end method

.method public f(Ljavax/crypto/SecretKey;)Landroid/security/keystore/KeyInfo;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    return-object v0

    .line 5
    :cond_0
    :try_start_0
    invoke-interface {p1}, Ljava/security/Key;->getAlgorithm()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const-string v2, "AndroidKeyStore"

    .line 10
    .line 11
    invoke-static {v1, v2}, Ljavax/crypto/SecretKeyFactory;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    const-class v2, Landroid/security/keystore/KeyInfo;

    .line 16
    .line 17
    invoke-virtual {v1, p1, v2}, Ljavax/crypto/SecretKeyFactory;->getKeySpec(Ljavax/crypto/SecretKey;Ljava/lang/Class;)Ljava/security/spec/KeySpec;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    check-cast p1, Landroid/security/keystore/KeyInfo;
    :try_end_0
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/NoSuchProviderException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/spec/InvalidKeySpecException; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    return-object p1

    .line 24
    :catch_0
    move-exception p1

    .line 25
    new-instance v1, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v2, "SymmetricKeyProvider: "

    .line 28
    .line 29
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget-object p0, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Ljava/lang/String;

    .line 35
    .line 36
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string p0, ": Failed to acquire KeyInfo: Exception: "

    .line 40
    .line 41
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    const/4 p1, 0x0

    .line 56
    new-array p1, p1, [Ljava/lang/Object;

    .line 57
    .line 58
    invoke-static {p0, p1}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    return-object v0
.end method

.method public g()Ljavax/crypto/SecretKey;
    .locals 6

    .line 1
    const-string v0, "SymmetricKeyProvider: "

    .line 2
    .line 3
    const-class v1, Lvv0/d;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    const/4 v2, 0x0

    .line 7
    :try_start_0
    iget-object v3, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Ljava/security/KeyStore;

    .line 10
    .line 11
    iget-object v4, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v4, Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {v3, v4}, Ljava/security/KeyStore;->containsAlias(Ljava/lang/String;)Z

    .line 16
    .line 17
    .line 18
    move-result v3
    :try_end_0
    .catch Ljava/security/KeyStoreException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    goto :goto_0

    .line 20
    :catch_0
    move v3, v2

    .line 21
    :goto_0
    const/4 v4, 0x0

    .line 22
    if-eqz v3, :cond_0

    .line 23
    .line 24
    :try_start_1
    iget-object v3, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v3, Ljava/security/KeyStore;

    .line 27
    .line 28
    iget-object v5, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v5, Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {v3, v5, v4}, Ljava/security/KeyStore;->getKey(Ljava/lang/String;[C)Ljava/security/Key;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    check-cast v3, Ljavax/crypto/SecretKey;
    :try_end_1
    .catch Ljava/security/KeyStoreException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/security/UnrecoverableKeyException; {:try_start_1 .. :try_end_1} :catch_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 37
    .line 38
    :try_start_2
    monitor-exit v1

    .line 39
    return-object v3

    .line 40
    :catchall_0
    move-exception p0

    .line 41
    goto :goto_2

    .line 42
    :catch_1
    move-exception v3

    .line 43
    new-instance v5, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    invoke-direct {v5, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p0, Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string p0, "Failed to get key. Exception: "

    .line 56
    .line 57
    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v3}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    invoke-virtual {v5, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    new-array v0, v2, [Ljava/lang/Object;

    .line 72
    .line 73
    invoke-static {p0, v0}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    monitor-exit v1

    .line 77
    return-object v4

    .line 78
    :cond_0
    iget-boolean v0, p0, Lvv0/d;->a:Z

    .line 79
    .line 80
    if-eqz v0, :cond_1

    .line 81
    .line 82
    iget-object v0, p0, Lvv0/d;->e:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v0, Lc8/g;

    .line 85
    .line 86
    iget-boolean v0, v0, Lc8/g;->c:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 87
    .line 88
    if-eqz v0, :cond_1

    .line 89
    .line 90
    :try_start_3
    const-string v0, "AES"

    .line 91
    .line 92
    const-string v2, "AndroidKeyStore"

    .line 93
    .line 94
    invoke-static {v0, v2}, Ljavax/crypto/KeyGenerator;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    new-instance v2, Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 99
    .line 100
    iget-object v3, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v3, Ljava/lang/String;

    .line 103
    .line 104
    const/4 v5, 0x3

    .line 105
    invoke-direct {v2, v3, v5}, Landroid/security/keystore/KeyGenParameterSpec$Builder;-><init>(Ljava/lang/String;I)V

    .line 106
    .line 107
    .line 108
    iget-object v3, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v3, La61/a;

    .line 111
    .line 112
    invoke-virtual {v3, v2}, La61/a;->c(Landroid/security/keystore/KeyGenParameterSpec$Builder;)V

    .line 113
    .line 114
    .line 115
    const/4 v3, 0x1

    .line 116
    invoke-virtual {v2, v3}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->setIsStrongBoxBacked(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    invoke-virtual {v2}, Landroid/security/keystore/KeyGenParameterSpec$Builder;->build()Landroid/security/keystore/KeyGenParameterSpec;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    invoke-virtual {v0, v2}, Ljavax/crypto/KeyGenerator;->init(Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v0}, Ljavax/crypto/KeyGenerator;->generateKey()Ljavax/crypto/SecretKey;

    .line 128
    .line 129
    .line 130
    move-result-object v4
    :try_end_3
    .catch Ljava/security/ProviderException; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/security/NoSuchProviderException; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/security/InvalidAlgorithmParameterException; {:try_start_3 .. :try_end_3} :catch_2
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 131
    goto :goto_1

    .line 132
    :catch_2
    move-exception v0

    .line 133
    :try_start_4
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_1
    invoke-virtual {p0}, Lvv0/d;->d()Ljavax/crypto/SecretKey;

    .line 138
    .line 139
    .line 140
    move-result-object v4

    .line 141
    :goto_1
    if-eqz v4, :cond_2

    .line 142
    .line 143
    invoke-virtual {p0, v4}, Lvv0/d;->f(Ljavax/crypto/SecretKey;)Landroid/security/keystore/KeyInfo;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    invoke-static {p0}, Lvv0/d;->h(Landroid/security/keystore/KeyInfo;)V

    .line 148
    .line 149
    .line 150
    :cond_2
    monitor-exit v1

    .line 151
    return-object v4

    .line 152
    :goto_2
    monitor-exit v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 153
    throw p0
.end method

.method public i(Lc2/k;Lw3/t;Z)I
    .locals 18

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v0, v1, Lvv0/d;->c:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lp3/d;

    .line 6
    .line 7
    iget-object v2, v1, Lvv0/d;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v2, Lv3/s;

    .line 10
    .line 11
    iget-boolean v3, v1, Lvv0/d;->a:Z

    .line 12
    .line 13
    const/4 v4, 0x0

    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    return v4

    .line 17
    :cond_0
    const/4 v3, 0x1

    .line 18
    :try_start_0
    iput-boolean v3, v1, Lvv0/d;->a:Z

    .line 19
    .line 20
    iget-object v5, v1, Lvv0/d;->d:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v5, Lhu/q;

    .line 23
    .line 24
    move-object/from16 v6, p1

    .line 25
    .line 26
    move-object/from16 v7, p2

    .line 27
    .line 28
    invoke-virtual {v5, v6, v7}, Lhu/q;->M(Lc2/k;Lw3/t;)Lcom/google/android/gms/internal/measurement/i4;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    iget-object v6, v5, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v6, Landroidx/collection/u;

    .line 35
    .line 36
    invoke-virtual {v6}, Landroidx/collection/u;->h()I

    .line 37
    .line 38
    .line 39
    move-result v7

    .line 40
    move v8, v4

    .line 41
    :goto_0
    if-ge v8, v7, :cond_3

    .line 42
    .line 43
    invoke-virtual {v6, v8}, Landroidx/collection/u;->i(I)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v9

    .line 47
    check-cast v9, Lp3/t;

    .line 48
    .line 49
    iget-boolean v10, v9, Lp3/t;->d:Z

    .line 50
    .line 51
    if-nez v10, :cond_2

    .line 52
    .line 53
    iget-boolean v9, v9, Lp3/t;->h:Z

    .line 54
    .line 55
    if-eqz v9, :cond_1

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_1
    add-int/lit8 v8, v8, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :catchall_0
    move-exception v0

    .line 62
    goto/16 :goto_8

    .line 63
    .line 64
    :cond_2
    :goto_1
    move v7, v4

    .line 65
    goto :goto_2

    .line 66
    :cond_3
    move v7, v3

    .line 67
    :goto_2
    invoke-virtual {v6}, Landroidx/collection/u;->h()I

    .line 68
    .line 69
    .line 70
    move-result v8

    .line 71
    move v9, v4

    .line 72
    :goto_3
    if-ge v9, v8, :cond_6

    .line 73
    .line 74
    invoke-virtual {v6, v9}, Landroidx/collection/u;->i(I)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v10

    .line 78
    check-cast v10, Lp3/t;

    .line 79
    .line 80
    if-nez v7, :cond_4

    .line 81
    .line 82
    invoke-static {v10}, Lp3/s;->b(Lp3/t;)Z

    .line 83
    .line 84
    .line 85
    move-result v11

    .line 86
    if-eqz v11, :cond_5

    .line 87
    .line 88
    :cond_4
    iget-object v11, v1, Lvv0/d;->b:Ljava/lang/Object;

    .line 89
    .line 90
    move-object v12, v11

    .line 91
    check-cast v12, Lv3/h0;

    .line 92
    .line 93
    iget-wide v13, v10, Lp3/t;->c:J

    .line 94
    .line 95
    iget-object v11, v1, Lvv0/d;->e:Ljava/lang/Object;

    .line 96
    .line 97
    move-object v15, v11

    .line 98
    check-cast v15, Lv3/s;

    .line 99
    .line 100
    iget v11, v10, Lp3/t;->i:I

    .line 101
    .line 102
    const/16 v17, 0x1

    .line 103
    .line 104
    move/from16 v16, v11

    .line 105
    .line 106
    invoke-virtual/range {v12 .. v17}, Lv3/h0;->A(JLv3/s;IZ)V

    .line 107
    .line 108
    .line 109
    iget-object v11, v2, Lv3/s;->d:Landroidx/collection/l0;

    .line 110
    .line 111
    invoke-virtual {v11}, Landroidx/collection/l0;->g()Z

    .line 112
    .line 113
    .line 114
    move-result v11

    .line 115
    if-nez v11, :cond_5

    .line 116
    .line 117
    iget-wide v11, v10, Lp3/t;->a:J

    .line 118
    .line 119
    invoke-static {v10}, Lp3/s;->b(Lp3/t;)Z

    .line 120
    .line 121
    .line 122
    move-result v10

    .line 123
    invoke-virtual {v0, v11, v12, v2, v10}, Lp3/d;->a(JLjava/util/List;Z)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v2}, Lv3/s;->clear()V

    .line 127
    .line 128
    .line 129
    :cond_5
    add-int/lit8 v9, v9, 0x1

    .line 130
    .line 131
    goto :goto_3

    .line 132
    :cond_6
    move/from16 v2, p3

    .line 133
    .line 134
    invoke-virtual {v0, v5, v2}, Lp3/d;->b(Lcom/google/android/gms/internal/measurement/i4;Z)Z

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    iget-boolean v2, v5, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 139
    .line 140
    if-eqz v2, :cond_8

    .line 141
    .line 142
    :cond_7
    move v2, v4

    .line 143
    goto :goto_5

    .line 144
    :cond_8
    invoke-virtual {v6}, Landroidx/collection/u;->h()I

    .line 145
    .line 146
    .line 147
    move-result v2

    .line 148
    move v5, v4

    .line 149
    :goto_4
    if-ge v5, v2, :cond_7

    .line 150
    .line 151
    invoke-virtual {v6, v5}, Landroidx/collection/u;->i(I)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v7

    .line 155
    check-cast v7, Lp3/t;

    .line 156
    .line 157
    invoke-static {v7, v3}, Lp3/s;->h(Lp3/t;Z)J

    .line 158
    .line 159
    .line 160
    move-result-wide v8

    .line 161
    const-wide/16 v10, 0x0

    .line 162
    .line 163
    invoke-static {v8, v9, v10, v11}, Ld3/b;->c(JJ)Z

    .line 164
    .line 165
    .line 166
    move-result v8

    .line 167
    if-nez v8, :cond_9

    .line 168
    .line 169
    invoke-virtual {v7}, Lp3/t;->b()Z

    .line 170
    .line 171
    .line 172
    move-result v7

    .line 173
    if-eqz v7, :cond_9

    .line 174
    .line 175
    move v2, v3

    .line 176
    goto :goto_5

    .line 177
    :cond_9
    add-int/lit8 v5, v5, 0x1

    .line 178
    .line 179
    goto :goto_4

    .line 180
    :goto_5
    invoke-virtual {v6}, Landroidx/collection/u;->h()I

    .line 181
    .line 182
    .line 183
    move-result v5

    .line 184
    move v7, v4

    .line 185
    :goto_6
    if-ge v7, v5, :cond_b

    .line 186
    .line 187
    invoke-virtual {v6, v7}, Landroidx/collection/u;->i(I)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v8

    .line 191
    check-cast v8, Lp3/t;

    .line 192
    .line 193
    invoke-virtual {v8}, Lp3/t;->b()Z

    .line 194
    .line 195
    .line 196
    move-result v8
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 197
    if-eqz v8, :cond_a

    .line 198
    .line 199
    move v5, v3

    .line 200
    goto :goto_7

    .line 201
    :cond_a
    add-int/lit8 v7, v7, 0x1

    .line 202
    .line 203
    goto :goto_6

    .line 204
    :cond_b
    move v5, v4

    .line 205
    :goto_7
    shl-int/2addr v2, v3

    .line 206
    or-int/2addr v0, v2

    .line 207
    shl-int/lit8 v2, v5, 0x2

    .line 208
    .line 209
    or-int/2addr v0, v2

    .line 210
    iput-boolean v4, v1, Lvv0/d;->a:Z

    .line 211
    .line 212
    return v0

    .line 213
    :goto_8
    iput-boolean v4, v1, Lvv0/d;->a:Z

    .line 214
    .line 215
    throw v0
.end method

.method public j()Z
    .locals 6

    .line 1
    iget-object v0, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljp/vg;

    .line 4
    .line 5
    iget-object v1, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Landroid/content/Context;

    .line 8
    .line 9
    iget-object v2, p0, Lvv0/d;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Ljp/c;

    .line 12
    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    goto/16 :goto_2

    .line 16
    .line 17
    :cond_0
    :try_start_0
    sget-object v2, Lzo/d;->b:Lrb0/a;

    .line 18
    .line 19
    const-string v3, "com.google.android.gms.vision.dynamite"

    .line 20
    .line 21
    invoke-static {v1, v2, v3}, Lzo/d;->c(Landroid/content/Context;Lzo/c;Ljava/lang/String;)Lzo/d;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    const-string v3, "com.google.android.gms.vision.barcode.ChimeraNativeBarcodeDetectorCreator"

    .line 26
    .line 27
    invoke-virtual {v2, v3}, Lzo/d;->b(Ljava/lang/String;)Landroid/os/IBinder;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    sget v3, Ljp/e;->d:I

    .line 32
    .line 33
    const-string v3, "com.google.android.gms.vision.barcode.internal.client.INativeBarcodeDetectorCreator"

    .line 34
    .line 35
    if-nez v2, :cond_1

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    goto :goto_0

    .line 39
    :cond_1
    invoke-interface {v2, v3}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    instance-of v5, v4, Ljp/f;

    .line 44
    .line 45
    if-eqz v5, :cond_2

    .line 46
    .line 47
    move-object v2, v4

    .line 48
    check-cast v2, Ljp/f;

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    new-instance v4, Ljp/d;

    .line 52
    .line 53
    const/4 v5, 0x6

    .line 54
    invoke-direct {v4, v2, v3, v5}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 55
    .line 56
    .line 57
    move-object v2, v4

    .line 58
    :goto_0
    new-instance v3, Lyo/b;

    .line 59
    .line 60
    invoke-direct {v3, v1}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget-object v4, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v4, Ljp/b;

    .line 66
    .line 67
    check-cast v2, Ljp/d;

    .line 68
    .line 69
    invoke-virtual {v2, v3, v4}, Ljp/d;->W(Lyo/b;Ljp/b;)Ljp/c;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    iput-object v2, p0, Lvv0/d;->e:Ljava/lang/Object;

    .line 74
    .line 75
    if-nez v2, :cond_4

    .line 76
    .line 77
    iget-boolean v2, p0, Lvv0/d;->a:Z

    .line 78
    .line 79
    if-eqz v2, :cond_3

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    const-string v2, "LegacyBarcodeScanner"

    .line 83
    .line 84
    const-string v3, "Request optional module download."

    .line 85
    .line 86
    invoke-static {v2, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 87
    .line 88
    .line 89
    const-string v2, "barcode"

    .line 90
    .line 91
    sget-object v3, Lfv/h;->a:[Ljo/d;

    .line 92
    .line 93
    sget-object v3, Lip/d;->e:Lip/b;

    .line 94
    .line 95
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    const/4 v3, 0x1

    .line 100
    invoke-static {v3, v2}, Llp/ta;->a(I[Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    new-instance v4, Lip/g;

    .line 104
    .line 105
    invoke-direct {v4, v2, v3}, Lip/g;-><init>([Ljava/lang/Object;I)V

    .line 106
    .line 107
    .line 108
    invoke-static {v1, v4}, Lfv/h;->a(Landroid/content/Context;Ljava/util/List;)V

    .line 109
    .line 110
    .line 111
    iput-boolean v3, p0, Lvv0/d;->a:Z

    .line 112
    .line 113
    sget-object p0, Ljp/ac;->g:Ljp/ac;

    .line 114
    .line 115
    invoke-static {v0, p0}, Llv/a;->b(Ljp/vg;Ljp/ac;)V

    .line 116
    .line 117
    .line 118
    new-instance p0, Lbv/a;

    .line 119
    .line 120
    const-string v0, "Waiting for the barcode module to be downloaded. Please wait."

    .line 121
    .line 122
    const/16 v1, 0xe

    .line 123
    .line 124
    invoke-direct {p0, v0, v1}, Lbv/a;-><init>(Ljava/lang/String;I)V

    .line 125
    .line 126
    .line 127
    throw p0

    .line 128
    :cond_4
    :goto_1
    sget-object p0, Ljp/ac;->e:Ljp/ac;

    .line 129
    .line 130
    invoke-static {v0, p0}, Llv/a;->b(Ljp/vg;Ljp/ac;)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Lzo/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 131
    .line 132
    .line 133
    :goto_2
    const/4 p0, 0x0

    .line 134
    return p0

    .line 135
    :catch_0
    move-exception p0

    .line 136
    new-instance v0, Lbv/a;

    .line 137
    .line 138
    const-string v1, "Failed to load deprecated vision dynamite module."

    .line 139
    .line 140
    invoke-direct {v0, v1, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 141
    .line 142
    .line 143
    throw v0

    .line 144
    :catch_1
    move-exception p0

    .line 145
    new-instance v0, Lbv/a;

    .line 146
    .line 147
    const-string v1, "Failed to create legacy barcode detector."

    .line 148
    .line 149
    invoke-direct {v0, v1, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 150
    .line 151
    .line 152
    throw v0
.end method

.method public declared-synchronized k()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lvv0/d;->a:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-void

    .line 8
    :cond_0
    const/4 v0, 0x1

    .line 9
    :try_start_1
    iput-boolean v0, p0, Lvv0/d;->a:Z

    .line 10
    .line 11
    iget-object v0, p0, Lvv0/d;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Landroid/content/Context;

    .line 14
    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    iget-object v1, p0, Lvv0/d;->c:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lsm/a;

    .line 20
    .line 21
    invoke-virtual {v1, v0}, Lsm/a;->b(Landroid/content/Context;)V

    .line 22
    .line 23
    .line 24
    iget-object v1, p0, Lvv0/d;->d:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Le3/c;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Landroid/content/Context;->unregisterComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catchall_0
    move-exception v0

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    :goto_0
    iget-object v0, p0, Lvv0/d;->b:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, Ljava/lang/ref/WeakReference;

    .line 37
    .line 38
    invoke-virtual {v0}, Ljava/lang/ref/Reference;->clear()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 39
    .line 40
    .line 41
    monitor-exit p0

    .line 42
    return-void

    .line 43
    :goto_1
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 44
    throw v0
.end method

.method public l()V
    .locals 3

    .line 1
    iget-object v0, p0, Lvv0/d;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljp/c;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    :try_start_0
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    const/4 v2, 0x3

    .line 12
    invoke-virtual {v0, v1, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catch_0
    move-exception v0

    .line 17
    const-string v1, "LegacyBarcodeScanner"

    .line 18
    .line 19
    const-string v2, "Failed to release legacy barcode detector."

    .line 20
    .line 21
    invoke-static {v1, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 22
    .line 23
    .line 24
    :goto_0
    const/4 v0, 0x0

    .line 25
    iput-object v0, p0, Lvv0/d;->e:Ljava/lang/Object;

    .line 26
    .line 27
    :cond_0
    return-void
.end method
