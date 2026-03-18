.class public abstract Lq51/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lw51/b;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lw51/b;

    .line 2
    .line 3
    const-string v1, "Keychain"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lw51/b;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lq51/r;->a:Lw51/b;

    .line 9
    .line 10
    return-void
.end method

.method public static final a()Lkp/r8;
    .locals 3

    .line 1
    const-string v0, "AndroidKeyStore"

    .line 2
    .line 3
    :try_start_0
    invoke-static {v0}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x0

    .line 8
    invoke-virtual {v0, v1}, Ljava/security/KeyStore;->load(Ljava/security/KeyStore$LoadStoreParameter;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lg91/b;

    .line 12
    .line 13
    invoke-direct {v1, v0}, Lg91/b;-><init>(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :catch_0
    move-exception v0

    .line 18
    new-instance v1, Lg91/a;

    .line 19
    .line 20
    new-instance v2, Lq51/m;

    .line 21
    .line 22
    invoke-static {v0}, Lkp/y5;->e(Ljava/lang/Exception;)Le91/b;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-direct {v2, v0}, Lq51/p;-><init>(Le91/b;)V

    .line 27
    .line 28
    .line 29
    invoke-direct {v1, v2}, Lg91/a;-><init>(Lq51/p;)V

    .line 30
    .line 31
    .line 32
    :goto_0
    instance-of v0, v1, Lg91/b;

    .line 33
    .line 34
    if-eqz v0, :cond_0

    .line 35
    .line 36
    new-instance v0, Lg91/b;

    .line 37
    .line 38
    new-instance v2, Lq51/b;

    .line 39
    .line 40
    check-cast v1, Lg91/b;

    .line 41
    .line 42
    iget-object v1, v1, Lg91/b;->a:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v1, Ljava/security/KeyStore;

    .line 45
    .line 46
    invoke-direct {v2, v1}, Lq51/b;-><init>(Ljava/security/KeyStore;)V

    .line 47
    .line 48
    .line 49
    invoke-direct {v0, v2}, Lg91/b;-><init>(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_0
    instance-of v0, v1, Lg91/a;

    .line 54
    .line 55
    if-eqz v0, :cond_1

    .line 56
    .line 57
    check-cast v1, Lg91/a;

    .line 58
    .line 59
    new-instance v0, Lg91/a;

    .line 60
    .line 61
    iget-object v1, v1, Lg91/a;->a:Lq51/p;

    .line 62
    .line 63
    invoke-direct {v0, v1}, Lg91/a;-><init>(Lq51/p;)V

    .line 64
    .line 65
    .line 66
    :goto_1
    return-object v0

    .line 67
    :cond_1
    new-instance v0, La8/r0;

    .line 68
    .line 69
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 70
    .line 71
    .line 72
    throw v0
.end method

.method public static final b(Ljava/lang/String;Ljava/lang/String;Lq51/e;)Lq51/d;
    .locals 4

    .line 1
    const-string v0, "directory"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "key"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "_always"

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    :try_start_0
    instance-of v2, p2, Lq51/e;

    .line 15
    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {v0}, Lf91/b;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    goto :goto_1

    .line 27
    :catch_0
    move-exception v0

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-instance v0, La8/r0;

    .line 30
    .line 31
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 32
    .line 33
    .line 34
    throw v0
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 35
    :goto_0
    new-instance v2, Lo51/c;

    .line 36
    .line 37
    const/16 v3, 0xb

    .line 38
    .line 39
    invoke-direct {v2, v3, p1, p2}, Lo51/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    sget-object p1, Lw51/c;->a:Lw51/b;

    .line 43
    .line 44
    sget-object p1, Lw51/e;->f:Lw51/e;

    .line 45
    .line 46
    const-class p2, Lw51/c;

    .line 47
    .line 48
    invoke-virtual {p2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    invoke-static {p2, p1}, Lw51/c;->c(Ljava/lang/String;Lw51/e;)Lw51/a;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    const/16 p2, 0x9

    .line 57
    .line 58
    invoke-static {v1, p1, v0, v2, p2}, Lw51/c;->b(Lw51/b;Lw51/a;Ljava/lang/Exception;Lay0/a;I)V

    .line 59
    .line 60
    .line 61
    move-object p1, v1

    .line 62
    :goto_1
    if-eqz p1, :cond_1

    .line 63
    .line 64
    new-instance v1, Lq51/d;

    .line 65
    .line 66
    const-string p2, "/"

    .line 67
    .line 68
    invoke-static {p0, p2, p1}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    invoke-direct {v1, p0}, Lq51/d;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    :cond_1
    return-object v1
.end method

.method public static final c(Lq51/e;)V
    .locals 0

    .line 1
    instance-of p0, p0, Lq51/e;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, La8/r0;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0
.end method

.method public static final d(Ljava/lang/String;Ljava/security/KeyStore;)Lkp/r8;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "alias"

    .line 7
    .line 8
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    :try_start_0
    new-instance v0, Lg91/b;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-virtual {p1, p0, v1}, Ljava/security/KeyStore;->getEntry(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    instance-of p1, p0, Ljava/security/KeyStore$SecretKeyEntry;

    .line 19
    .line 20
    if-eqz p1, :cond_0

    .line 21
    .line 22
    check-cast p0, Ljava/security/KeyStore$SecretKeyEntry;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    move-object p0, v1

    .line 26
    :goto_0
    if-eqz p0, :cond_1

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/security/KeyStore$SecretKeyEntry;->getSecretKey()Ljavax/crypto/SecretKey;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    :cond_1
    invoke-direct {v0, v1}, Lg91/b;-><init>(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 33
    .line 34
    .line 35
    return-object v0

    .line 36
    :catch_0
    move-exception p0

    .line 37
    instance-of p1, p0, Ljava/security/UnrecoverableEntryException;

    .line 38
    .line 39
    if-eqz p1, :cond_2

    .line 40
    .line 41
    new-instance p1, Lg91/a;

    .line 42
    .line 43
    new-instance v0, Lq51/k;

    .line 44
    .line 45
    check-cast p0, Ljava/security/UnrecoverableEntryException;

    .line 46
    .line 47
    invoke-direct {v0, p0}, Lq51/k;-><init>(Ljava/security/UnrecoverableEntryException;)V

    .line 48
    .line 49
    .line 50
    invoke-direct {p1, v0}, Lg91/a;-><init>(Lq51/p;)V

    .line 51
    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_2
    new-instance p1, Lg91/a;

    .line 55
    .line 56
    new-instance v0, Lq51/m;

    .line 57
    .line 58
    invoke-static {p0}, Lkp/y5;->e(Ljava/lang/Exception;)Le91/b;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    invoke-direct {v0, p0}, Lq51/p;-><init>(Le91/b;)V

    .line 63
    .line 64
    .line 65
    invoke-direct {p1, v0}, Lg91/a;-><init>(Lq51/p;)V

    .line 66
    .line 67
    .line 68
    :goto_1
    return-object p1
.end method

.method public static final e(Landroid/content/Context;)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "/KeychainObjectsAPI"

    .line 10
    .line 11
    invoke-static {p0, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const-string v0, "23"

    .line 16
    .line 17
    invoke-static {p0, v0}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method
