.class public final Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;
.super Ltechnology/cariad/cat/genx/crypto/CredentialStore;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000:\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0008\u0008\u0000\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\'\u0010\u000c\u001a\u00020\u000b2\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0008\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\tH\u0002\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u001f\u0010\u0015\u001a\u00020\u00122\u0006\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u0011\u001a\u00020\u0010H\u0010\u00a2\u0006\u0004\u0008\u0013\u0010\u0014J)\u0010\u0018\u001a\u0004\u0018\u00010\u000e2\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0008\u001a\u00020\u00062\u0006\u0010\u0011\u001a\u00020\u0010H\u0010\u00a2\u0006\u0004\u0008\u0016\u0010\u0017R\u0014\u0010\u0003\u001a\u00020\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0003\u0010\u0019\u00a8\u0006\u001a"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;",
        "Ltechnology/cariad/cat/genx/crypto/CredentialStore;",
        "Lu51/g;",
        "secureStorage",
        "<init>",
        "(Lu51/g;)V",
        "",
        "localIdentifier",
        "remoteIdentifier",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
        "",
        "uniqueKey",
        "([B[BLtechnology/cariad/cat/genx/TransportType;)Ljava/lang/String;",
        "Ltechnology/cariad/cat/genx/crypto/SessionCredentials;",
        "sessionCredentialsEntry",
        "",
        "cgxTransportType",
        "",
        "storeSessionCredentials$genx_release",
        "(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;B)I",
        "storeSessionCredentials",
        "retrieveSessionCredentials$genx_release",
        "([B[BB)Ltechnology/cariad/cat/genx/crypto/SessionCredentials;",
        "retrieveSessionCredentials",
        "Lu51/g;",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final secureStorage:Lu51/g;


# direct methods
.method public constructor <init>(Lu51/g;)V
    .locals 1

    .line 1
    const-string v0, "secureStorage"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/crypto/CredentialStore;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->secureStorage:Lu51/g;

    .line 10
    .line 11
    return-void
.end method

.method public static synthetic a(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->retrieveSessionCredentials$lambda$0(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final synthetic access$getSecureStorage$p(Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;)Lu51/g;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->secureStorage:Lu51/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic b([B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->retrieveSessionCredentials$lambda$1([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final retrieveSessionCredentials$lambda$0(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "retrieveSessionCredentials(): retrieve "

    .line 2
    .line 3
    invoke-static {v0, p0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static final retrieveSessionCredentials$lambda$1([B)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "retrieveSessionCredentials(): Failed to retrieve session credentials for localIdentifier = "

    .line 6
    .line 7
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private final uniqueKey([B[BLtechnology/cariad/cat/genx/TransportType;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p1}, Lly0/d;->l([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p2}, Lly0/d;->l([B)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p2

    .line 13
    new-instance p3, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    invoke-direct {p3}, Ljava/lang/StringBuilder;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string p0, "_"

    .line 22
    .line 23
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method


# virtual methods
.method public bridge synthetic retrieveSessionCredentials([B[BB)Ltechnology/cariad/cat/genx/crypto/SessionCredentials;
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->retrieveSessionCredentials$genx_release([B[BB)Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public retrieveSessionCredentials$genx_release([B[BB)Ltechnology/cariad/cat/genx/crypto/SessionCredentials;
    .locals 10

    .line 1
    const-string v0, "localIdentifier"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "remoteIdentifier"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p3}, Ltechnology/cariad/cat/genx/TransportTypeKt;->getTransportType(B)Ltechnology/cariad/cat/genx/TransportType;

    .line 12
    .line 13
    .line 14
    move-result-object p3

    .line 15
    invoke-direct {p0, p1, p2, p3}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->uniqueKey([B[BLtechnology/cariad/cat/genx/TransportType;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p2

    .line 19
    new-instance v3, Ltechnology/cariad/cat/genx/crypto/b;

    .line 20
    .line 21
    const/4 p3, 0x1

    .line 22
    invoke-direct {v3, p2, p3}, Ltechnology/cariad/cat/genx/crypto/b;-><init>(Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    new-instance v0, Lt51/j;

    .line 26
    .line 27
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    const-string p3, "getName(...)"

    .line 32
    .line 33
    invoke-static {p3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v6

    .line 37
    const-string v1, "GenX"

    .line 38
    .line 39
    sget-object v2, Lt51/d;->a:Lt51/d;

    .line 40
    .line 41
    const/4 v4, 0x0

    .line 42
    invoke-direct/range {v0 .. v6}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-static {v0}, Lt51/a;->a(Lt51/j;)V

    .line 46
    .line 47
    .line 48
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 49
    .line 50
    sget-object v0, Lcz0/d;->e:Lcz0/d;

    .line 51
    .line 52
    new-instance v1, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$result$1;

    .line 53
    .line 54
    const/4 v2, 0x0

    .line 55
    invoke-direct {v1, p0, p2, v2}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$result$1;-><init>(Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 56
    .line 57
    .line 58
    invoke-static {v0, v1}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    check-cast v1, Llx0/o;

    .line 63
    .line 64
    iget-object v1, v1, Llx0/o;->d:Ljava/lang/Object;

    .line 65
    .line 66
    instance-of v3, v1, Llx0/n;

    .line 67
    .line 68
    if-nez v3, :cond_1

    .line 69
    .line 70
    if-eqz v3, :cond_0

    .line 71
    .line 72
    move-object v1, v2

    .line 73
    :cond_0
    check-cast v1, Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_1
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 77
    .line 78
    .line 79
    move-result-object v7

    .line 80
    instance-of v1, v7, Lu51/d;

    .line 81
    .line 82
    if-nez v1, :cond_2

    .line 83
    .line 84
    new-instance v6, Ltechnology/cariad/cat/genx/crypto/b;

    .line 85
    .line 86
    const/4 v1, 0x2

    .line 87
    invoke-direct {v6, p1, v1}, Ltechnology/cariad/cat/genx/crypto/b;-><init>(Ljava/lang/Object;I)V

    .line 88
    .line 89
    .line 90
    new-instance v3, Lt51/j;

    .line 91
    .line 92
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v8

    .line 96
    invoke-static {p3}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v9

    .line 100
    const-string v4, "GenX"

    .line 101
    .line 102
    sget-object v5, Lt51/e;->a:Lt51/e;

    .line 103
    .line 104
    invoke-direct/range {v3 .. v9}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    invoke-static {v3}, Lt51/a;->a(Lt51/j;)V

    .line 108
    .line 109
    .line 110
    :cond_2
    move-object v1, v2

    .line 111
    :goto_0
    if-eqz v1, :cond_3

    .line 112
    .line 113
    new-instance p1, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;

    .line 114
    .line 115
    invoke-direct {p1, p0, p2, v2}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$retrieveSessionCredentials$2;-><init>(Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 116
    .line 117
    .line 118
    invoke-static {v0, p1}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    :cond_3
    return-object v1
.end method

.method public bridge synthetic storeSessionCredentials(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;B)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->storeSessionCredentials$genx_release(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;B)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public storeSessionCredentials$genx_release(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;B)I
    .locals 3

    .line 1
    const-string v0, "sessionCredentialsEntry"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p2}, Ltechnology/cariad/cat/genx/TransportTypeKt;->getTransportType(B)Ltechnology/cariad/cat/genx/TransportType;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/crypto/SessionCredentials;->getLocalIdentifier()[B

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/crypto/SessionCredentials;->getRemoteIdentifier()[B

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-direct {p0, v0, v1, p2}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;->uniqueKey([B[BLtechnology/cariad/cat/genx/TransportType;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p2

    .line 22
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 23
    .line 24
    sget-object v0, Lcz0/d;->e:Lcz0/d;

    .line 25
    .line 26
    new-instance v1, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    invoke-direct {v1, p0, p2, p1, v2}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;-><init>(Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/SessionCredentials;Lkotlin/coroutines/Continuation;)V

    .line 30
    .line 31
    .line 32
    invoke-static {v0, v1}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Ljava/lang/Number;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    return p0
.end method
