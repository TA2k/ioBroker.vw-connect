.class public final Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyTypeKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0005\n\u0002\u0008\u0003\"\u0018\u0010\u0000\u001a\u00020\u0001*\u00020\u00028@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0003\u0010\u0004\u00a8\u0006\u0005"
    }
    d2 = {
        "encryptionKeyType",
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;",
        "",
        "getEncryptionKeyType",
        "(B)Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final getEncryptionKeyType(B)Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;
    .locals 4

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;->getEntries()Lsx0/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/16 v1, 0xa

    .line 6
    .line 7
    invoke-static {v0, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-static {v1}, Lmx0/x;->k(I)I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const/16 v2, 0x10

    .line 16
    .line 17
    if-ge v1, v2, :cond_0

    .line 18
    .line 19
    move v1, v2

    .line 20
    :cond_0
    new-instance v2, Ljava/util/LinkedHashMap;

    .line 21
    .line 22
    invoke-direct {v2, v1}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    move-object v3, v1

    .line 40
    check-cast v3, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 41
    .line 42
    invoke-virtual {v3}, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;->getCgxEncryptionKeyType$genx_release()B

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    invoke-interface {v2, v3, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    sget-object v0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;->VKMS:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 59
    .line 60
    invoke-interface {v2, p0, v0}, Ljava/util/Map;->getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 65
    .line 66
    return-object p0
.end method
