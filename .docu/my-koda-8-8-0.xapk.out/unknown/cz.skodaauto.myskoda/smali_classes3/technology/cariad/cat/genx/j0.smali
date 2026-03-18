.class public final synthetic Ltechnology/cariad/cat/genx/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Ltechnology/cariad/cat/genx/VehicleManagerImpl;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltechnology/cariad/cat/genx/j0;->d:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, [B

    .line 2
    .line 3
    check-cast p2, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 4
    .line 5
    check-cast p3, Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 6
    .line 7
    check-cast p4, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 8
    .line 9
    iget-object p0, p0, Ltechnology/cariad/cat/genx/j0;->d:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 10
    .line 11
    invoke-static {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->g1(Ltechnology/cariad/cat/genx/VehicleManagerImpl;[BLtechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/GenXError;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
