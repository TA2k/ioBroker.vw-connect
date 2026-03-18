.class public final synthetic Ltechnology/cariad/cat/genx/keyexchange/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

.field public final synthetic f:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

.field public final synthetic g:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

.field public final synthetic h:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

.field public final synthetic i:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;I)V
    .locals 0

    .line 1
    iput p6, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->e:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 4
    .line 5
    iput-object p2, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->f:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 6
    .line 7
    iput-object p3, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->g:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 8
    .line 9
    iput-object p4, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->h:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 10
    .line 11
    iput-object p5, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->i:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->h:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 7
    .line 8
    iget-object v1, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->i:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 9
    .line 10
    iget-object v2, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->e:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 11
    .line 12
    iget-object v3, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->f:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 13
    .line 14
    iget-object p0, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->g:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 15
    .line 16
    invoke-static {v2, v3, p0, v0, v1}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->M(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Llx0/b0;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->h:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;

    .line 22
    .line 23
    iget-object v1, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->i:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 24
    .line 25
    iget-object v2, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->e:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 26
    .line 27
    iget-object v3, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->f:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;

    .line 28
    .line 29
    iget-object p0, p0, Ltechnology/cariad/cat/genx/keyexchange/c;->g:Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;

    .line 30
    .line 31
    invoke-static {v2, v3, p0, v0, v1}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->j0(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Llx0/b0;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
