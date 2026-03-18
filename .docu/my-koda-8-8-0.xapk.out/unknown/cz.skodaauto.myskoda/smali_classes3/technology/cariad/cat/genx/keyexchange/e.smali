.class public final synthetic Ltechnology/cariad/cat/genx/keyexchange/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

.field public final synthetic f:Ltechnology/cariad/cat/genx/QRCode;

.field public final synthetic g:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;I)V
    .locals 0

    .line 1
    iput p4, p0, Ltechnology/cariad/cat/genx/keyexchange/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/keyexchange/e;->e:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 4
    .line 5
    iput-object p2, p0, Ltechnology/cariad/cat/genx/keyexchange/e;->f:Ltechnology/cariad/cat/genx/QRCode;

    .line 6
    .line 7
    iput-object p3, p0, Ltechnology/cariad/cat/genx/keyexchange/e;->g:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/keyexchange/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/keyexchange/e;->f:Ltechnology/cariad/cat/genx/QRCode;

    .line 7
    .line 8
    iget-object v1, p0, Ltechnology/cariad/cat/genx/keyexchange/e;->g:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 9
    .line 10
    iget-object p0, p0, Ltechnology/cariad/cat/genx/keyexchange/e;->e:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 11
    .line 12
    invoke-static {p0, v0, v1}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->l0(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Llx0/b0;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/keyexchange/e;->f:Ltechnology/cariad/cat/genx/QRCode;

    .line 18
    .line 19
    iget-object v1, p0, Ltechnology/cariad/cat/genx/keyexchange/e;->g:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 20
    .line 21
    iget-object p0, p0, Ltechnology/cariad/cat/genx/keyexchange/e;->e:Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;

    .line 22
    .line 23
    invoke-static {p0, v0, v1}, Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;->V(Ltechnology/cariad/cat/genx/keyexchange/KeyExchangeManager;Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Llx0/b0;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
