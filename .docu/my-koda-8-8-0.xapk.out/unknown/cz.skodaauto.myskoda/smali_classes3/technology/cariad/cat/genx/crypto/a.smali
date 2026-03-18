.class public final synthetic Ltechnology/cariad/cat/genx/crypto/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/io/Serializable;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/io/Serializable;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltechnology/cariad/cat/genx/crypto/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltechnology/cariad/cat/genx/crypto/a;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Ltechnology/cariad/cat/genx/crypto/a;->f:Ljava/io/Serializable;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ltechnology/cariad/cat/genx/crypto/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/genx/crypto/a;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, [B

    .line 9
    .line 10
    iget-object p0, p0, Ltechnology/cariad/cat/genx/crypto/a;->f:Ljava/io/Serializable;

    .line 11
    .line 12
    check-cast p0, [B

    .line 13
    .line 14
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair$Companion;->d([B[B)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    iget-object v0, p0, Ltechnology/cariad/cat/genx/crypto/a;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v0, Ltechnology/cariad/cat/genx/crypto/SessionCredentials;

    .line 26
    .line 27
    iget-object p0, p0, Ltechnology/cariad/cat/genx/crypto/a;->f:Ljava/io/Serializable;

    .line 28
    .line 29
    check-cast p0, Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {v0, p0}, Ltechnology/cariad/cat/genx/crypto/CredentialStoreWithSecureStorage$storeSessionCredentials$1;->b(Ltechnology/cariad/cat/genx/crypto/SessionCredentials;Ljava/lang/String;)Ljava/lang/String;

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
