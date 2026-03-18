.class public final synthetic Ltechnology/cariad/cat/genx/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

.field public final synthetic g:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

.field public final synthetic h:S

.field public final synthetic i:S

.field public final synthetic j:S


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltechnology/cariad/cat/genx/l0;->d:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 5
    .line 6
    iput-object p2, p0, Ltechnology/cariad/cat/genx/l0;->e:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Ltechnology/cariad/cat/genx/l0;->f:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 9
    .line 10
    iput-object p4, p0, Ltechnology/cariad/cat/genx/l0;->g:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 11
    .line 12
    iput-short p5, p0, Ltechnology/cariad/cat/genx/l0;->h:S

    .line 13
    .line 14
    iput-short p6, p0, Ltechnology/cariad/cat/genx/l0;->i:S

    .line 15
    .line 16
    iput-short p7, p0, Ltechnology/cariad/cat/genx/l0;->j:S

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 7

    .line 1
    iget-short v5, p0, Ltechnology/cariad/cat/genx/l0;->i:S

    .line 2
    .line 3
    iget-short v6, p0, Ltechnology/cariad/cat/genx/l0;->j:S

    .line 4
    .line 5
    iget-object v0, p0, Ltechnology/cariad/cat/genx/l0;->d:Ltechnology/cariad/cat/genx/VehicleManagerImpl;

    .line 6
    .line 7
    iget-object v1, p0, Ltechnology/cariad/cat/genx/l0;->e:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v2, p0, Ltechnology/cariad/cat/genx/l0;->f:Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;

    .line 10
    .line 11
    iget-object v3, p0, Ltechnology/cariad/cat/genx/l0;->g:Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;

    .line 12
    .line 13
    iget-short v4, p0, Ltechnology/cariad/cat/genx/l0;->h:S

    .line 14
    .line 15
    invoke-static/range {v0 .. v6}, Ltechnology/cariad/cat/genx/VehicleManagerImpl;->h(Ltechnology/cariad/cat/genx/VehicleManagerImpl;Ljava/lang/String;Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;SSS)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
