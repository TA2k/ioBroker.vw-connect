.class public interface abstract Ltechnology/cariad/cat/genx/KeyExchangeInformation;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/KeyExchangeInformation$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0012\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0007\u0008f\u0018\u0000 \u001e2\u00020\u0001:\u0001\u001eR\u0014\u0010\u0005\u001a\u00020\u00028&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0003\u0010\u0004R\u0014\u0010\t\u001a\u00020\u00068&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0007\u0010\u0008R\u0014\u0010\r\u001a\u00020\n8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000b\u0010\u000cR\u0014\u0010\u0011\u001a\u00020\u000e8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000f\u0010\u0010R\u0014\u0010\u0015\u001a\u00020\u00128&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0013\u0010\u0014R\u0014\u0010\u0017\u001a\u00020\u00128&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0016\u0010\u0014R\u0014\u0010\u001b\u001a\u00020\u00188&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0019\u0010\u001aR\u0014\u0010\u001d\u001a\u00020\u00188&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001c\u0010\u001a\u00a8\u0006\u001f\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/KeyExchangeInformation;",
        "",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "getVehicleAntennaKeyPair",
        "()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "vehicleAntennaKeyPair",
        "",
        "getVin",
        "()Ljava/lang/String;",
        "vin",
        "Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;",
        "getVehicleAntennaIdentifier",
        "()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;",
        "vehicleAntennaIdentifier",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;",
        "getRemotePublicSigningKey",
        "()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;",
        "remotePublicSigningKey",
        "",
        "getLamSecret",
        "()[B",
        "lamSecret",
        "getAdvertisementSecret",
        "advertisementSecret",
        "Llx0/z;",
        "getMajor-Mh2AYeg",
        "()S",
        "major",
        "getMinor-Mh2AYeg",
        "minor",
        "Companion",
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


# static fields
.field public static final Companion:Ltechnology/cariad/cat/genx/KeyExchangeInformation$Companion;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/KeyExchangeInformation$Companion;->$$INSTANCE:Ltechnology/cariad/cat/genx/KeyExchangeInformation$Companion;

    .line 2
    .line 3
    sput-object v0, Ltechnology/cariad/cat/genx/KeyExchangeInformation;->Companion:Ltechnology/cariad/cat/genx/KeyExchangeInformation$Companion;

    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public abstract getAdvertisementSecret()[B
.end method

.method public abstract getLamSecret()[B
.end method

.method public abstract getMajor-Mh2AYeg()S
.end method

.method public abstract getMinor-Mh2AYeg()S
.end method

.method public abstract getRemotePublicSigningKey()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$PublicKey;
.end method

.method public abstract getVehicleAntennaIdentifier()Ltechnology/cariad/cat/genx/VehicleAntenna$Identifier;
.end method

.method public abstract getVehicleAntennaKeyPair()Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;
.end method

.method public abstract getVin()Ljava/lang/String;
.end method
