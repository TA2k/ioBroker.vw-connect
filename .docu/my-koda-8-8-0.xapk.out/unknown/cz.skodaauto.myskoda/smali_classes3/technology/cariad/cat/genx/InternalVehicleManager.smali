.class public interface abstract Ltechnology/cariad/cat/genx/InternalVehicleManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/VehicleManager;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000^\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0005\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0004\n\u0002\u0010\u0012\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\n\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008`\u0018\u0000 ,2\u00020\u0001:\u0001,J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H&\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\u001f\u0010\u000b\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\tH&\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ%\u0010\u0012\u001a\u0004\u0018\u00010\t2\n\u0010\u000f\u001a\u00060\rj\u0002`\u000e2\u0006\u0010\u0011\u001a\u00020\u0010H&\u00a2\u0006\u0004\u0008\u0012\u0010\u0013JU\u0010\u001e\u001a\u0004\u0018\u00010\t2\n\u0010\u000f\u001a\u00060\rj\u0002`\u000e2\u0006\u0010\u0014\u001a\u00020\u00022\u0006\u0010\u0016\u001a\u00020\u00152\u0006\u0010\u0018\u001a\u00020\u00172\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u001a\u001a\u00020\u00192\u0006\u0010\u001b\u001a\u00020\u00192\u0006\u0010\u001d\u001a\u00020\u001cH&\u00a2\u0006\u0004\u0008\u001e\u0010\u001fJ#\u0010 \u001a\u00020\u00062\n\u0010\u000f\u001a\u00060\rj\u0002`\u000e2\u0006\u0010\n\u001a\u00020\tH&\u00a2\u0006\u0004\u0008 \u0010!J)\u0010$\u001a\u0004\u0018\u00010\u00152\u0006\u0010\u0014\u001a\u00020\u00022\u0006\u0010\"\u001a\u00020\u00152\u0006\u0010#\u001a\u00020\u0015H&\u00a2\u0006\u0004\u0008$\u0010%J)\u0010&\u001a\u0004\u0018\u00010\u00152\u0006\u0010\u0014\u001a\u00020\u00022\u0006\u0010\"\u001a\u00020\u00152\u0006\u0010#\u001a\u00020\u0015H&\u00a2\u0006\u0004\u0008&\u0010%R\u001a\u0010+\u001a\u0008\u0012\u0004\u0012\u00020(0\'8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008)\u0010*\u00a8\u0006-\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/InternalVehicleManager;",
        "Ltechnology/cariad/cat/genx/VehicleManager;",
        "",
        "cgxTransportType",
        "",
        "isEnabled",
        "Llx0/b0;",
        "onStateUpdated",
        "(BZ)V",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "error",
        "onEncounteredError",
        "(BLtechnology/cariad/cat/genx/GenXError;)V",
        "",
        "Ltechnology/cariad/cat/genx/VIN;",
        "vin",
        "",
        "cgxAntenna",
        "onKeyExchangeSucceeded",
        "(Ljava/lang/String;I)Ltechnology/cariad/cat/genx/GenXError;",
        "encryptionKeyType",
        "",
        "uuid",
        "Ltechnology/cariad/cat/genx/crypto/RemoteCredentials;",
        "remoteCredentials",
        "",
        "beaconMinor",
        "beaconMajor",
        "Ltechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;",
        "localKeyPair",
        "onEncryptedKeyExchangeSucceeded",
        "(Ljava/lang/String;B[BLtechnology/cariad/cat/genx/crypto/RemoteCredentials;ISSLtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/GenXError;",
        "onKeyExchangeFailed",
        "(Ljava/lang/String;Ltechnology/cariad/cat/genx/GenXError;)V",
        "message",
        "initializationVector",
        "onEncryptMessage",
        "(B[B[B)[B",
        "onDecryptMessage",
        "",
        "Ltechnology/cariad/cat/genx/ClientManager;",
        "getClientManager",
        "()Ljava/util/List;",
        "clientManager",
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
.field public static final Companion:Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;->$$INSTANCE:Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;

    .line 2
    .line 3
    sput-object v0, Ltechnology/cariad/cat/genx/InternalVehicleManager;->Companion:Ltechnology/cariad/cat/genx/InternalVehicleManager$Companion;

    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public abstract getClientManager()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ltechnology/cariad/cat/genx/ClientManager;",
            ">;"
        }
    .end annotation
.end method

.method public abstract onDecryptMessage(B[B[B)[B
.end method

.method public abstract onEncounteredError(BLtechnology/cariad/cat/genx/GenXError;)V
.end method

.method public abstract onEncryptMessage(B[B[B)[B
.end method

.method public abstract onEncryptedKeyExchangeSucceeded(Ljava/lang/String;B[BLtechnology/cariad/cat/genx/crypto/RemoteCredentials;ISSLtechnology/cariad/cat/genx/crypto/EdDSASigning$KeyPair;)Ltechnology/cariad/cat/genx/GenXError;
.end method

.method public abstract onKeyExchangeFailed(Ljava/lang/String;Ltechnology/cariad/cat/genx/GenXError;)V
.end method

.method public abstract onKeyExchangeSucceeded(Ljava/lang/String;I)Ltechnology/cariad/cat/genx/GenXError;
.end method

.method public abstract onStateUpdated(BZ)V
.end method
