.class public interface abstract Ltechnology/cariad/cat/genx/VehicleManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/ScanningManager;
.implements Ljava/io/Closeable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/VehicleManager$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0080\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0005\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\t\u0008f\u0018\u0000 ?2\u00020\u00012\u00020\u0002:\u0001?J\u000f\u0010\u0004\u001a\u00020\u0003H&\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u0017\u0010\t\u001a\u00020\u00082\u0006\u0010\u0007\u001a\u00020\u0006H&\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0017\u0010\u000b\u001a\u00020\u00082\u0006\u0010\u0007\u001a\u00020\u0006H&\u00a2\u0006\u0004\u0008\u000b\u0010\nJ\u000f\u0010\u000c\u001a\u00020\u0008H&\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u001d\u0010\u0012\u001a\u0004\u0018\u00010\u00112\n\u0010\u0010\u001a\u00060\u000ej\u0002`\u000fH&\u00a2\u0006\u0004\u0008\u0012\u0010\u0013J$\u0010\u001a\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u00172\u000c\u0010\u0016\u001a\u0008\u0012\u0004\u0012\u00020\u00150\u0014H\u00a6@\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J\u001e\u0010\u001d\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u00172\u0006\u0010\u0010\u001a\u00020\u000eH\u00a6@\u00a2\u0006\u0004\u0008\u001b\u0010\u001cJ\u0016\u0010 \u001a\u0008\u0012\u0004\u0012\u00020\u00030\u0017H\u00a6@\u00a2\u0006\u0004\u0008\u001e\u0010\u001fJ\u001f\u0010%\u001a\u00020\u00032\u0006\u0010\"\u001a\u00020!2\u0006\u0010$\u001a\u00020#H&\u00a2\u0006\u0004\u0008%\u0010&J\u0016\u0010(\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u0017H\u00a6@\u00a2\u0006\u0004\u0008\'\u0010\u001fJ/\u00100\u001a\u00020\u00032\u0006\u0010*\u001a\u00020)2\u0006\u0010$\u001a\u00020+2\u0006\u0010-\u001a\u00020,2\u0006\u0010/\u001a\u00020.H\'\u00a2\u0006\u0004\u00080\u00101R\u001a\u00106\u001a\u0008\u0012\u0004\u0012\u000203028&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00084\u00105R \u0010:\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u00060\u0014078&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u00088\u00109R\u0014\u0010;\u001a\u00020\u00088&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008;\u0010\rR\u001a\u0010<\u001a\u0008\u0012\u0004\u0012\u00020\u0008078&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008<\u00109R\u001a\u0010=\u001a\u0008\u0012\u0004\u0012\u00020\u0008078&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008=\u00109R\u001a\u0010>\u001a\u0008\u0012\u0004\u0012\u00020\u0008078&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008>\u00109\u00a8\u0006@\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/VehicleManager;",
        "Ltechnology/cariad/cat/genx/ScanningManager;",
        "Ljava/io/Closeable;",
        "Llx0/b0;",
        "close",
        "()V",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
        "",
        "isTransportEnabled",
        "(Ltechnology/cariad/cat/genx/TransportType;)Z",
        "isTransportSupported",
        "isLocationPermissionGranted",
        "()Z",
        "",
        "Ltechnology/cariad/cat/genx/VIN;",
        "vin",
        "Ltechnology/cariad/cat/genx/Vehicle;",
        "vehicle",
        "(Ljava/lang/String;)Ltechnology/cariad/cat/genx/Vehicle;",
        "",
        "Ltechnology/cariad/cat/genx/Vehicle$Information;",
        "vehicleInformation",
        "Llx0/o;",
        "registerVehicles-gIAlu-s",
        "(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "registerVehicles",
        "unregisterVehicle-gIAlu-s",
        "(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "unregisterVehicle",
        "unregisterAllVehicles-IoAF18A",
        "(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;",
        "unregisterAllVehicles",
        "Ltechnology/cariad/cat/genx/QRCode;",
        "qrCode",
        "Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;",
        "delegate",
        "startKeyExchange",
        "(Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;)V",
        "cancelKeyExchange-IoAF18A",
        "cancelKeyExchange",
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;",
        "deviceType",
        "Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;",
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;",
        "keyExchangeEncryptionCredentials",
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;",
        "encryptionKeyType",
        "startEncryptedKeyExchange",
        "(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;)V",
        "Lyy0/i;",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "getVehicleErrors",
        "()Lyy0/i;",
        "vehicleErrors",
        "Lyy0/a2;",
        "getEnabledTransportTypes",
        "()Lyy0/a2;",
        "enabledTransportTypes",
        "isAnyVehicleRegistered",
        "isBleEnabled",
        "isWifiEnabled",
        "isLocationEnabled",
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
.field public static final ACTION_BEACON_IN_RANGE:Ljava/lang/String; = "technology.cariad.cat.genx.action.BEACON_IN_RANGE"

.field public static final ACTION_BEACON_OUT_OF_RANGE:Ljava/lang/String; = "technology.cariad.cat.genx.action.BEACON_OUT_OF_RANGE"

.field public static final Companion:Ltechnology/cariad/cat/genx/VehicleManager$Companion;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/VehicleManager$Companion;->$$INSTANCE:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

    .line 2
    .line 3
    sput-object v0, Ltechnology/cariad/cat/genx/VehicleManager;->Companion:Ltechnology/cariad/cat/genx/VehicleManager$Companion;

    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public abstract cancelKeyExchange-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation
.end method

.method public abstract close()V
.end method

.method public abstract getEnabledTransportTypes()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getVehicleErrors()Lyy0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/i;"
        }
    .end annotation
.end method

.method public abstract isAnyVehicleRegistered()Z
.end method

.method public abstract isBleEnabled()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isLocationEnabled()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isLocationPermissionGranted()Z
.end method

.method public abstract isTransportEnabled(Ltechnology/cariad/cat/genx/TransportType;)Z
.end method

.method public abstract isTransportSupported(Ltechnology/cariad/cat/genx/TransportType;)Z
.end method

.method public abstract isWifiEnabled()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract registerVehicles-gIAlu-s(Ljava/util/List;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ltechnology/cariad/cat/genx/Vehicle$Information;",
            ">;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation
.end method

.method public abstract startEncryptedKeyExchange(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/KeyExchangeEncryptionCredentials;Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/EncryptionKeyType;)V
    .annotation build Ltechnology/cariad/cat/genx/ExperimentalAPI;
    .end annotation
.end method

.method public abstract startKeyExchange(Ltechnology/cariad/cat/genx/QRCode;Ltechnology/cariad/cat/genx/QRKeyExchangeDelegate;)V
.end method

.method public abstract unregisterAllVehicles-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation
.end method

.method public abstract unregisterVehicle-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Lkotlin/coroutines/Continuation<",
            "-",
            "Llx0/o;",
            ">;)",
            "Ljava/lang/Object;"
        }
    .end annotation
.end method

.method public abstract vehicle(Ljava/lang/String;)Ltechnology/cariad/cat/genx/Vehicle;
.end method
