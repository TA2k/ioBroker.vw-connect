.class public interface abstract Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/KeyExchangeDelegate;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008g\u0018\u00002\u00020\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H&\u00a2\u0006\u0004\u0008\u0007\u0010\u0008\u00a8\u0006\t\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/EncryptedKeyExchangeDelegate;",
        "Ltechnology/cariad/cat/genx/KeyExchangeDelegate;",
        "Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;",
        "deviceType",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "error",
        "Llx0/b0;",
        "onEncryptedKeyExchangeFailed",
        "(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/GenXError;)V",
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

.annotation build Ltechnology/cariad/cat/genx/ExperimentalAPI;
.end annotation


# virtual methods
.method public abstract onEncryptedKeyExchangeFailed(Ltechnology/cariad/cat/genx/keyexchange/encryptedkeyexchange/DeviceType;Ltechnology/cariad/cat/genx/GenXError;)V
.end method
