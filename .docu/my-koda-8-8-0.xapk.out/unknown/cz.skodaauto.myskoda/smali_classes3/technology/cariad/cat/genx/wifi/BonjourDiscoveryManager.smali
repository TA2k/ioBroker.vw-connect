.class public interface abstract Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\u0003\u0008`\u0018\u00002\u00020\u0001J\u0015\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u0002H&\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0003H&\u00a2\u0006\u0004\u0008\u0007\u0010\u0008R \u0010\u000e\u001a\u000e\u0012\n\u0012\u0008\u0012\u0004\u0012\u00020\u000b0\n0\t8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000c\u0010\rR\u0014\u0010\u0010\u001a\u00020\u000f8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0010\u0010\u0011\u00a8\u0006\u0012\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/BonjourDiscoveryManager;",
        "Ljava/io/Closeable;",
        "Llx0/o;",
        "Llx0/b0;",
        "startBonjourDiscovery-d1pmJ48",
        "()Ljava/lang/Object;",
        "startBonjourDiscovery",
        "stopBonjourDiscovery",
        "()V",
        "Lyy0/a2;",
        "",
        "Ltechnology/cariad/cat/genx/wifi/WifiClientInformation;",
        "getPotentialWifiClients",
        "()Lyy0/a2;",
        "potentialWifiClients",
        "",
        "isBonjourScanningActive",
        "()Z",
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


# virtual methods
.method public abstract getPotentialWifiClients()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isBonjourScanningActive()Z
.end method

.method public abstract startBonjourDiscovery-d1pmJ48()Ljava/lang/Object;
.end method

.method public abstract stopBonjourDiscovery()V
.end method
