.class public interface abstract Ltechnology/cariad/cat/genx/wifi/WifiManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;,
        Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000:\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008`\u0018\u00002\u00020\u0001:\u0002\u0018\u0019J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u0007\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0007\u0010\u0006J\u0017\u0010\u0008\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0008\u0010\u0006J\u0017\u0010\n\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0017\u0010\u000c\u001a\u00020\t2\u0006\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u000c\u0010\u000bR\u001c\u0010\u0011\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u000e0\r8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000f\u0010\u0010R\u001a\u0010\u0014\u001a\u0008\u0012\u0004\u0012\u00020\u00120\r8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0013\u0010\u0010R\u001a\u0010\u0017\u001a\u0008\u0012\u0004\u0012\u00020\u00150\r8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0016\u0010\u0010\u00a8\u0006\u001a\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/WifiManager;",
        "",
        "Landroid/content/Context;",
        "context",
        "",
        "isWiFiEnabled",
        "(Landroid/content/Context;)Z",
        "isWiFiDirectSupported",
        "isWiFiSupported",
        "Llx0/b0;",
        "registerBroadcastReceiver",
        "(Landroid/content/Context;)V",
        "unregisterBroadcastReceiver",
        "Lyy0/a2;",
        "Ltechnology/cariad/cat/genx/wifi/Wifi;",
        "getConnectedWifi",
        "()Lyy0/a2;",
        "connectedWifi",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager$WifiState;",
        "getWifiState",
        "wifiState",
        "Ltechnology/cariad/cat/genx/wifi/WifiManager$AccessPointState;",
        "getAccessPointState",
        "accessPointState",
        "WifiState",
        "AccessPointState",
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
.method public abstract getAccessPointState()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getConnectedWifi()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract getWifiState()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract isWiFiDirectSupported(Landroid/content/Context;)Z
.end method

.method public abstract isWiFiEnabled(Landroid/content/Context;)Z
.end method

.method public abstract isWiFiSupported(Landroid/content/Context;)Z
.end method

.method public abstract registerBroadcastReceiver(Landroid/content/Context;)V
.end method

.method public abstract unregisterBroadcastReceiver(Landroid/content/Context;)V
.end method
