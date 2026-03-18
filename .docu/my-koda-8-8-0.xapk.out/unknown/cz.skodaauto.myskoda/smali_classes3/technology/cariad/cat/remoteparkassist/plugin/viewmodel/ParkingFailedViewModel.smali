.class public interface abstract Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx61/a;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\u0002\u0008f\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0003\u0010\u0004R\u001a\u0010\t\u001a\u0008\u0012\u0004\u0012\u00020\u00060\u00058&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0007\u0010\u0008R\u001a\u0010\u000b\u001a\u0008\u0012\u0004\u0012\u00020\n0\u00058&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000b\u0010\u0008\u00a8\u0006\u000c\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFailedViewModel;",
        "Lx61/a;",
        "Llx0/b0;",
        "reconnect",
        "()V",
        "Lyy0/a2;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;",
        "getError",
        "()Lyy0/a2;",
        "error",
        "",
        "isReconnectEnabled",
        "remoteparkassistplugin_release"
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
.method public abstract synthetic closeRPAModule()V
.end method

.method public abstract getError()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract synthetic isClosable()Lyy0/a2;
.end method

.method public abstract isReconnectEnabled()Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation
.end method

.method public abstract reconnect()V
.end method
