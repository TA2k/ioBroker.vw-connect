.class public interface abstract Ltechnology/cariad/cat/genx/ClientDelegate;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0006\u0008`\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H\'\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\'\u00a2\u0006\u0004\u0008\u0005\u0010\u0004J\'\u0010\u000c\u001a\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\u00082\u0006\u0010\u000b\u001a\u00020\nH\'\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0017\u0010\u0010\u001a\u00020\u00022\u0006\u0010\u000f\u001a\u00020\u000eH\'\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u000f\u0010\u0012\u001a\u00020\u0008H\'\u00a2\u0006\u0004\u0008\u0012\u0010\u0013\u00a8\u0006\u0014\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/ClientDelegate;",
        "Ljava/io/Closeable;",
        "Llx0/b0;",
        "onClientConnected",
        "()V",
        "onClientDisconnected",
        "Ltechnology/cariad/cat/genx/Channel;",
        "channel",
        "",
        "success",
        "",
        "message",
        "onClientDiscoveredChannel",
        "(Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)V",
        "Ltechnology/cariad/cat/genx/TypedFrame;",
        "typedFrame",
        "onClientReceivedTypedFrame",
        "(Ltechnology/cariad/cat/genx/TypedFrame;)V",
        "shouldClientBeRemovedAfterAdvertisementStopped",
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
.method public abstract onClientConnected()V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public abstract onClientDisconnected()V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public abstract onClientDiscoveredChannel(Ltechnology/cariad/cat/genx/Channel;ZLjava/lang/String;)V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public abstract onClientReceivedTypedFrame(Ltechnology/cariad/cat/genx/TypedFrame;)V
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method

.method public abstract shouldClientBeRemovedAfterAdvertisementStopped()Z
    .annotation build Ltechnology/cariad/cat/genx/RequiresGenXDispatch;
    .end annotation
.end method
