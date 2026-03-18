.class public interface abstract Ltechnology/cariad/cat/genx/ClientManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltechnology/cariad/cat/genx/Referencing;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000>\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\u000b\n\u0002\u0008\u0004\u0008`\u0018\u00002\u00020\u0001J\u0011\u0010\u0003\u001a\u0004\u0018\u00010\u0002H&\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J\u0011\u0010\u0005\u001a\u0004\u0018\u00010\u0002H&\u00a2\u0006\u0004\u0008\u0005\u0010\u0004J\u0017\u0010\t\u001a\u00020\u00082\u0006\u0010\u0007\u001a\u00020\u0006H&\u00a2\u0006\u0004\u0008\t\u0010\nR\u0014\u0010\u000e\u001a\u00020\u000b8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000c\u0010\rR\u0014\u0010\u0012\u001a\u00020\u000f8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0010\u0010\u0011R\u001e\u0010\u0018\u001a\u0004\u0018\u00010\u00138&@&X\u00a6\u000e\u00a2\u0006\u000c\u001a\u0004\u0008\u0014\u0010\u0015\"\u0004\u0008\u0016\u0010\u0017R\u0014\u0010\u001a\u001a\u00020\u00198&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001a\u0010\u001bR\u0014\u0010\u001c\u001a\u00020\u00198&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001c\u0010\u001b\u00a8\u0006\u001d\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/ClientManager;",
        "Ltechnology/cariad/cat/genx/Referencing;",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "startScanningForClients",
        "()Ltechnology/cariad/cat/genx/GenXError;",
        "stopScanningForClients",
        "",
        "identifier",
        "Llx0/b0;",
        "removeClient",
        "(Ljava/lang/String;)V",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "getTransportType",
        "()Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "getGenXDispatcher",
        "()Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "genXDispatcher",
        "Ltechnology/cariad/cat/genx/ClientManagerDelegate;",
        "getDelegate",
        "()Ltechnology/cariad/cat/genx/ClientManagerDelegate;",
        "setDelegate",
        "(Ltechnology/cariad/cat/genx/ClientManagerDelegate;)V",
        "delegate",
        "",
        "isEnabled",
        "()Z",
        "isScanningRequired",
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
.method public abstract getDelegate()Ltechnology/cariad/cat/genx/ClientManagerDelegate;
.end method

.method public abstract getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;
.end method

.method public abstract getTransportType()Ltechnology/cariad/cat/genx/TransportType;
.end method

.method public abstract isEnabled()Z
.end method

.method public abstract isScanningRequired()Z
.end method

.method public abstract removeClient(Ljava/lang/String;)V
.end method

.method public abstract setDelegate(Ltechnology/cariad/cat/genx/ClientManagerDelegate;)V
.end method

.method public abstract startScanningForClients()Ltechnology/cariad/cat/genx/GenXError;
.end method

.method public abstract stopScanningForClients()Ltechnology/cariad/cat/genx/GenXError;
.end method
