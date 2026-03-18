.class public interface abstract Ltechnology/cariad/cat/genx/Client;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/Client$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000V\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0008`\u0018\u0000 )2\u00020\u0001:\u0001)J\u000f\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0005\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0006\u0010\u0004J\u0017\u0010\t\u001a\u00020\u00022\u0006\u0010\u0008\u001a\u00020\u0007H&\u00a2\u0006\u0004\u0008\t\u0010\nJ\u0019\u0010\u000e\u001a\u0004\u0018\u00010\r2\u0006\u0010\u000c\u001a\u00020\u000bH&\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ\u000f\u0010\u0011\u001a\u00020\u0010H&\u00a2\u0006\u0004\u0008\u0011\u0010\u0012R\u0014\u0010\u0016\u001a\u00020\u00138&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0014\u0010\u0015R\u001e\u0010\u001c\u001a\u0004\u0018\u00010\u00178&@&X\u00a6\u000e\u00a2\u0006\u000c\u001a\u0004\u0008\u0018\u0010\u0019\"\u0004\u0008\u001a\u0010\u001bR\u0014\u0010 \u001a\u00020\u001d8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u001e\u0010\u001fR\u0014\u0010$\u001a\u00020!8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\"\u0010#R\u0014\u0010(\u001a\u00020%8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008&\u0010\'\u00a8\u0006*\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/Client;",
        "Ljava/io/Closeable;",
        "Llx0/b0;",
        "connect",
        "()V",
        "disconnect",
        "remove",
        "Ltechnology/cariad/cat/genx/Channel;",
        "channel",
        "discoverChannel",
        "(Ltechnology/cariad/cat/genx/Channel;)V",
        "Ltechnology/cariad/cat/genx/TypedFrame;",
        "typedFrame",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "send",
        "(Ltechnology/cariad/cat/genx/TypedFrame;)Ltechnology/cariad/cat/genx/GenXError;",
        "",
        "maximumATTPayloadSize",
        "()I",
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "getGenXDispatcher",
        "()Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "genXDispatcher",
        "Ltechnology/cariad/cat/genx/ClientDelegate;",
        "getDelegate",
        "()Ltechnology/cariad/cat/genx/ClientDelegate;",
        "setDelegate",
        "(Ltechnology/cariad/cat/genx/ClientDelegate;)V",
        "delegate",
        "",
        "getIdentifier",
        "()Ljava/lang/String;",
        "identifier",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "getAntenna",
        "()Ltechnology/cariad/cat/genx/Antenna;",
        "antenna",
        "Ltechnology/cariad/cat/genx/TransportType;",
        "getTransportType",
        "()Ltechnology/cariad/cat/genx/TransportType;",
        "transportType",
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
.field public static final Companion:Ltechnology/cariad/cat/genx/Client$Companion;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/Client$Companion;->$$INSTANCE:Ltechnology/cariad/cat/genx/Client$Companion;

    .line 2
    .line 3
    sput-object v0, Ltechnology/cariad/cat/genx/Client;->Companion:Ltechnology/cariad/cat/genx/Client$Companion;

    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public abstract connect()V
.end method

.method public abstract disconnect()V
.end method

.method public abstract discoverChannel(Ltechnology/cariad/cat/genx/Channel;)V
.end method

.method public abstract getAntenna()Ltechnology/cariad/cat/genx/Antenna;
.end method

.method public abstract getDelegate()Ltechnology/cariad/cat/genx/ClientDelegate;
.end method

.method public abstract getGenXDispatcher()Ltechnology/cariad/cat/genx/GenXDispatcher;
.end method

.method public abstract getIdentifier()Ljava/lang/String;
.end method

.method public abstract getTransportType()Ltechnology/cariad/cat/genx/TransportType;
.end method

.method public abstract maximumATTPayloadSize()I
.end method

.method public abstract remove()V
.end method

.method public abstract send(Ltechnology/cariad/cat/genx/TypedFrame;)Ltechnology/cariad/cat/genx/GenXError;
.end method

.method public abstract setDelegate(Ltechnology/cariad/cat/genx/ClientDelegate;)V
.end method
