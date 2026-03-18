.class public interface abstract Ltechnology/cariad/cat/genx/GenXDispatcher;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/GenXDispatcher$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\t\n\u0002\u0008\u0006\u0008`\u0018\u0000 \u000c2\u00020\u0001:\u0001\u000cJ\u001d\u0010\u0005\u001a\u00020\u00032\u000c\u0010\u0004\u001a\u0008\u0012\u0004\u0012\u00020\u00030\u0002H&\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\'\u0010\u0005\u001a\u00020\u00032\u0006\u0010\u0008\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\u00072\u0006\u0010\n\u001a\u00020\u0007H&\u00a2\u0006\u0004\u0008\u0005\u0010\u000b\u00a8\u0006\r\u00c0\u0006\u0003"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/GenXDispatcher;",
        "Ljava/io/Closeable;",
        "Lkotlin/Function0;",
        "Llx0/b0;",
        "function",
        "dispatch",
        "(Lay0/a;)V",
        "",
        "nativeFunc",
        "delayMs",
        "context",
        "(JJJ)V",
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
.field public static final Companion:Ltechnology/cariad/cat/genx/GenXDispatcher$Companion;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/GenXDispatcher$Companion;->$$INSTANCE:Ltechnology/cariad/cat/genx/GenXDispatcher$Companion;

    .line 2
    .line 3
    sput-object v0, Ltechnology/cariad/cat/genx/GenXDispatcher;->Companion:Ltechnology/cariad/cat/genx/GenXDispatcher$Companion;

    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public abstract dispatch(JJJ)V
.end method

.method public abstract dispatch(Lay0/a;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/a;",
            ")V"
        }
    .end annotation
.end method
