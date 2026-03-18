.class public final Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;
.super Ltechnology/cariad/cat/genx/GenXError;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/GenXError;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "KeyExchangeClosedUnexpectedly"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0000\n\u0000\u0008\u00c6\u0002\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0008\u0010\u0004\u001a\u00020\u0005H\u0002\u00a8\u0006\u0006"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "<init>",
        "()V",
        "readResolve",
        "",
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
.field public static final INSTANCE:Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;

    .line 2
    .line 3
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/GenXError;-><init>(Lkotlin/jvm/internal/g;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method private final readResolve()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$KeyExchangeClosedUnexpectedly;

    .line 2
    .line 3
    return-object p0
.end method
