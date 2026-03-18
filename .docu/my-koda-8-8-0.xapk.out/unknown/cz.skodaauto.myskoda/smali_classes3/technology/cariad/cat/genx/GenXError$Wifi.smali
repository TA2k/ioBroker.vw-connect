.class public abstract Ltechnology/cariad/cat/genx/GenXError$Wifi;
.super Ltechnology/cariad/cat/genx/GenXError;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/GenXError;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x409
    name = "Wifi"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/GenXError$Wifi$BonjourFailed;,
        Ltechnology/cariad/cat/genx/GenXError$Wifi$Disabled;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u00086\u0018\u00002\u00020\u0001:\u0002\u0004\u0005B\t\u0008\u0004\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u0082\u0001\u0002\u0006\u0007\u00a8\u0006\u0008"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/GenXError$Wifi;",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "<init>",
        "()V",
        "BonjourFailed",
        "Disabled",
        "Ltechnology/cariad/cat/genx/GenXError$Wifi$BonjourFailed;",
        "Ltechnology/cariad/cat/genx/GenXError$Wifi$Disabled;",
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


# direct methods
.method private constructor <init>()V
    .locals 1

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/GenXError;-><init>(Lkotlin/jvm/internal/g;)V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/GenXError$Wifi;-><init>()V

    return-void
.end method
