.class public final Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0013\u0010\u0008\u001a\u00020\u0005*\u00020\u0004H\u0000\u00a2\u0006\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\t"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;",
        "",
        "<init>",
        "()V",
        "Llx0/u;",
        "Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
        "asGlobalServiceID-WZ4Q5Ns$genx_release",
        "(I)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;",
        "asGlobalServiceID",
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
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final asGlobalServiceID-WZ4Q5Ns$genx_release(I)Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;
    .locals 3

    .line 1
    new-instance p0, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;

    .line 2
    .line 3
    ushr-int/lit8 v0, p1, 0x10

    .line 4
    .line 5
    int-to-byte v0, v0

    .line 6
    ushr-int/lit8 v1, p1, 0x8

    .line 7
    .line 8
    int-to-byte v1, v1

    .line 9
    int-to-byte p1, p1

    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-direct {p0, v0, v1, p1, v2}, Ltechnology/cariad/cat/genx/protocol/GlobalServiceID;-><init>(BBBLkotlin/jvm/internal/g;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method
