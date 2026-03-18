.class public final Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0011\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0086\u0002\u00a8\u0006\u0008"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;",
        "",
        "<init>",
        "()V",
        "invoke",
        "Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;",
        "context",
        "Landroid/content/Context;",
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
.field static final synthetic $$INSTANCE:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;

    .line 2
    .line 3
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;->$$INSTANCE:Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final invoke(Landroid/content/Context;)Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade;
    .locals 0

    .line 1
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1;

    .line 7
    .line 8
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/wifi/NSDManagerFacade$Companion$invoke$1;-><init>(Landroid/content/Context;)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method
