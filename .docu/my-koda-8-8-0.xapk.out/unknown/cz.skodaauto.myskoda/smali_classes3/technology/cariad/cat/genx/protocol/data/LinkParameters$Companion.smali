.class public final Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0013\u0010\u0006\u001a\u0008\u0012\u0004\u0012\u00020\u00050\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\u0008"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$Companion;",
        "",
        "<init>",
        "()V",
        "Lqz0/a;",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;",
        "serializer",
        "()Lqz0/a;",
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
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$Companion;-><init>()V

    return-void
.end method

.method private final synthetic get$cachedSerializer()Lqz0/a;
    .locals 0

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;->access$get$cachedSerializer$delegate$cp()Llx0/i;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lqz0/a;

    .line 10
    .line 11
    return-object p0
.end method


# virtual methods
.method public final serializer()Lqz0/a;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lqz0/a;"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$Companion;->get$cachedSerializer()Lqz0/a;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
