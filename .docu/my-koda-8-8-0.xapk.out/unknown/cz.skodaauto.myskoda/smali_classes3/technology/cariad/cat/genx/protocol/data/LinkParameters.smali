.class public abstract Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$Companion;,
        Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;,
        Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00008\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u00087\u0018\u0000 \u00112\u00020\u0001:\u0003\u0012\u0013\u0011B\t\u0008\u0004\u00a2\u0006\u0004\u0008\u0002\u0010\u0003B\u001b\u0008\u0016\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0008\u0010\u0007\u001a\u0004\u0018\u00010\u0006\u00a2\u0006\u0004\u0008\u0002\u0010\u0008J\'\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\t\u001a\u00020\u00002\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\r\u001a\u00020\u000cH\u0007\u00a2\u0006\u0004\u0008\u000f\u0010\u0010\u0082\u0001\u0002\u0014\u0015\u00a8\u0006\u0016"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;",
        "",
        "<init>",
        "()V",
        "",
        "seen0",
        "Luz0/l1;",
        "serializationConstructorMarker",
        "(ILuz0/l1;)V",
        "self",
        "Ltz0/b;",
        "output",
        "Lsz0/g;",
        "serialDesc",
        "Llx0/b0;",
        "write$Self",
        "(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;Ltz0/b;Lsz0/g;)V",
        "Companion",
        "RequestValues",
        "ResponseValues",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;",
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

.annotation runtime Lqz0/g;
.end annotation


# static fields
.field private static final $cachedSerializer$delegate:Llx0/i;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llx0/i;"
        }
    .end annotation
.end field

.field public static final Companion:Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$Companion;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;->Companion:Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$Companion;

    .line 8
    .line 9
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 10
    .line 11
    new-instance v1, Lmz0/b;

    .line 12
    .line 13
    const/4 v2, 0x5

    .line 14
    invoke-direct {v1, v2}, Lmz0/b;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sput-object v0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;->$cachedSerializer$delegate:Llx0/i;

    .line 22
    .line 23
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ILuz0/l1;)V
    .locals 0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;-><init>()V

    return-void
.end method

.method private static final _init_$_anonymous_()Lqz0/a;
    .locals 7

    .line 1
    new-instance v0, Lqz0/f;

    .line 2
    .line 3
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 4
    .line 5
    const-class v2, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;

    .line 6
    .line 7
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    const-class v3, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 12
    .line 13
    invoke-virtual {v1, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    const-class v4, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;

    .line 18
    .line 19
    invoke-virtual {v1, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const/4 v4, 0x2

    .line 24
    move-object v5, v3

    .line 25
    new-array v3, v4, [Lhy0/d;

    .line 26
    .line 27
    const/4 v6, 0x0

    .line 28
    aput-object v5, v3, v6

    .line 29
    .line 30
    const/4 v5, 0x1

    .line 31
    aput-object v1, v3, v5

    .line 32
    .line 33
    new-array v4, v4, [Lqz0/a;

    .line 34
    .line 35
    sget-object v1, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues$$serializer;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues$$serializer;

    .line 36
    .line 37
    aput-object v1, v4, v6

    .line 38
    .line 39
    sget-object v1, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues$$serializer;->INSTANCE:Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues$$serializer;

    .line 40
    .line 41
    aput-object v1, v4, v5

    .line 42
    .line 43
    new-array v5, v6, [Ljava/lang/annotation/Annotation;

    .line 44
    .line 45
    const-string v1, "technology.cariad.cat.genx.protocol.data.LinkParameters"

    .line 46
    .line 47
    invoke-direct/range {v0 .. v5}, Lqz0/f;-><init>(Ljava/lang/String;Lhy0/d;[Lhy0/d;[Lqz0/a;[Ljava/lang/annotation/Annotation;)V

    .line 48
    .line 49
    .line 50
    return-object v0
.end method

.method public static synthetic a()Lqz0/a;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;->_init_$_anonymous_()Lqz0/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static final synthetic access$get$cachedSerializer$delegate$cp()Llx0/i;
    .locals 1

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;->$cachedSerializer$delegate:Llx0/i;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic write$Self(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters;Ltz0/b;Lsz0/g;)V
    .locals 0

    .line 1
    return-void
.end method
