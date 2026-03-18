.class public final Ltechnology/cariad/cat/genx/GenXError$VehicleAlreadyClosed;
.super Ltechnology/cariad/cat/genx/GenXError;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/GenXError;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "VehicleAlreadyClosed"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u00c6\n\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0008\u0010\u0004\u001a\u00020\u0005H\u0002J\u0013\u0010\u0006\u001a\u00020\u00072\u0008\u0010\u0008\u001a\u0004\u0018\u00010\u0005H\u00d6\u0003J\t\u0010\t\u001a\u00020\nH\u00d6\u0001J\t\u0010\u000b\u001a\u00020\u000cH\u00d6\u0001\u00a8\u0006\r"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/GenXError$VehicleAlreadyClosed;",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "<init>",
        "()V",
        "readResolve",
        "",
        "equals",
        "",
        "other",
        "hashCode",
        "",
        "toString",
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
.field public static final INSTANCE:Ltechnology/cariad/cat/genx/GenXError$VehicleAlreadyClosed;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/GenXError$VehicleAlreadyClosed;

    .line 2
    .line 3
    invoke-direct {v0}, Ltechnology/cariad/cat/genx/GenXError$VehicleAlreadyClosed;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ltechnology/cariad/cat/genx/GenXError$VehicleAlreadyClosed;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$VehicleAlreadyClosed;

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
    sget-object p0, Ltechnology/cariad/cat/genx/GenXError$VehicleAlreadyClosed;->INSTANCE:Ltechnology/cariad/cat/genx/GenXError$VehicleAlreadyClosed;

    .line 2
    .line 3
    return-object p0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of p0, p1, Ltechnology/cariad/cat/genx/GenXError$VehicleAlreadyClosed;

    .line 6
    .line 7
    if-nez p0, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_1
    return v0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    const p0, -0x45141dc0

    .line 2
    .line 3
    .line 4
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "VehicleAlreadyClosed"

    .line 2
    .line 3
    return-object p0
.end method
