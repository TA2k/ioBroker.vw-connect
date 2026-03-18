.class public abstract Ltechnology/cariad/cat/genx/protocol/AddressDirection;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/protocol/AddressDirection$Companion;,
        Ltechnology/cariad/cat/genx/protocol/AddressDirection$Other;,
        Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;,
        Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00006\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u00086\u0018\u0000 \u00132\u00020\u0001:\u0004\u0014\u0015\u0016\u0013B\u0011\u0008\u0004\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\u001a\u0010\u0008\u001a\u00020\u00072\u0008\u0010\u0006\u001a\u0004\u0018\u00010\u0001H\u0096\u0002\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u000f\u0010\u000e\u001a\u00020\rH\u0016\u00a2\u0006\u0004\u0008\u000e\u0010\u000fR\u001a\u0010\u0003\u001a\u00020\u00028\u0000X\u0080\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u0010\u001a\u0004\u0008\u0011\u0010\u0012\u0082\u0001\u0003\u0017\u0018\u0019\u00a8\u0006\u001a"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/protocol/AddressDirection;",
        "",
        "Llx0/s;",
        "rawValue",
        "<init>",
        "(B)V",
        "other",
        "",
        "equals",
        "(Ljava/lang/Object;)Z",
        "",
        "hashCode",
        "()I",
        "",
        "toString",
        "()Ljava/lang/String;",
        "B",
        "getRawValue-w2LRezQ$genx_release",
        "()B",
        "Companion",
        "PhoneToVehicle",
        "VehicleToPhone",
        "Other",
        "Ltechnology/cariad/cat/genx/protocol/AddressDirection$Other;",
        "Ltechnology/cariad/cat/genx/protocol/AddressDirection$PhoneToVehicle;",
        "Ltechnology/cariad/cat/genx/protocol/AddressDirection$VehicleToPhone;",
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
.field public static final Companion:Ltechnology/cariad/cat/genx/protocol/AddressDirection$Companion;


# instance fields
.field private final rawValue:B


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/AddressDirection$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/protocol/AddressDirection$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/genx/protocol/AddressDirection;->Companion:Ltechnology/cariad/cat/genx/protocol/AddressDirection$Companion;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(B)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-byte p1, p0, Ltechnology/cariad/cat/genx/protocol/AddressDirection;->rawValue:B

    return-void
.end method

.method public synthetic constructor <init>(BLkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/genx/protocol/AddressDirection;-><init>(B)V

    return-void
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/genx/protocol/AddressDirection;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    iget-byte p0, p0, Ltechnology/cariad/cat/genx/protocol/AddressDirection;->rawValue:B

    .line 12
    .line 13
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/AddressDirection;

    .line 14
    .line 15
    iget-byte p1, p1, Ltechnology/cariad/cat/genx/protocol/AddressDirection;->rawValue:B

    .line 16
    .line 17
    if-eq p0, p1, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    return v0
.end method

.method public final getRawValue-w2LRezQ$genx_release()B
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/genx/protocol/AddressDirection;->rawValue:B

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-byte p0, p0, Ltechnology/cariad/cat/genx/protocol/AddressDirection;->rawValue:B

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Byte;->hashCode(B)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-byte p0, p0, Ltechnology/cariad/cat/genx/protocol/AddressDirection;->rawValue:B

    .line 10
    .line 11
    invoke-static {p0}, Llx0/s;->a(B)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    const-string v1, "(rawValue="

    .line 16
    .line 17
    const-string v2, ")"

    .line 18
    .line 19
    invoke-static {v0, v1, p0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
