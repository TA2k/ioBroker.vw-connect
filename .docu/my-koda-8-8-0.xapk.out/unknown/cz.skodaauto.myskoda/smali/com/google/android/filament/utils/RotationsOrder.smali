.class public final enum Lcom/google/android/filament/utils/RotationsOrder;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/google/android/filament/utils/RotationsOrder;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u000f\u0008\u0086\u0081\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00000\u0001B!\u0008\u0002\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003\u0012\u0006\u0010\u0005\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0006\u0010\u0007R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0008\u0010\tR\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\tR\u0011\u0010\u0005\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\tj\u0002\u0008\u000cj\u0002\u0008\rj\u0002\u0008\u000ej\u0002\u0008\u000fj\u0002\u0008\u0010j\u0002\u0008\u0011\u00a8\u0006\u0012"
    }
    d2 = {
        "Lcom/google/android/filament/utils/RotationsOrder;",
        "",
        "yaw",
        "Lcom/google/android/filament/utils/VectorComponent;",
        "pitch",
        "roll",
        "<init>",
        "(Ljava/lang/String;ILcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;)V",
        "getYaw",
        "()Lcom/google/android/filament/utils/VectorComponent;",
        "getPitch",
        "getRoll",
        "XYZ",
        "XZY",
        "YXZ",
        "YZX",
        "ZXY",
        "ZYX",
        "filament-utils-android_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field private static final synthetic $ENTRIES:Lsx0/a;

.field private static final synthetic $VALUES:[Lcom/google/android/filament/utils/RotationsOrder;

.field public static final enum XYZ:Lcom/google/android/filament/utils/RotationsOrder;

.field public static final enum XZY:Lcom/google/android/filament/utils/RotationsOrder;

.field public static final enum YXZ:Lcom/google/android/filament/utils/RotationsOrder;

.field public static final enum YZX:Lcom/google/android/filament/utils/RotationsOrder;

.field public static final enum ZXY:Lcom/google/android/filament/utils/RotationsOrder;

.field public static final enum ZYX:Lcom/google/android/filament/utils/RotationsOrder;


# instance fields
.field private final pitch:Lcom/google/android/filament/utils/VectorComponent;

.field private final roll:Lcom/google/android/filament/utils/VectorComponent;

.field private final yaw:Lcom/google/android/filament/utils/VectorComponent;


# direct methods
.method private static final synthetic $values()[Lcom/google/android/filament/utils/RotationsOrder;
    .locals 6

    .line 1
    sget-object v0, Lcom/google/android/filament/utils/RotationsOrder;->XYZ:Lcom/google/android/filament/utils/RotationsOrder;

    .line 2
    .line 3
    sget-object v1, Lcom/google/android/filament/utils/RotationsOrder;->XZY:Lcom/google/android/filament/utils/RotationsOrder;

    .line 4
    .line 5
    sget-object v2, Lcom/google/android/filament/utils/RotationsOrder;->YXZ:Lcom/google/android/filament/utils/RotationsOrder;

    .line 6
    .line 7
    sget-object v3, Lcom/google/android/filament/utils/RotationsOrder;->YZX:Lcom/google/android/filament/utils/RotationsOrder;

    .line 8
    .line 9
    sget-object v4, Lcom/google/android/filament/utils/RotationsOrder;->ZXY:Lcom/google/android/filament/utils/RotationsOrder;

    .line 10
    .line 11
    sget-object v5, Lcom/google/android/filament/utils/RotationsOrder;->ZYX:Lcom/google/android/filament/utils/RotationsOrder;

    .line 12
    .line 13
    filled-new-array/range {v0 .. v5}, [Lcom/google/android/filament/utils/RotationsOrder;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/RotationsOrder;

    .line 2
    .line 3
    sget-object v5, Lcom/google/android/filament/utils/VectorComponent;->X:Lcom/google/android/filament/utils/VectorComponent;

    .line 4
    .line 5
    sget-object v4, Lcom/google/android/filament/utils/VectorComponent;->Y:Lcom/google/android/filament/utils/VectorComponent;

    .line 6
    .line 7
    sget-object v6, Lcom/google/android/filament/utils/VectorComponent;->Z:Lcom/google/android/filament/utils/VectorComponent;

    .line 8
    .line 9
    const-string v1, "XYZ"

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    move-object v3, v5

    .line 13
    move-object v5, v6

    .line 14
    invoke-direct/range {v0 .. v5}, Lcom/google/android/filament/utils/RotationsOrder;-><init>(Ljava/lang/String;ILcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;)V

    .line 15
    .line 16
    .line 17
    move-object v5, v3

    .line 18
    sput-object v0, Lcom/google/android/filament/utils/RotationsOrder;->XYZ:Lcom/google/android/filament/utils/RotationsOrder;

    .line 19
    .line 20
    new-instance v1, Lcom/google/android/filament/utils/RotationsOrder;

    .line 21
    .line 22
    const-string v2, "XZY"

    .line 23
    .line 24
    const/4 v3, 0x1

    .line 25
    move-object v7, v6

    .line 26
    move-object v6, v4

    .line 27
    move-object v4, v5

    .line 28
    move-object v5, v7

    .line 29
    invoke-direct/range {v1 .. v6}, Lcom/google/android/filament/utils/RotationsOrder;-><init>(Ljava/lang/String;ILcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;)V

    .line 30
    .line 31
    .line 32
    move-object v5, v4

    .line 33
    move-object v4, v6

    .line 34
    move-object v6, v7

    .line 35
    sput-object v1, Lcom/google/android/filament/utils/RotationsOrder;->XZY:Lcom/google/android/filament/utils/RotationsOrder;

    .line 36
    .line 37
    new-instance v1, Lcom/google/android/filament/utils/RotationsOrder;

    .line 38
    .line 39
    const-string v2, "YXZ"

    .line 40
    .line 41
    const/4 v3, 0x2

    .line 42
    invoke-direct/range {v1 .. v6}, Lcom/google/android/filament/utils/RotationsOrder;-><init>(Ljava/lang/String;ILcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;)V

    .line 43
    .line 44
    .line 45
    sput-object v1, Lcom/google/android/filament/utils/RotationsOrder;->YXZ:Lcom/google/android/filament/utils/RotationsOrder;

    .line 46
    .line 47
    new-instance v1, Lcom/google/android/filament/utils/RotationsOrder;

    .line 48
    .line 49
    const-string v2, "YZX"

    .line 50
    .line 51
    const/4 v3, 0x3

    .line 52
    move-object v6, v5

    .line 53
    move-object v5, v7

    .line 54
    invoke-direct/range {v1 .. v6}, Lcom/google/android/filament/utils/RotationsOrder;-><init>(Ljava/lang/String;ILcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;)V

    .line 55
    .line 56
    .line 57
    move-object v7, v6

    .line 58
    move-object v6, v5

    .line 59
    move-object v5, v7

    .line 60
    sput-object v1, Lcom/google/android/filament/utils/RotationsOrder;->YZX:Lcom/google/android/filament/utils/RotationsOrder;

    .line 61
    .line 62
    new-instance v1, Lcom/google/android/filament/utils/RotationsOrder;

    .line 63
    .line 64
    const-string v2, "ZXY"

    .line 65
    .line 66
    const/4 v3, 0x4

    .line 67
    move-object v7, v6

    .line 68
    move-object v6, v4

    .line 69
    move-object v4, v7

    .line 70
    invoke-direct/range {v1 .. v6}, Lcom/google/android/filament/utils/RotationsOrder;-><init>(Ljava/lang/String;ILcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;)V

    .line 71
    .line 72
    .line 73
    move-object v7, v6

    .line 74
    move-object v6, v4

    .line 75
    move-object v4, v7

    .line 76
    sput-object v1, Lcom/google/android/filament/utils/RotationsOrder;->ZXY:Lcom/google/android/filament/utils/RotationsOrder;

    .line 77
    .line 78
    new-instance v1, Lcom/google/android/filament/utils/RotationsOrder;

    .line 79
    .line 80
    const-string v2, "ZYX"

    .line 81
    .line 82
    const/4 v3, 0x5

    .line 83
    move-object v7, v5

    .line 84
    move-object v5, v4

    .line 85
    move-object v4, v6

    .line 86
    move-object v6, v7

    .line 87
    invoke-direct/range {v1 .. v6}, Lcom/google/android/filament/utils/RotationsOrder;-><init>(Ljava/lang/String;ILcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;)V

    .line 88
    .line 89
    .line 90
    sput-object v1, Lcom/google/android/filament/utils/RotationsOrder;->ZYX:Lcom/google/android/filament/utils/RotationsOrder;

    .line 91
    .line 92
    invoke-static {}, Lcom/google/android/filament/utils/RotationsOrder;->$values()[Lcom/google/android/filament/utils/RotationsOrder;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    sput-object v0, Lcom/google/android/filament/utils/RotationsOrder;->$VALUES:[Lcom/google/android/filament/utils/RotationsOrder;

    .line 97
    .line 98
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    sput-object v0, Lcom/google/android/filament/utils/RotationsOrder;->$ENTRIES:Lsx0/a;

    .line 103
    .line 104
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;ILcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;Lcom/google/android/filament/utils/VectorComponent;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/google/android/filament/utils/VectorComponent;",
            "Lcom/google/android/filament/utils/VectorComponent;",
            "Lcom/google/android/filament/utils/VectorComponent;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lcom/google/android/filament/utils/RotationsOrder;->yaw:Lcom/google/android/filament/utils/VectorComponent;

    .line 5
    .line 6
    iput-object p4, p0, Lcom/google/android/filament/utils/RotationsOrder;->pitch:Lcom/google/android/filament/utils/VectorComponent;

    .line 7
    .line 8
    iput-object p5, p0, Lcom/google/android/filament/utils/RotationsOrder;->roll:Lcom/google/android/filament/utils/VectorComponent;

    .line 9
    .line 10
    return-void
.end method

.method public static getEntries()Lsx0/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lsx0/a;"
        }
    .end annotation

    .line 1
    sget-object v0, Lcom/google/android/filament/utils/RotationsOrder;->$ENTRIES:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/google/android/filament/utils/RotationsOrder;
    .locals 1

    .line 1
    const-class v0, Lcom/google/android/filament/utils/RotationsOrder;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/android/filament/utils/RotationsOrder;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/google/android/filament/utils/RotationsOrder;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/utils/RotationsOrder;->$VALUES:[Lcom/google/android/filament/utils/RotationsOrder;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/android/filament/utils/RotationsOrder;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final getPitch()Lcom/google/android/filament/utils/VectorComponent;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/RotationsOrder;->pitch:Lcom/google/android/filament/utils/VectorComponent;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRoll()Lcom/google/android/filament/utils/VectorComponent;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/RotationsOrder;->roll:Lcom/google/android/filament/utils/VectorComponent;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getYaw()Lcom/google/android/filament/utils/VectorComponent;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/RotationsOrder;->yaw:Lcom/google/android/filament/utils/VectorComponent;

    .line 2
    .line 3
    return-object p0
.end method
