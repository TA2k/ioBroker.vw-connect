.class public final enum Lcom/google/android/filament/View$TargetBufferFlags;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "TargetBufferFlags"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/google/android/filament/View$TargetBufferFlags;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lcom/google/android/filament/View$TargetBufferFlags;

.field public static ALL:Ljava/util/EnumSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/EnumSet<",
            "Lcom/google/android/filament/View$TargetBufferFlags;",
            ">;"
        }
    .end annotation
.end field

.field public static ALL_COLOR:Ljava/util/EnumSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/EnumSet<",
            "Lcom/google/android/filament/View$TargetBufferFlags;",
            ">;"
        }
    .end annotation
.end field

.field public static final enum COLOR0:Lcom/google/android/filament/View$TargetBufferFlags;

.field public static final enum COLOR1:Lcom/google/android/filament/View$TargetBufferFlags;

.field public static final enum COLOR2:Lcom/google/android/filament/View$TargetBufferFlags;

.field public static final enum COLOR3:Lcom/google/android/filament/View$TargetBufferFlags;

.field public static final enum DEPTH:Lcom/google/android/filament/View$TargetBufferFlags;

.field public static DEPTH_STENCIL:Ljava/util/EnumSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/EnumSet<",
            "Lcom/google/android/filament/View$TargetBufferFlags;",
            ">;"
        }
    .end annotation
.end field

.field public static NONE:Ljava/util/EnumSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/EnumSet<",
            "Lcom/google/android/filament/View$TargetBufferFlags;",
            ">;"
        }
    .end annotation
.end field

.field public static final enum STENCIL:Lcom/google/android/filament/View$TargetBufferFlags;


# instance fields
.field private mFlags:I


# direct methods
.method private static synthetic $values()[Lcom/google/android/filament/View$TargetBufferFlags;
    .locals 6

    .line 1
    sget-object v0, Lcom/google/android/filament/View$TargetBufferFlags;->COLOR0:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 2
    .line 3
    sget-object v1, Lcom/google/android/filament/View$TargetBufferFlags;->COLOR1:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 4
    .line 5
    sget-object v2, Lcom/google/android/filament/View$TargetBufferFlags;->COLOR2:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 6
    .line 7
    sget-object v3, Lcom/google/android/filament/View$TargetBufferFlags;->COLOR3:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 8
    .line 9
    sget-object v4, Lcom/google/android/filament/View$TargetBufferFlags;->DEPTH:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 10
    .line 11
    sget-object v5, Lcom/google/android/filament/View$TargetBufferFlags;->STENCIL:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 12
    .line 13
    filled-new-array/range {v0 .. v5}, [Lcom/google/android/filament/View$TargetBufferFlags;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 9

    .line 1
    new-instance v0, Lcom/google/android/filament/View$TargetBufferFlags;

    .line 2
    .line 3
    const-string v1, "COLOR0"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    invoke-direct {v0, v1, v2, v3}, Lcom/google/android/filament/View$TargetBufferFlags;-><init>(Ljava/lang/String;II)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lcom/google/android/filament/View$TargetBufferFlags;->COLOR0:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 11
    .line 12
    new-instance v1, Lcom/google/android/filament/View$TargetBufferFlags;

    .line 13
    .line 14
    const-string v2, "COLOR1"

    .line 15
    .line 16
    const/4 v4, 0x2

    .line 17
    invoke-direct {v1, v2, v3, v4}, Lcom/google/android/filament/View$TargetBufferFlags;-><init>(Ljava/lang/String;II)V

    .line 18
    .line 19
    .line 20
    sput-object v1, Lcom/google/android/filament/View$TargetBufferFlags;->COLOR1:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 21
    .line 22
    new-instance v2, Lcom/google/android/filament/View$TargetBufferFlags;

    .line 23
    .line 24
    const-string v3, "COLOR2"

    .line 25
    .line 26
    const/4 v5, 0x4

    .line 27
    invoke-direct {v2, v3, v4, v5}, Lcom/google/android/filament/View$TargetBufferFlags;-><init>(Ljava/lang/String;II)V

    .line 28
    .line 29
    .line 30
    sput-object v2, Lcom/google/android/filament/View$TargetBufferFlags;->COLOR2:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 31
    .line 32
    new-instance v3, Lcom/google/android/filament/View$TargetBufferFlags;

    .line 33
    .line 34
    const/4 v4, 0x3

    .line 35
    const/16 v6, 0x8

    .line 36
    .line 37
    const-string v7, "COLOR3"

    .line 38
    .line 39
    invoke-direct {v3, v7, v4, v6}, Lcom/google/android/filament/View$TargetBufferFlags;-><init>(Ljava/lang/String;II)V

    .line 40
    .line 41
    .line 42
    sput-object v3, Lcom/google/android/filament/View$TargetBufferFlags;->COLOR3:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 43
    .line 44
    new-instance v4, Lcom/google/android/filament/View$TargetBufferFlags;

    .line 45
    .line 46
    const-string v6, "DEPTH"

    .line 47
    .line 48
    const/16 v7, 0x10

    .line 49
    .line 50
    invoke-direct {v4, v6, v5, v7}, Lcom/google/android/filament/View$TargetBufferFlags;-><init>(Ljava/lang/String;II)V

    .line 51
    .line 52
    .line 53
    sput-object v4, Lcom/google/android/filament/View$TargetBufferFlags;->DEPTH:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 54
    .line 55
    new-instance v5, Lcom/google/android/filament/View$TargetBufferFlags;

    .line 56
    .line 57
    const/4 v6, 0x5

    .line 58
    const/16 v7, 0x20

    .line 59
    .line 60
    const-string v8, "STENCIL"

    .line 61
    .line 62
    invoke-direct {v5, v8, v6, v7}, Lcom/google/android/filament/View$TargetBufferFlags;-><init>(Ljava/lang/String;II)V

    .line 63
    .line 64
    .line 65
    sput-object v5, Lcom/google/android/filament/View$TargetBufferFlags;->STENCIL:Lcom/google/android/filament/View$TargetBufferFlags;

    .line 66
    .line 67
    invoke-static {}, Lcom/google/android/filament/View$TargetBufferFlags;->$values()[Lcom/google/android/filament/View$TargetBufferFlags;

    .line 68
    .line 69
    .line 70
    move-result-object v6

    .line 71
    sput-object v6, Lcom/google/android/filament/View$TargetBufferFlags;->$VALUES:[Lcom/google/android/filament/View$TargetBufferFlags;

    .line 72
    .line 73
    const-class v6, Lcom/google/android/filament/View$TargetBufferFlags;

    .line 74
    .line 75
    invoke-static {v6}, Ljava/util/EnumSet;->noneOf(Ljava/lang/Class;)Ljava/util/EnumSet;

    .line 76
    .line 77
    .line 78
    move-result-object v6

    .line 79
    sput-object v6, Lcom/google/android/filament/View$TargetBufferFlags;->NONE:Ljava/util/EnumSet;

    .line 80
    .line 81
    invoke-static {v0, v1, v2, v3}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 82
    .line 83
    .line 84
    move-result-object v1

    .line 85
    sput-object v1, Lcom/google/android/filament/View$TargetBufferFlags;->ALL_COLOR:Ljava/util/EnumSet;

    .line 86
    .line 87
    invoke-static {v4, v5}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    sput-object v1, Lcom/google/android/filament/View$TargetBufferFlags;->DEPTH_STENCIL:Ljava/util/EnumSet;

    .line 92
    .line 93
    invoke-static {v0, v5}, Ljava/util/EnumSet;->range(Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    sput-object v0, Lcom/google/android/filament/View$TargetBufferFlags;->ALL:Ljava/util/EnumSet;

    .line 98
    .line 99
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;II)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lcom/google/android/filament/View$TargetBufferFlags;->mFlags:I

    .line 5
    .line 6
    return-void
.end method

.method public static flags(Ljava/util/EnumSet;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/EnumSet<",
            "Lcom/google/android/filament/View$TargetBufferFlags;",
            ">;)I"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 v0, 0x0

    .line 6
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    check-cast v1, Lcom/google/android/filament/View$TargetBufferFlags;

    .line 17
    .line 18
    iget v1, v1, Lcom/google/android/filament/View$TargetBufferFlags;->mFlags:I

    .line 19
    .line 20
    or-int/2addr v0, v1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    return v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/google/android/filament/View$TargetBufferFlags;
    .locals 1

    .line 1
    const-class v0, Lcom/google/android/filament/View$TargetBufferFlags;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/google/android/filament/View$TargetBufferFlags;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/google/android/filament/View$TargetBufferFlags;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/View$TargetBufferFlags;->$VALUES:[Lcom/google/android/filament/View$TargetBufferFlags;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lcom/google/android/filament/View$TargetBufferFlags;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/google/android/filament/View$TargetBufferFlags;

    .line 8
    .line 9
    return-object v0
.end method
