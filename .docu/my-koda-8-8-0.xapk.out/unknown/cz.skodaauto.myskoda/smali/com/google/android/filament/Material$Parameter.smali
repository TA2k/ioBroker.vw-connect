.class public Lcom/google/android/filament/Material$Parameter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/google/android/filament/proguard/UsedByNative;
    value = "Material.cpp"
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Material;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Parameter"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Material$Parameter$Type;,
        Lcom/google/android/filament/Material$Parameter$Precision;
    }
.end annotation


# static fields
.field private static final SAMPLER_OFFSET:I
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "Material.cpp"
    .end annotation
.end field

.field private static final SUBPASS_OFFSET:I
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "Material.cpp"
    .end annotation
.end field

.field private static final sTypeValues:[Lcom/google/android/filament/Material$Parameter$Type;


# instance fields
.field public final count:I

.field public final name:Ljava/lang/String;

.field public final precision:Lcom/google/android/filament/Material$Parameter$Precision;

.field public final type:Lcom/google/android/filament/Material$Parameter$Type;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/Material$Parameter$Type;->values()[Lcom/google/android/filament/Material$Parameter$Type;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/Material$Parameter;->sTypeValues:[Lcom/google/android/filament/Material$Parameter$Type;

    .line 6
    .line 7
    sget-object v0, Lcom/google/android/filament/Material$Parameter$Type;->MAT4:Lcom/google/android/filament/Material$Parameter$Type;

    .line 8
    .line 9
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    add-int/lit8 v0, v0, 0x1

    .line 14
    .line 15
    sput v0, Lcom/google/android/filament/Material$Parameter;->SAMPLER_OFFSET:I

    .line 16
    .line 17
    sget-object v0, Lcom/google/android/filament/Material$Parameter$Type;->SAMPLER_3D:Lcom/google/android/filament/Material$Parameter$Type;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    add-int/lit8 v0, v0, 0x1

    .line 24
    .line 25
    sput v0, Lcom/google/android/filament/Material$Parameter;->SUBPASS_OFFSET:I

    .line 26
    .line 27
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;Lcom/google/android/filament/Material$Parameter$Type;Lcom/google/android/filament/Material$Parameter$Precision;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/filament/Material$Parameter;->name:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/filament/Material$Parameter;->type:Lcom/google/android/filament/Material$Parameter$Type;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/google/android/filament/Material$Parameter;->precision:Lcom/google/android/filament/Material$Parameter$Precision;

    .line 9
    .line 10
    iput p4, p0, Lcom/google/android/filament/Material$Parameter;->count:I

    .line 11
    .line 12
    return-void
.end method

.method private static add(Ljava/util/List;Ljava/lang/String;III)V
    .locals 2
    .annotation build Lcom/google/android/filament/proguard/UsedByNative;
        value = "Material.cpp"
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/google/android/filament/Material$Parameter;",
            ">;",
            "Ljava/lang/String;",
            "III)V"
        }
    .end annotation

    .line 1
    new-instance v0, Lcom/google/android/filament/Material$Parameter;

    .line 2
    .line 3
    sget-object v1, Lcom/google/android/filament/Material$Parameter;->sTypeValues:[Lcom/google/android/filament/Material$Parameter$Type;

    .line 4
    .line 5
    aget-object p2, v1, p2

    .line 6
    .line 7
    invoke-static {}, Lcom/google/android/filament/Material$Parameter$Precision;->values()[Lcom/google/android/filament/Material$Parameter$Precision;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    aget-object p3, v1, p3

    .line 12
    .line 13
    invoke-direct {v0, p1, p2, p3, p4}, Lcom/google/android/filament/Material$Parameter;-><init>(Ljava/lang/String;Lcom/google/android/filament/Material$Parameter$Type;Lcom/google/android/filament/Material$Parameter$Precision;I)V

    .line 14
    .line 15
    .line 16
    invoke-interface {p0, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    return-void
.end method
