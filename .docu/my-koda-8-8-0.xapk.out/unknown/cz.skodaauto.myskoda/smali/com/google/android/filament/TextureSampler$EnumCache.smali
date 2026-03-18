.class final Lcom/google/android/filament/TextureSampler$EnumCache;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/TextureSampler;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "EnumCache"
.end annotation


# static fields
.field static final sCompareFunctionValues:[Lcom/google/android/filament/TextureSampler$CompareFunction;

.field static final sCompareModeValues:[Lcom/google/android/filament/TextureSampler$CompareMode;

.field static final sMagFilterValues:[Lcom/google/android/filament/TextureSampler$MagFilter;

.field static final sMinFilterValues:[Lcom/google/android/filament/TextureSampler$MinFilter;

.field static final sWrapModeValues:[Lcom/google/android/filament/TextureSampler$WrapMode;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/TextureSampler$MinFilter;->values()[Lcom/google/android/filament/TextureSampler$MinFilter;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sMinFilterValues:[Lcom/google/android/filament/TextureSampler$MinFilter;

    .line 6
    .line 7
    invoke-static {}, Lcom/google/android/filament/TextureSampler$MagFilter;->values()[Lcom/google/android/filament/TextureSampler$MagFilter;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sMagFilterValues:[Lcom/google/android/filament/TextureSampler$MagFilter;

    .line 12
    .line 13
    invoke-static {}, Lcom/google/android/filament/TextureSampler$WrapMode;->values()[Lcom/google/android/filament/TextureSampler$WrapMode;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sWrapModeValues:[Lcom/google/android/filament/TextureSampler$WrapMode;

    .line 18
    .line 19
    invoke-static {}, Lcom/google/android/filament/TextureSampler$CompareMode;->values()[Lcom/google/android/filament/TextureSampler$CompareMode;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sCompareModeValues:[Lcom/google/android/filament/TextureSampler$CompareMode;

    .line 24
    .line 25
    invoke-static {}, Lcom/google/android/filament/TextureSampler$CompareFunction;->values()[Lcom/google/android/filament/TextureSampler$CompareFunction;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sput-object v0, Lcom/google/android/filament/TextureSampler$EnumCache;->sCompareFunctionValues:[Lcom/google/android/filament/TextureSampler$CompareFunction;

    .line 30
    .line 31
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
