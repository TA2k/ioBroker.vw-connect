.class public final Lcom/google/android/filament/utils/Half;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/Half$Companion;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/lang/Comparable<",
        "Lcom/google/android/filament/utils/Half;",
        ">;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000X\n\u0002\u0018\u0002\n\u0002\u0010\u000f\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0010\u0005\n\u0002\u0008\u0003\n\u0002\u0010\n\n\u0002\u0008\u0004\n\u0002\u0010\t\n\u0002\u0008\u0003\n\u0002\u0010\u0007\n\u0002\u0008\u0003\n\u0002\u0010\u0006\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008.\n\u0002\u0010\u000e\n\u0002\u0008\u0007\n\u0002\u0010\u0000\n\u0002\u0008\u000f\u0008\u0087@\u0018\u0000 d2\u0008\u0012\u0004\u0012\u00020\u00000\u0001:\u0001dB\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\r\u0010\t\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\r\u0010\r\u001a\u00020\n\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\r\u0010\u0010\u001a\u00020\u000e\u00a2\u0006\u0004\u0008\u000f\u0010\u0005J\r\u0010\u0012\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0011\u0010\u0008J\r\u0010\u0016\u001a\u00020\u0013\u00a2\u0006\u0004\u0008\u0014\u0010\u0015J\r\u0010\u001a\u001a\u00020\u0017\u00a2\u0006\u0004\u0008\u0018\u0010\u0019J\r\u0010\u001e\u001a\u00020\u001b\u00a2\u0006\u0004\u0008\u001c\u0010\u001dJ\r\u0010\"\u001a\u00020\u001f\u00a2\u0006\u0004\u0008 \u0010!J\r\u0010$\u001a\u00020\u001f\u00a2\u0006\u0004\u0008#\u0010!J\r\u0010&\u001a\u00020\u001f\u00a2\u0006\u0004\u0008%\u0010!J\r\u0010(\u001a\u00020\u001f\u00a2\u0006\u0004\u0008\'\u0010!J\r\u0010*\u001a\u00020\u001f\u00a2\u0006\u0004\u0008)\u0010!J\u0015\u0010.\u001a\u00020\u00002\u0006\u0010+\u001a\u00020\u0000\u00a2\u0006\u0004\u0008,\u0010-J\r\u00100\u001a\u00020\u0000\u00a2\u0006\u0004\u0008/\u0010\u0005J\r\u00102\u001a\u00020\u0000\u00a2\u0006\u0004\u00081\u0010\u0005J\u0015\u00105\u001a\u00020\u00002\u0006\u00103\u001a\u00020\u0000\u00a2\u0006\u0004\u00084\u0010-J\r\u00107\u001a\u00020\u0006\u00a2\u0006\u0004\u00086\u0010\u0008J\r\u00109\u001a\u00020\u0013\u00a2\u0006\u0004\u00088\u0010\u0015J\u0010\u0010;\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008:\u0010\u0005J\u0010\u0010=\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008<\u0010\u0005J\u0018\u0010@\u001a\u00020\u00002\u0006\u0010>\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008?\u0010-J\u0018\u0010B\u001a\u00020\u00002\u0006\u0010>\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008A\u0010-J\u0018\u0010D\u001a\u00020\u00002\u0006\u0010>\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008C\u0010-J\u0018\u0010F\u001a\u00020\u00002\u0006\u0010>\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008E\u0010-J\u0010\u0010H\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008G\u0010\u0005J\u0010\u0010J\u001a\u00020\u0000H\u0086\u0002\u00a2\u0006\u0004\u0008I\u0010\u0005J\u0018\u0010M\u001a\u00020\u00062\u0006\u0010>\u001a\u00020\u0000H\u0096\u0002\u00a2\u0006\u0004\u0008K\u0010LJ\u000f\u0010Q\u001a\u00020NH\u0016\u00a2\u0006\u0004\u0008O\u0010PJ\r\u0010S\u001a\u00020N\u00a2\u0006\u0004\u0008R\u0010PJ\u0010\u0010U\u001a\u00020\u0006H\u00d6\u0001\u00a2\u0006\u0004\u0008T\u0010\u0008J\u001a\u0010Y\u001a\u00020\u001f2\u0008\u0010>\u001a\u0004\u0018\u00010VH\u00d6\u0003\u00a2\u0006\u0004\u0008W\u0010XR\u0014\u0010\u0003\u001a\u00020\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0003\u0010ZR\u0011\u0010+\u001a\u00020\u00008F\u00a2\u0006\u0006\u001a\u0004\u0008[\u0010\u0005R\u0011\u0010]\u001a\u00020\u00068F\u00a2\u0006\u0006\u001a\u0004\u0008\\\u0010\u0008R\u0011\u0010_\u001a\u00020\u00068F\u00a2\u0006\u0006\u001a\u0004\u0008^\u0010\u0008R\u0011\u0010a\u001a\u00020\u00008F\u00a2\u0006\u0006\u001a\u0004\u0008`\u0010\u0005R\u0011\u0010c\u001a\u00020\u00008F\u00a2\u0006\u0006\u001a\u0004\u0008b\u0010\u0005\u0088\u0001\u0003\u0092\u0001\u00020\u0002\u00a8\u0006e"
    }
    d2 = {
        "Lcom/google/android/filament/utils/Half;",
        "",
        "Llx0/z;",
        "v",
        "constructor-impl",
        "(S)S",
        "",
        "toBits-impl",
        "(S)I",
        "toBits",
        "",
        "toByte-impl",
        "(S)B",
        "toByte",
        "",
        "toShort-impl",
        "toShort",
        "toInt-impl",
        "toInt",
        "",
        "toLong-impl",
        "(S)J",
        "toLong",
        "",
        "toFloat-impl",
        "(S)F",
        "toFloat",
        "",
        "toDouble-impl",
        "(S)D",
        "toDouble",
        "",
        "isNaN-impl",
        "(S)Z",
        "isNaN",
        "isInfinite-impl",
        "isInfinite",
        "isFinite-impl",
        "isFinite",
        "isZero-impl",
        "isZero",
        "isNormalized-impl",
        "isNormalized",
        "sign",
        "withSign-5SPjhV8",
        "(SS)S",
        "withSign",
        "nextUp-SjiOe_E",
        "nextUp",
        "nextDown-SjiOe_E",
        "nextDown",
        "to",
        "nextTowards-5SPjhV8",
        "nextTowards",
        "roundToInt-impl",
        "roundToInt",
        "roundToLong-impl",
        "roundToLong",
        "unaryMinus-SjiOe_E",
        "unaryMinus",
        "unaryPlus-SjiOe_E",
        "unaryPlus",
        "other",
        "plus-5SPjhV8",
        "plus",
        "minus-5SPjhV8",
        "minus",
        "times-5SPjhV8",
        "times",
        "div-5SPjhV8",
        "div",
        "inc-SjiOe_E",
        "inc",
        "dec-SjiOe_E",
        "dec",
        "compareTo-FqSqZzs",
        "(SS)I",
        "compareTo",
        "",
        "toString-impl",
        "(S)Ljava/lang/String;",
        "toString",
        "toHexString-impl",
        "toHexString",
        "hashCode-impl",
        "hashCode",
        "",
        "equals-impl",
        "(SLjava/lang/Object;)Z",
        "equals",
        "S",
        "getSign-SjiOe_E",
        "getExponent-impl",
        "exponent",
        "getSignificand-impl",
        "significand",
        "getAbsoluteValue-SjiOe_E",
        "absoluteValue",
        "getUlp-SjiOe_E",
        "ulp",
        "Companion",
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
.field public static final Companion:Lcom/google/android/filament/utils/Half$Companion;

.field private static final EPSILON:S

.field private static final LOWEST_VALUE:S

.field public static final MAX_EXPONENT:I = 0xf

.field private static final MAX_VALUE:S

.field public static final MIN_EXPONENT:I = -0xe

.field private static final MIN_NORMAL:S

.field private static final MIN_VALUE:S

.field private static final NEGATIVE_INFINITY:S

.field private static final NEGATIVE_ZERO:S

.field private static final NaN:S

.field private static final POSITIVE_INFINITY:S

.field private static final POSITIVE_ZERO:S

.field public static final SIZE:I = 0x10


# instance fields
.field private final v:S


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Half$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/google/android/filament/utils/Half$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/filament/utils/Half;->Companion:Lcom/google/android/filament/utils/Half$Companion;

    .line 8
    .line 9
    const/16 v0, 0x1400

    .line 10
    .line 11
    int-to-short v0, v0

    .line 12
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    sput-short v0, Lcom/google/android/filament/utils/Half;->EPSILON:S

    .line 17
    .line 18
    const v0, 0xfbff

    .line 19
    .line 20
    .line 21
    int-to-short v0, v0

    .line 22
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    sput-short v0, Lcom/google/android/filament/utils/Half;->LOWEST_VALUE:S

    .line 27
    .line 28
    const/16 v0, 0x7bff

    .line 29
    .line 30
    int-to-short v0, v0

    .line 31
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    sput-short v0, Lcom/google/android/filament/utils/Half;->MAX_VALUE:S

    .line 36
    .line 37
    const/16 v0, 0x400

    .line 38
    .line 39
    int-to-short v0, v0

    .line 40
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    sput-short v0, Lcom/google/android/filament/utils/Half;->MIN_NORMAL:S

    .line 45
    .line 46
    const/4 v0, 0x1

    .line 47
    int-to-short v0, v0

    .line 48
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    sput-short v0, Lcom/google/android/filament/utils/Half;->MIN_VALUE:S

    .line 53
    .line 54
    const/16 v0, 0x7e00

    .line 55
    .line 56
    int-to-short v0, v0

    .line 57
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    sput-short v0, Lcom/google/android/filament/utils/Half;->NaN:S

    .line 62
    .line 63
    const v0, 0xfc00

    .line 64
    .line 65
    .line 66
    int-to-short v0, v0

    .line 67
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    sput-short v0, Lcom/google/android/filament/utils/Half;->NEGATIVE_INFINITY:S

    .line 72
    .line 73
    const v0, 0x8000

    .line 74
    .line 75
    .line 76
    int-to-short v0, v0

    .line 77
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    sput-short v0, Lcom/google/android/filament/utils/Half;->NEGATIVE_ZERO:S

    .line 82
    .line 83
    const/16 v0, 0x7c00

    .line 84
    .line 85
    int-to-short v0, v0

    .line 86
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    sput-short v0, Lcom/google/android/filament/utils/Half;->POSITIVE_INFINITY:S

    .line 91
    .line 92
    const/4 v0, 0x0

    .line 93
    int-to-short v0, v0

    .line 94
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    sput-short v0, Lcom/google/android/filament/utils/Half;->POSITIVE_ZERO:S

    .line 99
    .line 100
    return-void
.end method

.method private synthetic constructor <init>(S)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-short p1, p0, Lcom/google/android/filament/utils/Half;->v:S

    .line 5
    .line 6
    return-void
.end method

.method public static final synthetic access$getEPSILON$cp()S
    .locals 1

    .line 1
    sget-short v0, Lcom/google/android/filament/utils/Half;->EPSILON:S

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getLOWEST_VALUE$cp()S
    .locals 1

    .line 1
    sget-short v0, Lcom/google/android/filament/utils/Half;->LOWEST_VALUE:S

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getMAX_VALUE$cp()S
    .locals 1

    .line 1
    sget-short v0, Lcom/google/android/filament/utils/Half;->MAX_VALUE:S

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getMIN_NORMAL$cp()S
    .locals 1

    .line 1
    sget-short v0, Lcom/google/android/filament/utils/Half;->MIN_NORMAL:S

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getMIN_VALUE$cp()S
    .locals 1

    .line 1
    sget-short v0, Lcom/google/android/filament/utils/Half;->MIN_VALUE:S

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getNEGATIVE_INFINITY$cp()S
    .locals 1

    .line 1
    sget-short v0, Lcom/google/android/filament/utils/Half;->NEGATIVE_INFINITY:S

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getNEGATIVE_ZERO$cp()S
    .locals 1

    .line 1
    sget-short v0, Lcom/google/android/filament/utils/Half;->NEGATIVE_ZERO:S

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getNaN$cp()S
    .locals 1

    .line 1
    sget-short v0, Lcom/google/android/filament/utils/Half;->NaN:S

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPOSITIVE_INFINITY$cp()S
    .locals 1

    .line 1
    sget-short v0, Lcom/google/android/filament/utils/Half;->POSITIVE_INFINITY:S

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic access$getPOSITIVE_ZERO$cp()S
    .locals 1

    .line 1
    sget-short v0, Lcom/google/android/filament/utils/Half;->POSITIVE_ZERO:S

    .line 2
    .line 3
    return v0
.end method

.method public static final synthetic box-impl(S)Lcom/google/android/filament/utils/Half;
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/Half;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lcom/google/android/filament/utils/Half;-><init>(S)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static compareTo-FqSqZzs(SS)I
    .locals 3

    .line 1
    and-int/lit16 v0, p0, 0x7fff

    const/16 v1, 0x7e00

    const/16 v2, 0x7c00

    if-le v0, v2, :cond_0

    move p0, v1

    :cond_0
    and-int/lit16 v0, p1, 0x7fff

    if-le v0, v2, :cond_1

    move p1, v1

    :cond_1
    if-ne p0, p1, :cond_2

    const/4 p0, 0x0

    return p0

    :cond_2
    shr-int/lit8 v0, p0, 0xf

    const v1, 0x8000

    sub-int v2, v1, v0

    or-int/2addr v2, v1

    xor-int/2addr p0, v2

    add-int/2addr p0, v0

    shr-int/lit8 v0, p1, 0xf

    sub-int v2, v1, v0

    or-int/2addr v1, v2

    xor-int/2addr p1, v1

    add-int/2addr p1, v0

    if-ge p0, p1, :cond_3

    const/4 p0, -0x1

    return p0

    :cond_3
    const/4 p0, 0x1

    return p0
.end method

.method public static constructor-impl(S)S
    .locals 0

    .line 1
    return p0
.end method

.method public static final dec-SjiOe_E(S)S
    .locals 1

    .line 1
    const v0, 0xbc00

    .line 2
    .line 3
    .line 4
    int-to-short v0, v0

    .line 5
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-static {p0, v0}, Lcom/google/android/filament/utils/Half;->plus-5SPjhV8(SS)S

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public static final div-5SPjhV8(SS)S
    .locals 8

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->toBits-impl(S)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p1}, Lcom/google/android/filament/utils/Half;->toBits-impl(S)I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    xor-int v0, p0, p1

    .line 10
    .line 11
    const v1, 0x8000

    .line 12
    .line 13
    .line 14
    and-int/2addr v0, v1

    .line 15
    and-int/lit16 v1, p0, 0x7fff

    .line 16
    .line 17
    const/16 v2, 0x7fff

    .line 18
    .line 19
    and-int/2addr p1, v2

    .line 20
    const/4 v3, 0x0

    .line 21
    const/16 v4, 0x7c00

    .line 22
    .line 23
    if-ge v1, v4, :cond_a

    .line 24
    .line 25
    if-lt p1, v4, :cond_0

    .line 26
    .line 27
    goto/16 :goto_3

    .line 28
    .line 29
    :cond_0
    if-nez v1, :cond_2

    .line 30
    .line 31
    if-nez p1, :cond_1

    .line 32
    .line 33
    move v0, v2

    .line 34
    :cond_1
    int-to-short p0, v0

    .line 35
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    return p0

    .line 40
    :cond_2
    if-nez p1, :cond_3

    .line 41
    .line 42
    or-int/lit16 p0, v0, 0x7c00

    .line 43
    .line 44
    int-to-short p0, p0

    .line 45
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    return p0

    .line 50
    :cond_3
    const/16 p0, 0xe

    .line 51
    .line 52
    :goto_0
    const/16 v2, 0x400

    .line 53
    .line 54
    if-ge v1, v2, :cond_4

    .line 55
    .line 56
    shl-int/lit8 v1, v1, 0x1

    .line 57
    .line 58
    add-int/lit8 p0, p0, -0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_4
    :goto_1
    if-ge p1, v2, :cond_5

    .line 62
    .line 63
    shl-int/lit8 p1, p1, 0x1

    .line 64
    .line 65
    add-int/lit8 p0, p0, 0x1

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_5
    and-int/lit16 v5, v1, 0x3ff

    .line 69
    .line 70
    or-int/2addr v5, v2

    .line 71
    and-int/lit16 v6, p1, 0x3ff

    .line 72
    .line 73
    or-int/2addr v2, v6

    .line 74
    invoke-static {v5, v2}, Ljava/lang/Integer;->compareUnsigned(II)I

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    const/4 v7, 0x1

    .line 79
    if-gez v6, :cond_6

    .line 80
    .line 81
    move v6, v7

    .line 82
    goto :goto_2

    .line 83
    :cond_6
    move v6, v3

    .line 84
    :goto_2
    shr-int/lit8 v1, v1, 0xa

    .line 85
    .line 86
    shr-int/lit8 p1, p1, 0xa

    .line 87
    .line 88
    sub-int/2addr v1, p1

    .line 89
    sub-int/2addr v1, v6

    .line 90
    add-int/2addr v1, p0

    .line 91
    const/16 p0, 0x1d

    .line 92
    .line 93
    if-le v1, p0, :cond_7

    .line 94
    .line 95
    or-int/lit16 p0, v0, 0x7c00

    .line 96
    .line 97
    int-to-short p0, p0

    .line 98
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    return p0

    .line 103
    :cond_7
    const/16 p0, -0xb

    .line 104
    .line 105
    if-ge v1, p0, :cond_8

    .line 106
    .line 107
    int-to-short p0, v0

    .line 108
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 109
    .line 110
    .line 111
    move-result p0

    .line 112
    return p0

    .line 113
    :cond_8
    add-int/lit8 v6, v6, 0xc

    .line 114
    .line 115
    shl-int p0, v5, v6

    .line 116
    .line 117
    shl-int/lit8 p1, v2, 0x1

    .line 118
    .line 119
    invoke-static {p0, p1}, Ljava/lang/Integer;->divideUnsigned(II)I

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    invoke-static {p0, p1}, Ljava/lang/Integer;->remainderUnsigned(II)I

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    if-eqz p0, :cond_9

    .line 128
    .line 129
    move v3, v7

    .line 130
    :cond_9
    const/16 p0, 0xb

    .line 131
    .line 132
    invoke-static {v0, v1, v2, v3, p0}, Lcom/google/android/filament/utils/HalfKt;->access$fixedToHalf-yOCu0fQ(IIIII)S

    .line 133
    .line 134
    .line 135
    move-result p0

    .line 136
    return p0

    .line 137
    :cond_a
    :goto_3
    if-gt v1, v4, :cond_e

    .line 138
    .line 139
    if-le p1, v4, :cond_b

    .line 140
    .line 141
    goto :goto_4

    .line 142
    :cond_b
    if-ne v1, p1, :cond_c

    .line 143
    .line 144
    goto :goto_6

    .line 145
    :cond_c
    if-ne v1, v4, :cond_d

    .line 146
    .line 147
    move v3, v4

    .line 148
    :cond_d
    or-int v2, v0, v3

    .line 149
    .line 150
    goto :goto_6

    .line 151
    :cond_e
    :goto_4
    and-int/2addr p0, v2

    .line 152
    if-le p0, v4, :cond_f

    .line 153
    .line 154
    goto :goto_5

    .line 155
    :cond_f
    move v1, p1

    .line 156
    :goto_5
    or-int/lit16 v2, v1, 0x200

    .line 157
    .line 158
    :goto_6
    int-to-short p0, v2

    .line 159
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 160
    .line 161
    .line 162
    move-result p0

    .line 163
    return p0
.end method

.method public static equals-impl(SLjava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lcom/google/android/filament/utils/Half;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    return v1

    .line 7
    :cond_0
    check-cast p1, Lcom/google/android/filament/utils/Half;

    .line 8
    .line 9
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Half;->unbox-impl()S

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    if-eq p0, p1, :cond_1

    .line 14
    .line 15
    return v1

    .line 16
    :cond_1
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public static final equals-impl0(SS)Z
    .locals 0

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    const/4 p0, 0x0

    .line 6
    return p0
.end method

.method public static final getAbsoluteValue-SjiOe_E(S)S
    .locals 0

    .line 1
    and-int/lit16 p0, p0, 0x7fff

    .line 2
    .line 3
    int-to-short p0, p0

    .line 4
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    return p0
.end method

.method public static final getExponent-impl(S)I
    .locals 1

    .line 1
    const v0, 0xffff

    .line 2
    .line 3
    .line 4
    and-int/2addr p0, v0

    .line 5
    ushr-int/lit8 p0, p0, 0xa

    .line 6
    .line 7
    and-int/lit8 p0, p0, 0x1f

    .line 8
    .line 9
    add-int/lit8 p0, p0, -0xf

    .line 10
    .line 11
    return p0
.end method

.method public static final getSign-SjiOe_E(S)S
    .locals 2

    .line 1
    and-int/lit16 v0, p0, 0x7fff

    .line 2
    .line 3
    const/16 v1, 0x7c00

    .line 4
    .line 5
    if-le v0, v1, :cond_0

    .line 6
    .line 7
    sget-short p0, Lcom/google/android/filament/utils/Half;->NaN:S

    .line 8
    .line 9
    return p0

    .line 10
    :cond_0
    if-nez v0, :cond_1

    .line 11
    .line 12
    sget-short p0, Lcom/google/android/filament/utils/Half;->POSITIVE_ZERO:S

    .line 13
    .line 14
    return p0

    .line 15
    :cond_1
    const v0, 0x8000

    .line 16
    .line 17
    .line 18
    and-int/2addr p0, v0

    .line 19
    if-eqz p0, :cond_2

    .line 20
    .line 21
    const/high16 p0, -0x40800000    # -1.0f

    .line 22
    .line 23
    :goto_0
    invoke-static {p0}, Lcom/google/android/filament/utils/HalfKt;->Half(F)S

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    :cond_2
    const/high16 p0, 0x3f800000    # 1.0f

    .line 29
    .line 30
    goto :goto_0
.end method

.method public static final getSignificand-impl(S)I
    .locals 0

    .line 1
    and-int/lit16 p0, p0, 0x3ff

    .line 2
    .line 3
    return p0
.end method

.method public static final getUlp-SjiOe_E(S)S
    .locals 2

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->isNaN-impl(S)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    sget-short p0, Lcom/google/android/filament/utils/Half;->NaN:S

    .line 8
    .line 9
    return p0

    .line 10
    :cond_0
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->isInfinite-impl(S)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    sget-short p0, Lcom/google/android/filament/utils/Half;->POSITIVE_INFINITY:S

    .line 17
    .line 18
    return p0

    .line 19
    :cond_1
    and-int/lit16 v0, p0, 0x7fff

    .line 20
    .line 21
    const/16 v1, 0x7bff

    .line 22
    .line 23
    if-ne v0, v1, :cond_2

    .line 24
    .line 25
    const/16 p0, 0x4c00

    .line 26
    .line 27
    int-to-short p0, p0

    .line 28
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    return p0

    .line 33
    :cond_2
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->getAbsoluteValue-SjiOe_E(S)S

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->nextUp-SjiOe_E(S)S

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    invoke-static {v0, p0}, Lcom/google/android/filament/utils/Half;->minus-5SPjhV8(SS)S

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    return p0
.end method

.method public static hashCode-impl(S)I
    .locals 0

    .line 1
    invoke-static {p0}, Ljava/lang/Short;->hashCode(S)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static final inc-SjiOe_E(S)S
    .locals 1

    .line 1
    const/16 v0, 0x3c00

    .line 2
    .line 3
    int-to-short v0, v0

    .line 4
    invoke-static {v0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    invoke-static {p0, v0}, Lcom/google/android/filament/utils/Half;->plus-5SPjhV8(SS)S

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0
.end method

.method public static final isFinite-impl(S)Z
    .locals 1

    .line 1
    const/16 v0, 0x7c00

    .line 2
    .line 3
    and-int/2addr p0, v0

    .line 4
    if-eq p0, v0, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public static final isInfinite-impl(S)Z
    .locals 1

    .line 1
    and-int/lit16 p0, p0, 0x7fff

    .line 2
    .line 3
    const/16 v0, 0x7c00

    .line 4
    .line 5
    if-ne p0, v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public static final isNaN-impl(S)Z
    .locals 1

    .line 1
    and-int/lit16 p0, p0, 0x7fff

    .line 2
    .line 3
    const/16 v0, 0x7c00

    .line 4
    .line 5
    if-le p0, v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public static final isNormalized-impl(S)Z
    .locals 1

    .line 1
    const/16 v0, 0x7c00

    .line 2
    .line 3
    and-int/2addr p0, v0

    .line 4
    if-eqz p0, :cond_0

    .line 5
    .line 6
    if-eq p0, v0, :cond_0

    .line 7
    .line 8
    const/4 p0, 0x1

    .line 9
    return p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return p0
.end method

.method public static final isZero-impl(S)Z
    .locals 0

    .line 1
    and-int/lit16 p0, p0, 0x7fff

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public static final minus-5SPjhV8(SS)S
    .locals 0

    .line 1
    invoke-static {p1}, Lcom/google/android/filament/utils/Half;->unaryMinus-SjiOe_E(S)S

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    invoke-static {p0, p1}, Lcom/google/android/filament/utils/Half;->plus-5SPjhV8(SS)S

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public static final nextDown-SjiOe_E(S)S
    .locals 2

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->isNaN-impl(S)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_3

    .line 6
    .line 7
    sget-short v0, Lcom/google/android/filament/utils/Half;->NEGATIVE_INFINITY:S

    .line 8
    .line 9
    if-ne p0, v0, :cond_0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_0
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->isZero-impl(S)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    sget-short p0, Lcom/google/android/filament/utils/Half;->MIN_VALUE:S

    .line 19
    .line 20
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->unaryMinus-SjiOe_E(S)S

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0

    .line 25
    :cond_1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->toBits-impl(S)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    const v1, 0x8000

    .line 30
    .line 31
    .line 32
    and-int/2addr p0, v1

    .line 33
    if-nez p0, :cond_2

    .line 34
    .line 35
    const/4 p0, -0x1

    .line 36
    goto :goto_0

    .line 37
    :cond_2
    const/4 p0, 0x1

    .line 38
    :goto_0
    add-int/2addr v0, p0

    .line 39
    int-to-short p0, v0

    .line 40
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    :cond_3
    :goto_1
    return p0
.end method

.method public static final nextTowards-5SPjhV8(SS)S
    .locals 1

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->isNaN-impl(S)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_3

    .line 6
    .line 7
    invoke-static {p1}, Lcom/google/android/filament/utils/Half;->isNaN-impl(S)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-static {p1, p0}, Lcom/google/android/filament/utils/Half;->equals-impl0(SS)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    return p0

    .line 21
    :cond_1
    invoke-static {p1, p0}, Lcom/google/android/filament/utils/Half;->compareTo-FqSqZzs(SS)I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    if-lez p1, :cond_2

    .line 26
    .line 27
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->nextUp-SjiOe_E(S)S

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0

    .line 32
    :cond_2
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->nextDown-SjiOe_E(S)S

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0

    .line 37
    :cond_3
    :goto_0
    sget-short p0, Lcom/google/android/filament/utils/Half;->NaN:S

    .line 38
    .line 39
    return p0
.end method

.method public static final nextUp-SjiOe_E(S)S
    .locals 2

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->isNaN-impl(S)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_3

    .line 6
    .line 7
    sget-short v0, Lcom/google/android/filament/utils/Half;->POSITIVE_INFINITY:S

    .line 8
    .line 9
    if-ne p0, v0, :cond_0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_0
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->isZero-impl(S)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    sget-short p0, Lcom/google/android/filament/utils/Half;->MIN_VALUE:S

    .line 19
    .line 20
    return p0

    .line 21
    :cond_1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->toBits-impl(S)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    const v1, 0x8000

    .line 26
    .line 27
    .line 28
    and-int/2addr p0, v1

    .line 29
    if-nez p0, :cond_2

    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    goto :goto_0

    .line 33
    :cond_2
    const/4 p0, -0x1

    .line 34
    :goto_0
    add-int/2addr v0, p0

    .line 35
    int-to-short p0, v0

    .line 36
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    :cond_3
    :goto_1
    return p0
.end method

.method public static final plus-5SPjhV8(SS)S
    .locals 10

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->toBits-impl(S)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p1}, Lcom/google/android/filament/utils/Half;->toBits-impl(S)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    xor-int v2, v0, v1

    .line 10
    .line 11
    const v3, 0x8000

    .line 12
    .line 13
    .line 14
    and-int/2addr v2, v3

    .line 15
    const/4 v4, 0x0

    .line 16
    const/4 v5, 0x1

    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    move v2, v5

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    move v2, v4

    .line 22
    :goto_0
    and-int/lit16 v6, v0, 0x7fff

    .line 23
    .line 24
    and-int/lit16 v7, v1, 0x7fff

    .line 25
    .line 26
    const/16 v8, 0x7c00

    .line 27
    .line 28
    if-ge v6, v8, :cond_12

    .line 29
    .line 30
    if-lt v7, v8, :cond_1

    .line 31
    .line 32
    goto/16 :goto_8

    .line 33
    .line 34
    :cond_1
    if-nez v6, :cond_3

    .line 35
    .line 36
    if-eqz v7, :cond_2

    .line 37
    .line 38
    return p1

    .line 39
    :cond_2
    and-int p0, v0, v1

    .line 40
    .line 41
    int-to-short p0, p0

    .line 42
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    return p0

    .line 47
    :cond_3
    if-nez v7, :cond_4

    .line 48
    .line 49
    return p0

    .line 50
    :cond_4
    if-eqz v2, :cond_5

    .line 51
    .line 52
    if-le v7, v6, :cond_5

    .line 53
    .line 54
    move v0, v1

    .line 55
    :cond_5
    and-int p0, v0, v3

    .line 56
    .line 57
    if-le v7, v6, :cond_6

    .line 58
    .line 59
    move v9, v7

    .line 60
    move v7, v6

    .line 61
    move v6, v9

    .line 62
    :cond_6
    shr-int/lit8 p1, v6, 0xa

    .line 63
    .line 64
    const/16 v0, 0x3ff

    .line 65
    .line 66
    if-gt v6, v0, :cond_7

    .line 67
    .line 68
    move v1, v5

    .line 69
    goto :goto_1

    .line 70
    :cond_7
    move v1, v4

    .line 71
    :goto_1
    add-int/2addr p1, v1

    .line 72
    shr-int/lit8 v1, v7, 0xa

    .line 73
    .line 74
    sub-int v1, p1, v1

    .line 75
    .line 76
    if-gt v7, v0, :cond_8

    .line 77
    .line 78
    move v3, v5

    .line 79
    goto :goto_2

    .line 80
    :cond_8
    move v3, v4

    .line 81
    :goto_2
    sub-int/2addr v1, v3

    .line 82
    and-int/lit16 v3, v6, 0x3ff

    .line 83
    .line 84
    if-le v6, v0, :cond_9

    .line 85
    .line 86
    move v6, v5

    .line 87
    goto :goto_3

    .line 88
    :cond_9
    move v6, v4

    .line 89
    :goto_3
    shl-int/lit8 v6, v6, 0xa

    .line 90
    .line 91
    or-int/2addr v3, v6

    .line 92
    shl-int/lit8 v3, v3, 0x3

    .line 93
    .line 94
    const/16 v6, 0xd

    .line 95
    .line 96
    if-ge v1, v6, :cond_c

    .line 97
    .line 98
    and-int/lit16 v6, v7, 0x3ff

    .line 99
    .line 100
    if-le v7, v0, :cond_a

    .line 101
    .line 102
    move v0, v5

    .line 103
    goto :goto_4

    .line 104
    :cond_a
    move v0, v4

    .line 105
    :goto_4
    shl-int/lit8 v0, v0, 0xa

    .line 106
    .line 107
    or-int/2addr v0, v6

    .line 108
    shl-int/lit8 v0, v0, 0x3

    .line 109
    .line 110
    shr-int v6, v0, v1

    .line 111
    .line 112
    shl-int v1, v5, v1

    .line 113
    .line 114
    sub-int/2addr v1, v5

    .line 115
    and-int/2addr v0, v1

    .line 116
    if-eqz v0, :cond_b

    .line 117
    .line 118
    move v0, v5

    .line 119
    goto :goto_5

    .line 120
    :cond_b
    move v0, v4

    .line 121
    :goto_5
    or-int/2addr v0, v6

    .line 122
    goto :goto_6

    .line 123
    :cond_c
    move v0, v5

    .line 124
    :goto_6
    if-eqz v2, :cond_e

    .line 125
    .line 126
    sub-int/2addr v3, v0

    .line 127
    if-nez v3, :cond_d

    .line 128
    .line 129
    sget-short p0, Lcom/google/android/filament/utils/Half;->POSITIVE_ZERO:S

    .line 130
    .line 131
    return p0

    .line 132
    :cond_d
    :goto_7
    const/16 v0, 0x2000

    .line 133
    .line 134
    if-ge v3, v0, :cond_10

    .line 135
    .line 136
    if-le p1, v5, :cond_10

    .line 137
    .line 138
    shl-int/lit8 v3, v3, 0x1

    .line 139
    .line 140
    add-int/lit8 p1, p1, -0x1

    .line 141
    .line 142
    goto :goto_7

    .line 143
    :cond_e
    add-int/2addr v3, v0

    .line 144
    shr-int/lit8 v0, v3, 0xe

    .line 145
    .line 146
    add-int/2addr p1, v0

    .line 147
    const/16 v1, 0x1e

    .line 148
    .line 149
    if-le p1, v1, :cond_f

    .line 150
    .line 151
    or-int/2addr p0, v8

    .line 152
    int-to-short p0, p0

    .line 153
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 154
    .line 155
    .line 156
    move-result p0

    .line 157
    return p0

    .line 158
    :cond_f
    shr-int v1, v3, v0

    .line 159
    .line 160
    and-int/2addr v0, v3

    .line 161
    or-int v3, v1, v0

    .line 162
    .line 163
    :cond_10
    sub-int/2addr p1, v5

    .line 164
    shl-int/lit8 p1, p1, 0xa

    .line 165
    .line 166
    add-int/2addr p0, p1

    .line 167
    shr-int/lit8 p1, v3, 0x3

    .line 168
    .line 169
    add-int/2addr p0, p1

    .line 170
    shr-int/lit8 p1, v3, 0x2

    .line 171
    .line 172
    and-int/2addr p1, v5

    .line 173
    and-int/lit8 v0, v3, 0x3

    .line 174
    .line 175
    if-eqz v0, :cond_11

    .line 176
    .line 177
    move v4, v5

    .line 178
    :cond_11
    or-int v0, v4, p0

    .line 179
    .line 180
    and-int/2addr p1, v0

    .line 181
    add-int/2addr p0, p1

    .line 182
    int-to-short p0, p0

    .line 183
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 184
    .line 185
    .line 186
    move-result p0

    .line 187
    return p0

    .line 188
    :cond_12
    :goto_8
    if-gt v6, v8, :cond_16

    .line 189
    .line 190
    if-le v7, v8, :cond_13

    .line 191
    .line 192
    goto :goto_9

    .line 193
    :cond_13
    if-eq v7, v8, :cond_14

    .line 194
    .line 195
    goto :goto_b

    .line 196
    :cond_14
    if-eqz v2, :cond_15

    .line 197
    .line 198
    if-ne v6, v8, :cond_15

    .line 199
    .line 200
    const/16 v0, 0x7fff

    .line 201
    .line 202
    goto :goto_b

    .line 203
    :cond_15
    move v0, v1

    .line 204
    goto :goto_b

    .line 205
    :cond_16
    :goto_9
    and-int/lit16 p0, v0, 0x7fff

    .line 206
    .line 207
    if-le p0, v8, :cond_17

    .line 208
    .line 209
    goto :goto_a

    .line 210
    :cond_17
    move v6, v7

    .line 211
    :goto_a
    or-int/lit16 v0, v6, 0x200

    .line 212
    .line 213
    :goto_b
    int-to-short p0, v0

    .line 214
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 215
    .line 216
    .line 217
    move-result p0

    .line 218
    return p0
.end method

.method public static final roundToInt-impl(S)I
    .locals 1

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->isNaN-impl(S)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-static {p0}, Lcom/google/android/filament/utils/HalfKt;->round-FqSqZzs(S)S

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->toInt-impl(S)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    const-string v0, "Cannot round NaN value."

    .line 19
    .line 20
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0
.end method

.method public static final roundToLong-impl(S)J
    .locals 2

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->isNaN-impl(S)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-static {p0}, Lcom/google/android/filament/utils/HalfKt;->round-FqSqZzs(S)S

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->toLong-impl(S)J

    .line 12
    .line 13
    .line 14
    move-result-wide v0

    .line 15
    return-wide v0

    .line 16
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 17
    .line 18
    const-string v0, "Cannot round NaN value."

    .line 19
    .line 20
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0
.end method

.method public static final times-5SPjhV8(SS)S
    .locals 6

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->toBits-impl(S)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p1}, Lcom/google/android/filament/utils/Half;->toBits-impl(S)I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    xor-int v0, p0, p1

    .line 10
    .line 11
    const v1, 0x8000

    .line 12
    .line 13
    .line 14
    and-int/2addr v0, v1

    .line 15
    and-int/lit16 v1, p0, 0x7fff

    .line 16
    .line 17
    const/16 v2, 0x7fff

    .line 18
    .line 19
    and-int/2addr p1, v2

    .line 20
    const/16 v3, 0x7c00

    .line 21
    .line 22
    if-ge v1, v3, :cond_7

    .line 23
    .line 24
    if-lt p1, v3, :cond_0

    .line 25
    .line 26
    goto :goto_3

    .line 27
    :cond_0
    if-eqz v1, :cond_6

    .line 28
    .line 29
    if-nez p1, :cond_1

    .line 30
    .line 31
    goto :goto_2

    .line 32
    :cond_1
    const/16 p0, -0x10

    .line 33
    .line 34
    :goto_0
    const/16 v2, 0x400

    .line 35
    .line 36
    if-ge v1, v2, :cond_2

    .line 37
    .line 38
    shl-int/lit8 v1, v1, 0x1

    .line 39
    .line 40
    add-int/lit8 p0, p0, -0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_2
    :goto_1
    if-ge p1, v2, :cond_3

    .line 44
    .line 45
    shl-int/lit8 p1, p1, 0x1

    .line 46
    .line 47
    add-int/lit8 p0, p0, -0x1

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_3
    and-int/lit16 v4, v1, 0x3ff

    .line 51
    .line 52
    or-int/2addr v4, v2

    .line 53
    and-int/lit16 v5, p1, 0x3ff

    .line 54
    .line 55
    or-int/2addr v2, v5

    .line 56
    mul-int/2addr v4, v2

    .line 57
    ushr-int/lit8 v2, v4, 0x15

    .line 58
    .line 59
    shr-int/lit8 v1, v1, 0xa

    .line 60
    .line 61
    shr-int/lit8 p1, p1, 0xa

    .line 62
    .line 63
    add-int/2addr v1, p1

    .line 64
    add-int/2addr v1, v2

    .line 65
    add-int/2addr v1, p0

    .line 66
    const/16 p0, 0x1d

    .line 67
    .line 68
    if-le v1, p0, :cond_4

    .line 69
    .line 70
    or-int/lit16 p0, v0, 0x7c00

    .line 71
    .line 72
    int-to-short p0, p0

    .line 73
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 74
    .line 75
    .line 76
    move-result p0

    .line 77
    return p0

    .line 78
    :cond_4
    const/16 p0, -0xb

    .line 79
    .line 80
    if-ge v1, p0, :cond_5

    .line 81
    .line 82
    int-to-short p0, v0

    .line 83
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    return p0

    .line 88
    :cond_5
    ushr-int p0, v4, v2

    .line 89
    .line 90
    and-int p1, v4, v2

    .line 91
    .line 92
    const/16 v2, 0x14

    .line 93
    .line 94
    invoke-static {v0, v1, p0, p1, v2}, Lcom/google/android/filament/utils/HalfKt;->access$fixedToHalf-yOCu0fQ(IIIII)S

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    return p0

    .line 99
    :cond_6
    :goto_2
    int-to-short p0, v0

    .line 100
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    return p0

    .line 105
    :cond_7
    :goto_3
    if-gt v1, v3, :cond_b

    .line 106
    .line 107
    if-le p1, v3, :cond_8

    .line 108
    .line 109
    goto :goto_4

    .line 110
    :cond_8
    if-ne v1, v3, :cond_9

    .line 111
    .line 112
    if-eqz p1, :cond_d

    .line 113
    .line 114
    :cond_9
    if-ne p1, v3, :cond_a

    .line 115
    .line 116
    if-nez v1, :cond_a

    .line 117
    .line 118
    goto :goto_6

    .line 119
    :cond_a
    or-int/lit16 v2, v0, 0x7c00

    .line 120
    .line 121
    goto :goto_6

    .line 122
    :cond_b
    :goto_4
    and-int/2addr p0, v2

    .line 123
    if-le p0, v3, :cond_c

    .line 124
    .line 125
    goto :goto_5

    .line 126
    :cond_c
    move v1, p1

    .line 127
    :goto_5
    or-int/lit16 v2, v1, 0x200

    .line 128
    .line 129
    :cond_d
    :goto_6
    int-to-short p0, v2

    .line 130
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 131
    .line 132
    .line 133
    move-result p0

    .line 134
    return p0
.end method

.method public static final toBits-impl(S)I
    .locals 1

    .line 1
    const v0, 0xffff

    .line 2
    .line 3
    .line 4
    and-int/2addr p0, v0

    .line 5
    return p0
.end method

.method public static final toByte-impl(S)B
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/HalfKt;->access$halfToShort-xj2QHRw(S)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    float-to-int p0, p0

    .line 6
    int-to-byte p0, p0

    .line 7
    return p0
.end method

.method public static final toDouble-impl(S)D
    .locals 2

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/HalfKt;->access$halfToShort-xj2QHRw(S)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    float-to-double v0, p0

    .line 6
    return-wide v0
.end method

.method public static final toFloat-impl(S)F
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/HalfKt;->access$halfToShort-xj2QHRw(S)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static final toHexString-impl(S)Ljava/lang/String;
    .locals 9

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    const v1, 0xffff

    .line 7
    .line 8
    .line 9
    and-int/2addr v1, p0

    .line 10
    ushr-int/lit8 v2, v1, 0xf

    .line 11
    .line 12
    ushr-int/lit8 v1, v1, 0xa

    .line 13
    .line 14
    const/16 v3, 0x1f

    .line 15
    .line 16
    and-int/2addr v1, v3

    .line 17
    and-int/lit16 p0, p0, 0x3ff

    .line 18
    .line 19
    const/16 v4, 0x2d

    .line 20
    .line 21
    const-string v5, "toString(...)"

    .line 22
    .line 23
    if-ne v1, v3, :cond_2

    .line 24
    .line 25
    if-nez p0, :cond_1

    .line 26
    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    :cond_0
    const-string p0, "Infinity"

    .line 33
    .line 34
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_1
    const-string p0, "NaN"

    .line 39
    .line 40
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_2
    const/4 v3, 0x1

    .line 45
    if-ne v2, v3, :cond_3

    .line 46
    .line 47
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    :cond_3
    const-string v2, "replaceFirst(...)"

    .line 51
    .line 52
    const-string v3, ""

    .line 53
    .line 54
    const-string v4, "compile(...)"

    .line 55
    .line 56
    const-string v6, "0{2,}$"

    .line 57
    .line 58
    const/16 v7, 0x10

    .line 59
    .line 60
    if-nez v1, :cond_5

    .line 61
    .line 62
    if-nez p0, :cond_4

    .line 63
    .line 64
    const-string p0, "0x0.0p0"

    .line 65
    .line 66
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_4
    const-string v1, "0x0."

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-static {v7}, Lry/a;->a(I)V

    .line 76
    .line 77
    .line 78
    invoke-static {p0, v7}, Ljava/lang/Integer;->toString(II)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-static {p0, v5, v6, v4, p0}, Lf2/m0;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/regex/Matcher;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-virtual {p0, v3}, Ljava/util/regex/Matcher;->replaceFirst(Ljava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    const-string p0, "p-14"

    .line 97
    .line 98
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    goto :goto_0

    .line 102
    :cond_5
    const-string v8, "0x1."

    .line 103
    .line 104
    invoke-virtual {v0, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 105
    .line 106
    .line 107
    invoke-static {v7}, Lry/a;->a(I)V

    .line 108
    .line 109
    .line 110
    invoke-static {p0, v7}, Ljava/lang/Integer;->toString(II)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    invoke-static {p0, v5, v6, v4, p0}, Lf2/m0;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/regex/Matcher;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-virtual {p0, v3}, Ljava/util/regex/Matcher;->replaceFirst(Ljava/lang/String;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const/16 p0, 0x70

    .line 129
    .line 130
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    add-int/lit8 v1, v1, -0xf

    .line 134
    .line 135
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    :goto_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    invoke-static {p0, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    return-object p0
.end method

.method public static final toInt-impl(S)I
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/HalfKt;->access$halfToShort-xj2QHRw(S)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    float-to-int p0, p0

    .line 6
    return p0
.end method

.method public static final toLong-impl(S)J
    .locals 2

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/HalfKt;->access$halfToShort-xj2QHRw(S)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    float-to-long v0, p0

    .line 6
    return-wide v0
.end method

.method public static final toShort-impl(S)S
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/HalfKt;->access$halfToShort-xj2QHRw(S)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    float-to-int p0, p0

    .line 6
    int-to-short p0, p0

    .line 7
    return p0
.end method

.method public static toString-impl(S)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->toFloat-impl(S)F

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static final unaryMinus-SjiOe_E(S)S
    .locals 1

    .line 1
    const v0, 0xffff

    .line 2
    .line 3
    .line 4
    and-int/2addr p0, v0

    .line 5
    const v0, 0x8000

    .line 6
    .line 7
    .line 8
    xor-int/2addr p0, v0

    .line 9
    int-to-short p0, p0

    .line 10
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method

.method public static final unaryPlus-SjiOe_E(S)S
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static final withSign-5SPjhV8(SS)S
    .locals 1

    .line 1
    const v0, 0x8000

    .line 2
    .line 3
    .line 4
    and-int/2addr p1, v0

    .line 5
    and-int/lit16 p0, p0, 0x7fff

    .line 6
    .line 7
    or-int/2addr p0, p1

    .line 8
    int-to-short p0, p0

    .line 9
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method


# virtual methods
.method public bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lcom/google/android/filament/utils/Half;

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/utils/Half;->unbox-impl()S

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {p0, p1}, Lcom/google/android/filament/utils/Half;->compareTo-FqSqZzs(S)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public compareTo-FqSqZzs(S)I
    .locals 0

    .line 2
    iget-short p0, p0, Lcom/google/android/filament/utils/Half;->v:S

    invoke-static {p0, p1}, Lcom/google/android/filament/utils/Half;->compareTo-FqSqZzs(SS)I

    move-result p0

    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-short p0, p0, Lcom/google/android/filament/utils/Half;->v:S

    .line 2
    .line 3
    invoke-static {p0, p1}, Lcom/google/android/filament/utils/Half;->equals-impl(SLjava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-short p0, p0, Lcom/google/android/filament/utils/Half;->v:S

    .line 2
    .line 3
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->hashCode-impl(S)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-short p0, p0, Lcom/google/android/filament/utils/Half;->v:S

    .line 2
    .line 3
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->toString-impl(S)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final synthetic unbox-impl()S
    .locals 0

    .line 1
    iget-short p0, p0, Lcom/google/android/filament/utils/Half;->v:S

    .line 2
    .line 3
    return p0
.end method
