.class public final Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;
.super Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LiteralValue;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "UShortValue"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LiteralValue<",
        "Llx0/z;",
        ">;"
    }
.end annotation


# instance fields
.field private final value:S


# direct methods
.method private constructor <init>(S)V
    .locals 1

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LiteralValue;-><init>(Lkotlin/jvm/internal/g;)V

    iput-short p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;->value:S

    return-void
.end method

.method public synthetic constructor <init>(SLkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;-><init>(S)V

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
    instance-of v1, p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;

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
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;

    .line 12
    .line 13
    iget-short p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;->value:S

    .line 14
    .line 15
    iget-short p1, p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;->value:S

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

.method public synthetic getValue()Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;->getValue-Mh2AYeg()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    new-instance v0, Llx0/z;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Llx0/z;-><init>(S)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public getValue-Mh2AYeg()S
    .locals 0

    .line 1
    iget-short p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;->value:S

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-short p0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$UShortValue;->value:S

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Short;->hashCode(S)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
