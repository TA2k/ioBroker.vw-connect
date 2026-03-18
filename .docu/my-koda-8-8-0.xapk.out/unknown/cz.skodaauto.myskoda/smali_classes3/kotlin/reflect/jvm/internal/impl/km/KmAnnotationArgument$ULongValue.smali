.class public final Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;
.super Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LiteralValue;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ULongValue"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LiteralValue<",
        "Llx0/w;",
        ">;"
    }
.end annotation


# instance fields
.field private final value:J


# direct methods
.method private constructor <init>(J)V
    .locals 1

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LiteralValue;-><init>(Lkotlin/jvm/internal/g;)V

    iput-wide p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;->value:J

    return-void
.end method

.method public synthetic constructor <init>(JLkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;-><init>(J)V

    return-void
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;

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
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;

    .line 12
    .line 13
    iget-wide v3, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;->value:J

    .line 14
    .line 15
    iget-wide p0, p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;->value:J

    .line 16
    .line 17
    cmp-long p0, v3, p0

    .line 18
    .line 19
    if-eqz p0, :cond_2

    .line 20
    .line 21
    return v2

    .line 22
    :cond_2
    return v0
.end method

.method public synthetic getValue()Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;->getValue-s-VKNKU()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    new-instance p0, Llx0/w;

    .line 6
    .line 7
    invoke-direct {p0, v0, v1}, Llx0/w;-><init>(J)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public getValue-s-VKNKU()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;->value:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$ULongValue;->value:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
