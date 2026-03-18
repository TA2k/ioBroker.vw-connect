.class public final Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;
.super Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LiteralValue;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "LongValue"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LiteralValue<",
        "Ljava/lang/Long;",
        ">;"
    }
.end annotation


# instance fields
.field private final value:J


# direct methods
.method public constructor <init>(J)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LiteralValue;-><init>(Lkotlin/jvm/internal/g;)V

    .line 3
    .line 4
    .line 5
    iput-wide p1, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;->value:J

    .line 6
    .line 7
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
    instance-of v1, p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;

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
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;

    .line 12
    .line 13
    iget-wide v3, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;->value:J

    .line 14
    .line 15
    iget-wide p0, p1, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;->value:J

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

.method public getValue()Ljava/lang/Long;
    .locals 2

    .line 1
    iget-wide v0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;->value:J

    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic getValue()Ljava/lang/Object;
    .locals 0

    .line 2
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;->getValue()Ljava/lang/Long;

    move-result-object p0

    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument$LongValue;->value:J

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
