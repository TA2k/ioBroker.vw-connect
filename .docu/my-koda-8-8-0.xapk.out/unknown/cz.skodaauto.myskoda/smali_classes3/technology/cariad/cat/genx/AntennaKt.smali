.class public final Ltechnology/cariad/cat/genx/AntennaKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/AntennaKt$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\"\u0018\u0010\u0000\u001a\u00020\u0001*\u00020\u00028@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0003\u0010\u0004\"\u0018\u0010\u0005\u001a\u00020\u0006*\u00020\u00018@X\u0080\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0007\u0010\u0008\u00a8\u0006\t"
    }
    d2 = {
        "antenna",
        "Ltechnology/cariad/cat/genx/Antenna;",
        "",
        "getAntenna",
        "(I)Ltechnology/cariad/cat/genx/Antenna;",
        "cgxAntenna",
        "Ltechnology/cariad/cat/genx/CGXAntenna;",
        "getCgxAntenna",
        "(Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/CGXAntenna;",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final getAntenna(I)Ltechnology/cariad/cat/genx/Antenna;
    .locals 3

    .line 1
    sget-object v0, Ltechnology/cariad/cat/genx/CGXAntenna;->CGXAntennaInner:Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CGXAntenna;->getRawValue()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-ne p0, v0, :cond_0

    .line 8
    .line 9
    sget-object p0, Ltechnology/cariad/cat/genx/Antenna;->INNER:Ltechnology/cariad/cat/genx/Antenna;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object v0, Ltechnology/cariad/cat/genx/CGXAntenna;->CGXAntennaOuter:Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 13
    .line 14
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CGXAntenna;->getRawValue()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-ne p0, v0, :cond_1

    .line 19
    .line 20
    sget-object p0, Ltechnology/cariad/cat/genx/Antenna;->OUTER:Ltechnology/cariad/cat/genx/Antenna;

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    const-string v1, "Cannot map "

    .line 26
    .line 27
    const-string v2, " to a Vehicle.Antenna"

    .line 28
    .line 29
    invoke-static {v1, p0, v2}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw v0
.end method

.method public static final getCgxAntenna(Ltechnology/cariad/cat/genx/Antenna;)Ltechnology/cariad/cat/genx/CGXAntenna;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ltechnology/cariad/cat/genx/AntennaKt$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    aget p0, v0, p0

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    if-eq p0, v0, :cond_1

    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    if-ne p0, v0, :cond_0

    .line 19
    .line 20
    sget-object p0, Ltechnology/cariad/cat/genx/CGXAntenna;->CGXAntennaOuter:Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_0
    new-instance p0, La8/r0;

    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    sget-object p0, Ltechnology/cariad/cat/genx/CGXAntenna;->CGXAntennaInner:Ltechnology/cariad/cat/genx/CGXAntenna;

    .line 30
    .line 31
    return-object p0
.end method
