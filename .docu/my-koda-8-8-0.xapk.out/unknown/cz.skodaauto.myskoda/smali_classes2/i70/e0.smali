.class public abstract Li70/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lcz/myskoda/api/bff/v1/CostDetailsDto;)Ll70/t;
    .locals 5

    .line 1
    new-instance v0, Ljava/math/BigDecimal;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CostDetailsDto;->getCost()D

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-direct {v0, v1, v2}, Ljava/math/BigDecimal;-><init>(D)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CostDetailsDto;->getCostCurrency()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    new-instance v2, Ljava/math/BigDecimal;

    .line 15
    .line 16
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/CostDetailsDto;->getPricePerUnit()F

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    float-to-double v3, p0

    .line 21
    invoke-direct {v2, v3, v4}, Ljava/math/BigDecimal;-><init>(D)V

    .line 22
    .line 23
    .line 24
    new-instance p0, Ll70/t;

    .line 25
    .line 26
    invoke-direct {p0, v0, v1, v2}, Ll70/t;-><init>(Ljava/math/BigDecimal;Ljava/lang/String;Ljava/math/BigDecimal;)V

    .line 27
    .line 28
    .line 29
    return-object p0
.end method

.method public static final b(Lcz/myskoda/api/bff/v1/FuelCostDto;)Ll70/u;
    .locals 7

    .line 1
    new-instance v0, Ll70/u;

    .line 2
    .line 3
    new-instance v1, Ljava/math/BigDecimal;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/FuelCostDto;->getTotalCost()Ljava/lang/Double;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 12
    .line 13
    .line 14
    move-result-wide v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const-wide/16 v2, 0x0

    .line 17
    .line 18
    :goto_0
    invoke-direct {v1, v2, v3}, Ljava/math/BigDecimal;-><init>(D)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/FuelCostDto;->getTotalCostCurrency()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    if-nez v2, :cond_1

    .line 26
    .line 27
    const-string v2, ""

    .line 28
    .line 29
    :cond_1
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/FuelCostDto;->getFuelCost()Lcz/myskoda/api/bff/v1/CostDetailsDto;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    const/4 v4, 0x0

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    invoke-static {v3}, Li70/e0;->a(Lcz/myskoda/api/bff/v1/CostDetailsDto;)Ll70/t;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    goto :goto_1

    .line 41
    :cond_2
    move-object v3, v4

    .line 42
    :goto_1
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/FuelCostDto;->getCngCost()Lcz/myskoda/api/bff/v1/CostDetailsDto;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    if-eqz v5, :cond_3

    .line 47
    .line 48
    invoke-static {v5}, Li70/e0;->a(Lcz/myskoda/api/bff/v1/CostDetailsDto;)Ll70/t;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    goto :goto_2

    .line 53
    :cond_3
    move-object v5, v4

    .line 54
    :goto_2
    invoke-virtual {p0}, Lcz/myskoda/api/bff/v1/FuelCostDto;->getElectricityCost()Lcz/myskoda/api/bff/v1/CostDetailsDto;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    if-eqz p0, :cond_4

    .line 59
    .line 60
    invoke-static {p0}, Li70/e0;->a(Lcz/myskoda/api/bff/v1/CostDetailsDto;)Ll70/t;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    :cond_4
    move-object v6, v5

    .line 65
    move-object v5, v4

    .line 66
    move-object v4, v6

    .line 67
    invoke-direct/range {v0 .. v5}, Ll70/u;-><init>(Ljava/math/BigDecimal;Ljava/lang/String;Ll70/t;Ll70/t;Ll70/t;)V

    .line 68
    .line 69
    .line 70
    return-object v0
.end method

.method public static final c(Lcz/myskoda/api/bff/v1/VehicleTypeDto;)Ll70/a0;
    .locals 2

    .line 1
    const/4 v0, -0x1

    .line 2
    if-nez p0, :cond_0

    .line 3
    .line 4
    move p0, v0

    .line 5
    goto :goto_0

    .line 6
    :cond_0
    sget-object v1, Li70/d0;->a:[I

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    aget p0, v1, p0

    .line 13
    .line 14
    :goto_0
    if-eq p0, v0, :cond_6

    .line 15
    .line 16
    const/4 v0, 0x1

    .line 17
    if-eq p0, v0, :cond_5

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    if-eq p0, v0, :cond_4

    .line 21
    .line 22
    const/4 v0, 0x3

    .line 23
    if-eq p0, v0, :cond_3

    .line 24
    .line 25
    const/4 v0, 0x4

    .line 26
    if-eq p0, v0, :cond_2

    .line 27
    .line 28
    const/4 v0, 0x5

    .line 29
    if-ne p0, v0, :cond_1

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    new-instance p0, La8/r0;

    .line 33
    .line 34
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_2
    sget-object p0, Ll70/a0;->e:Ll70/a0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :cond_3
    sget-object p0, Ll70/a0;->f:Ll70/a0;

    .line 42
    .line 43
    return-object p0

    .line 44
    :cond_4
    sget-object p0, Ll70/a0;->g:Ll70/a0;

    .line 45
    .line 46
    return-object p0

    .line 47
    :cond_5
    sget-object p0, Ll70/a0;->d:Ll70/a0;

    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_6
    :goto_1
    sget-object p0, Ll70/a0;->h:Ll70/a0;

    .line 51
    .line 52
    return-object p0
.end method
