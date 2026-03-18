.class public final Li70/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lxl0/f;

.field public final b:Lti0/a;


# direct methods
.method public constructor <init>(Lxl0/f;Lti0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li70/r;->a:Lxl0/f;

    .line 5
    .line 6
    iput-object p2, p0, Li70/r;->b:Lti0/a;

    .line 7
    .line 8
    return-void
.end method

.method public static a(Lne0/c;)Lne0/c;
    .locals 11

    .line 1
    iget-object v0, p0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 2
    .line 3
    instance-of v1, v0, Lbm0/d;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    check-cast v0, Lbm0/d;

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move-object v0, v2

    .line 12
    :goto_0
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iget-object v0, v0, Lbm0/d;->e:Lbm0/c;

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_1
    move-object v0, v2

    .line 18
    :goto_1
    if-eqz v0, :cond_2

    .line 19
    .line 20
    iget-object v2, v0, Lbm0/c;->a:Ljava/lang/String;

    .line 21
    .line 22
    :cond_2
    if-eqz v2, :cond_8

    .line 23
    .line 24
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    const v3, -0x6fc0d5f8

    .line 29
    .line 30
    .line 31
    const-string v4, "message"

    .line 32
    .line 33
    if-eq v1, v3, :cond_6

    .line 34
    .line 35
    const v3, 0x1caa205

    .line 36
    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    const v3, 0x4c18c123    # 4.004366E7f

    .line 41
    .line 42
    .line 43
    if-eq v1, v3, :cond_3

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_3
    const-string v1, "PRICE_PER_UNIT_FORMAT_ERROR"

    .line 47
    .line 48
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    if-nez v1, :cond_4

    .line 53
    .line 54
    goto :goto_2

    .line 55
    :cond_4
    new-instance v5, Lne0/c;

    .line 56
    .line 57
    new-instance v6, Ll70/g;

    .line 58
    .line 59
    iget-object p0, v0, Lbm0/c;->b:Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {p0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-direct {v6, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    const/4 v9, 0x0

    .line 68
    const/16 v10, 0x1e

    .line 69
    .line 70
    const/4 v7, 0x0

    .line 71
    const/4 v8, 0x0

    .line 72
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 73
    .line 74
    .line 75
    return-object v5

    .line 76
    :cond_5
    const-string v1, "VALID_FROM_DATE_OUT_OF_RANGE"

    .line 77
    .line 78
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_8

    .line 83
    .line 84
    new-instance v5, Lne0/c;

    .line 85
    .line 86
    new-instance v6, Ll70/f;

    .line 87
    .line 88
    iget-object p0, v0, Lbm0/c;->b:Ljava/lang/String;

    .line 89
    .line 90
    invoke-static {p0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-direct {v6, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    const/4 v9, 0x0

    .line 97
    const/16 v10, 0x1e

    .line 98
    .line 99
    const/4 v7, 0x0

    .line 100
    const/4 v8, 0x0

    .line 101
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 102
    .line 103
    .line 104
    return-object v5

    .line 105
    :cond_6
    const-string v1, "FUEL_PRICE_ALREADY_EXISTS_TO_THIS_DATE"

    .line 106
    .line 107
    invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-nez v1, :cond_7

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_7
    new-instance v5, Lne0/c;

    .line 115
    .line 116
    new-instance v6, Ll70/e;

    .line 117
    .line 118
    iget-object p0, v0, Lbm0/c;->b:Ljava/lang/String;

    .line 119
    .line 120
    invoke-static {p0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    invoke-direct {v6, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    const/4 v9, 0x0

    .line 127
    const/16 v10, 0x1e

    .line 128
    .line 129
    const/4 v7, 0x0

    .line 130
    const/4 v8, 0x0

    .line 131
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 132
    .line 133
    .line 134
    return-object v5

    .line 135
    :cond_8
    :goto_2
    return-object p0
.end method
