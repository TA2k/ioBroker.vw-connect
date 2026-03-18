.class public final synthetic Lry/j;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Lry/j;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lry/j;

    .line 2
    .line 3
    const-string v4, "toModel(Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationDto;)Lcz/skodaauto/myskoda/feature/activeventilation/model/ActiveVentilationStatus;"

    .line 4
    .line 5
    const/4 v5, 0x1

    .line 6
    const/4 v1, 0x1

    .line 7
    const-class v2, Lry/a;

    .line 8
    .line 9
    const-string v3, "toModel"

    .line 10
    .line 11
    invoke-direct/range {v0 .. v5}, Lkotlin/jvm/internal/k;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lry/j;->d:Lry/j;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    check-cast p1, Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationDto;

    .line 2
    .line 3
    const-string p0, "p0"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationDto;->getState()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const v1, -0x459172c3    # -9.1000256E-4f

    .line 17
    .line 18
    .line 19
    if-eq v0, v1, :cond_3

    .line 20
    .line 21
    const v1, 0x1314f

    .line 22
    .line 23
    .line 24
    if-eq v0, v1, :cond_2

    .line 25
    .line 26
    const v1, 0x2eca4fef    # 9.2000955E-11f

    .line 27
    .line 28
    .line 29
    if-eq v0, v1, :cond_0

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_0
    const-string v0, "PREHEATING"

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-nez p0, :cond_1

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    sget-object p0, Luy/a;->f:Luy/a;

    .line 42
    .line 43
    :goto_0
    move-object v2, p0

    .line 44
    goto :goto_2

    .line 45
    :cond_2
    const-string v0, "OFF"

    .line 46
    .line 47
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    if-eqz p0, :cond_4

    .line 52
    .line 53
    sget-object p0, Luy/a;->d:Luy/a;

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_3
    const-string v0, "VENTILATION"

    .line 57
    .line 58
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    if-nez p0, :cond_5

    .line 63
    .line 64
    :cond_4
    :goto_1
    sget-object p0, Luy/a;->g:Luy/a;

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_5
    sget-object p0, Luy/a;->e:Luy/a;

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :goto_2
    sget p0, Lmy0/c;->g:I

    .line 71
    .line 72
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationDto;->getDurationInSeconds()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    sget-object v0, Lmy0/e;->h:Lmy0/e;

    .line 77
    .line 78
    invoke-static {p0, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 79
    .line 80
    .line 81
    move-result-wide v3

    .line 82
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationDto;->getEstimatedDateTimeToReachTargetTemperature()Ljava/time/OffsetDateTime;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationDto;->getTimers()Ljava/util/List;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    check-cast p0, Ljava/lang/Iterable;

    .line 91
    .line 92
    new-instance v5, Ljava/util/ArrayList;

    .line 93
    .line 94
    const/16 v0, 0xa

    .line 95
    .line 96
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    invoke-direct {v5, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 101
    .line 102
    .line 103
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    if-eqz v0, :cond_6

    .line 112
    .line 113
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    check-cast v0, Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;

    .line 118
    .line 119
    invoke-static {v0}, Lwn0/c;->b(Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;)Lao0/c;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    invoke-virtual {v5, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    goto :goto_3

    .line 127
    :cond_6
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationDto;->getCarCapturedTimestamp()Ljava/time/OffsetDateTime;

    .line 128
    .line 129
    .line 130
    move-result-object v6

    .line 131
    invoke-virtual {p1}, Lcz/myskoda/api/bff_air_conditioning/v2/ActiveVentilationDto;->getOutsideTemperature()Lcz/myskoda/api/bff_air_conditioning/v2/OutsideTemperatureDto;

    .line 132
    .line 133
    .line 134
    move-result-object p0

    .line 135
    if-eqz p0, :cond_7

    .line 136
    .line 137
    invoke-static {p0}, Ljb0/t;->a(Lcz/myskoda/api/bff_air_conditioning/v2/OutsideTemperatureDto;)Lmb0/c;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    :goto_4
    move-object v7, p0

    .line 142
    goto :goto_5

    .line 143
    :cond_7
    const/4 p0, 0x0

    .line 144
    goto :goto_4

    .line 145
    :goto_5
    new-instance v0, Luy/b;

    .line 146
    .line 147
    invoke-direct/range {v0 .. v7}, Luy/b;-><init>(Ljava/time/OffsetDateTime;Luy/a;JLjava/util/ArrayList;Ljava/time/OffsetDateTime;Lmb0/c;)V

    .line 148
    .line 149
    .line 150
    return-object v0
.end method
