.class public final Ljn/h;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:F


# direct methods
.method public synthetic constructor <init>(IF)V
    .locals 0

    .line 1
    iput p1, p0, Ljn/h;->f:I

    .line 2
    .line 3
    iput p2, p0, Ljn/h;->g:F

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Ljn/h;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lt4/c;

    .line 7
    .line 8
    const-string v0, "$this$offset"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget p0, p0, Ljn/h;->g:F

    .line 14
    .line 15
    invoke-static {p0}, Lcy0/a;->i(F)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    const/4 p1, 0x0

    .line 20
    invoke-static {p1, p0}, Lkp/d9;->a(II)J

    .line 21
    .line 22
    .line 23
    move-result-wide p0

    .line 24
    new-instance v0, Lt4/j;

    .line 25
    .line 26
    invoke-direct {v0, p0, p1}, Lt4/j;-><init>(J)V

    .line 27
    .line 28
    .line 29
    return-object v0

    .line 30
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    iget p0, p0, Ljn/h;->g:F

    .line 37
    .line 38
    rem-float v0, p1, p0

    .line 39
    .line 40
    neg-float v1, p0

    .line 41
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    const/4 v2, 0x0

    .line 46
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    filled-new-array {v1, v2, v3}, [Ljava/lang/Float;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    check-cast v1, Ljava/lang/Iterable;

    .line 63
    .line 64
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-nez v2, :cond_0

    .line 73
    .line 74
    const/4 v0, 0x0

    .line 75
    goto :goto_1

    .line 76
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v2

    .line 80
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    if-nez v3, :cond_1

    .line 85
    .line 86
    :goto_0
    move-object v0, v2

    .line 87
    goto :goto_1

    .line 88
    :cond_1
    move-object v3, v2

    .line 89
    check-cast v3, Ljava/lang/Number;

    .line 90
    .line 91
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    sub-float/2addr v3, v0

    .line 96
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    :cond_2
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    move-object v5, v4

    .line 105
    check-cast v5, Ljava/lang/Number;

    .line 106
    .line 107
    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    .line 108
    .line 109
    .line 110
    move-result v5

    .line 111
    sub-float/2addr v5, v0

    .line 112
    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    .line 113
    .line 114
    .line 115
    move-result v5

    .line 116
    invoke-static {v3, v5}, Ljava/lang/Float;->compare(FF)I

    .line 117
    .line 118
    .line 119
    move-result v6

    .line 120
    if-lez v6, :cond_3

    .line 121
    .line 122
    move-object v2, v4

    .line 123
    move v3, v5

    .line 124
    :cond_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 125
    .line 126
    .line 127
    move-result v4

    .line 128
    if-nez v4, :cond_2

    .line 129
    .line 130
    goto :goto_0

    .line 131
    :goto_1
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    check-cast v0, Ljava/lang/Number;

    .line 135
    .line 136
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 137
    .line 138
    .line 139
    move-result v0

    .line 140
    div-float/2addr p1, p0

    .line 141
    float-to-int p1, p1

    .line 142
    int-to-float p1, p1

    .line 143
    mul-float/2addr p0, p1

    .line 144
    add-float/2addr p0, v0

    .line 145
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    return-object p0

    .line 150
    nop

    .line 151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
