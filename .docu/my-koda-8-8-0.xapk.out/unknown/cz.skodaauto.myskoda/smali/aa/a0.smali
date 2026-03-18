.class public final synthetic Laa/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/t2;


# direct methods
.method public synthetic constructor <init>(Ll2/t2;I)V
    .locals 0

    .line 1
    iput p2, p0, Laa/a0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Laa/a0;->e:Ll2/t2;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Laa/a0;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    const/4 v3, 0x0

    .line 6
    iget-object p0, p0, Laa/a0;->e:Ll2/t2;

    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    sget v0, Lzj0/j;->b:F

    .line 12
    .line 13
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lcom/google/android/gms/maps/model/CameraPosition;

    .line 18
    .line 19
    return-object p0

    .line 20
    :pswitch_0
    invoke-static {p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/compose/RPAScreenKt;->f(Ll2/t2;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_1
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const-string v0, "VideoPlayer: LifecycleEffect - Resumed (restart playback="

    .line 30
    .line 31
    const-string v1, ")"

    .line 32
    .line 33
    invoke-static {p0, v0, v1}, Lf2/m0;->g(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0

    .line 38
    :pswitch_2
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, Ljava/lang/Number;

    .line 43
    .line 44
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    cmpl-float p0, p0, v3

    .line 49
    .line 50
    if-lez p0, :cond_0

    .line 51
    .line 52
    move v1, v2

    .line 53
    :cond_0
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :pswitch_3
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    check-cast p0, Ljava/lang/Number;

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    cmpl-float p0, p0, v3

    .line 69
    .line 70
    if-lez p0, :cond_1

    .line 71
    .line 72
    move v1, v2

    .line 73
    :cond_1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    :pswitch_4
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Ljava/lang/Number;

    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0

    .line 93
    :pswitch_5
    sget-object v0, Le2/g0;->a:Lc1/m;

    .line 94
    .line 95
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Ld3/b;

    .line 100
    .line 101
    iget-wide v0, p0, Ld3/b;->a:J

    .line 102
    .line 103
    new-instance p0, Ld3/b;

    .line 104
    .line 105
    invoke-direct {p0, v0, v1}, Ld3/b;-><init>(J)V

    .line 106
    .line 107
    .line 108
    return-object p0

    .line 109
    :pswitch_6
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    check-cast p0, Ld3/b;

    .line 114
    .line 115
    iget-wide v0, p0, Ld3/b;->a:J

    .line 116
    .line 117
    new-instance p0, Ld3/b;

    .line 118
    .line 119
    invoke-direct {p0, v0, v1}, Ld3/b;-><init>(J)V

    .line 120
    .line 121
    .line 122
    return-object p0

    .line 123
    :pswitch_7
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    check-cast p0, Ljava/util/List;

    .line 128
    .line 129
    check-cast p0, Ljava/lang/Iterable;

    .line 130
    .line 131
    new-instance v0, Ljava/util/ArrayList;

    .line 132
    .line 133
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 134
    .line 135
    .line 136
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    :cond_2
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 141
    .line 142
    .line 143
    move-result v1

    .line 144
    if-eqz v1, :cond_3

    .line 145
    .line 146
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    move-object v2, v1

    .line 151
    check-cast v2, Lz9/k;

    .line 152
    .line 153
    iget-object v2, v2, Lz9/k;->e:Lz9/u;

    .line 154
    .line 155
    iget-object v2, v2, Lz9/u;->d:Ljava/lang/String;

    .line 156
    .line 157
    const-string v3, "composable"

    .line 158
    .line 159
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v2

    .line 163
    if-eqz v2, :cond_2

    .line 164
    .line 165
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    goto :goto_0

    .line 169
    :cond_3
    return-object v0

    .line 170
    nop

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
