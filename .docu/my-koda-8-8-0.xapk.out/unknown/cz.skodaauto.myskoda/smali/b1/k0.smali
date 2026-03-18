.class public final Lb1/k0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lb1/t0;

.field public final synthetic h:Lb1/u0;


# direct methods
.method public synthetic constructor <init>(Lb1/t0;Lb1/u0;I)V
    .locals 0

    .line 1
    iput p3, p0, Lb1/k0;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lb1/k0;->g:Lb1/t0;

    .line 4
    .line 5
    iput-object p2, p0, Lb1/k0;->h:Lb1/u0;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lb1/k0;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lb1/i0;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    if-eq p1, v0, :cond_1

    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    if-ne p1, v0, :cond_0

    .line 19
    .line 20
    iget-object p0, p0, Lb1/k0;->h:Lb1/u0;

    .line 21
    .line 22
    iget-object p0, p0, Lb1/u0;->a:Lb1/i1;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, La8/r0;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    :goto_0
    const/high16 p0, 0x3f800000    # 1.0f

    .line 32
    .line 33
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0

    .line 38
    :pswitch_0
    check-cast p1, Lc1/r1;

    .line 39
    .line 40
    sget-object v0, Lb1/i0;->d:Lb1/i0;

    .line 41
    .line 42
    sget-object v1, Lb1/i0;->e:Lb1/i0;

    .line 43
    .line 44
    invoke-interface {p1, v0, v1}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_2

    .line 49
    .line 50
    sget-object p0, Lb1/o0;->b:Lc1/f1;

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    sget-object v0, Lb1/i0;->f:Lb1/i0;

    .line 54
    .line 55
    invoke-interface {p1, v1, v0}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    if-eqz p1, :cond_3

    .line 60
    .line 61
    iget-object p0, p0, Lb1/k0;->h:Lb1/u0;

    .line 62
    .line 63
    iget-object p0, p0, Lb1/u0;->a:Lb1/i1;

    .line 64
    .line 65
    sget-object p0, Lb1/o0;->b:Lc1/f1;

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_3
    sget-object p0, Lb1/o0;->b:Lc1/f1;

    .line 69
    .line 70
    :goto_1
    return-object p0

    .line 71
    :pswitch_1
    check-cast p1, Lb1/i0;

    .line 72
    .line 73
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 74
    .line 75
    .line 76
    move-result p1

    .line 77
    const/high16 v0, 0x3f800000    # 1.0f

    .line 78
    .line 79
    if-eqz p1, :cond_5

    .line 80
    .line 81
    const/4 v1, 0x1

    .line 82
    if-eq p1, v1, :cond_6

    .line 83
    .line 84
    const/4 v1, 0x2

    .line 85
    if-ne p1, v1, :cond_4

    .line 86
    .line 87
    iget-object p0, p0, Lb1/k0;->h:Lb1/u0;

    .line 88
    .line 89
    iget-object p0, p0, Lb1/u0;->a:Lb1/i1;

    .line 90
    .line 91
    iget-object p0, p0, Lb1/i1;->a:Lb1/v0;

    .line 92
    .line 93
    if-eqz p0, :cond_6

    .line 94
    .line 95
    iget v0, p0, Lb1/v0;->a:F

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_4
    new-instance p0, La8/r0;

    .line 99
    .line 100
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 101
    .line 102
    .line 103
    throw p0

    .line 104
    :cond_5
    iget-object p0, p0, Lb1/k0;->g:Lb1/t0;

    .line 105
    .line 106
    iget-object p0, p0, Lb1/t0;->a:Lb1/i1;

    .line 107
    .line 108
    iget-object p0, p0, Lb1/i1;->a:Lb1/v0;

    .line 109
    .line 110
    if-eqz p0, :cond_6

    .line 111
    .line 112
    iget v0, p0, Lb1/v0;->a:F

    .line 113
    .line 114
    :cond_6
    :goto_2
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0

    .line 119
    :pswitch_2
    check-cast p1, Lc1/r1;

    .line 120
    .line 121
    sget-object v0, Lb1/i0;->d:Lb1/i0;

    .line 122
    .line 123
    sget-object v1, Lb1/i0;->e:Lb1/i0;

    .line 124
    .line 125
    invoke-interface {p1, v0, v1}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    if-eqz v0, :cond_8

    .line 130
    .line 131
    iget-object p0, p0, Lb1/k0;->g:Lb1/t0;

    .line 132
    .line 133
    iget-object p0, p0, Lb1/t0;->a:Lb1/i1;

    .line 134
    .line 135
    iget-object p0, p0, Lb1/i1;->a:Lb1/v0;

    .line 136
    .line 137
    if-eqz p0, :cond_7

    .line 138
    .line 139
    iget-object p0, p0, Lb1/v0;->b:Lc1/a0;

    .line 140
    .line 141
    if-nez p0, :cond_b

    .line 142
    .line 143
    :cond_7
    sget-object p0, Lb1/o0;->b:Lc1/f1;

    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_8
    sget-object v0, Lb1/i0;->f:Lb1/i0;

    .line 147
    .line 148
    invoke-interface {p1, v1, v0}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result p1

    .line 152
    if-eqz p1, :cond_a

    .line 153
    .line 154
    iget-object p0, p0, Lb1/k0;->h:Lb1/u0;

    .line 155
    .line 156
    iget-object p0, p0, Lb1/u0;->a:Lb1/i1;

    .line 157
    .line 158
    iget-object p0, p0, Lb1/i1;->a:Lb1/v0;

    .line 159
    .line 160
    if-eqz p0, :cond_9

    .line 161
    .line 162
    iget-object p0, p0, Lb1/v0;->b:Lc1/a0;

    .line 163
    .line 164
    if-nez p0, :cond_b

    .line 165
    .line 166
    :cond_9
    sget-object p0, Lb1/o0;->b:Lc1/f1;

    .line 167
    .line 168
    goto :goto_3

    .line 169
    :cond_a
    sget-object p0, Lb1/o0;->b:Lc1/f1;

    .line 170
    .line 171
    :cond_b
    :goto_3
    return-object p0

    .line 172
    nop

    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
