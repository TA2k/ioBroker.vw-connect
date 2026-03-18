.class public final synthetic Lc1/u1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(FLl2/b1;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lc1/u1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lc1/u1;->e:F

    iput-object p2, p0, Lc1/u1;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lc1/w1;F)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lc1/u1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc1/u1;->f:Ljava/lang/Object;

    iput p2, p0, Lc1/u1;->e:F

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lc1/u1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lc1/u1;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ll2/b1;

    .line 9
    .line 10
    check-cast p1, Lt3/y;

    .line 11
    .line 12
    const-string v1, "it"

    .line 13
    .line 14
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-static {p1}, Lt3/k1;->f(Lt3/y;)Ld3/c;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    iget v1, v1, Ld3/c;->d:F

    .line 22
    .line 23
    iget p0, p0, Lc1/u1;->e:F

    .line 24
    .line 25
    cmpg-float v1, v1, p0

    .line 26
    .line 27
    if-gez v1, :cond_0

    .line 28
    .line 29
    invoke-static {p1}, Lt3/k1;->f(Lt3/y;)Ld3/c;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-virtual {v1}, Ld3/c;->f()Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-nez v1, :cond_0

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_0
    invoke-static {p1}, Lt3/k1;->f(Lt3/y;)Ld3/c;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    iget v1, v1, Ld3/c;->d:F

    .line 45
    .line 46
    cmpl-float p0, v1, p0

    .line 47
    .line 48
    if-gez p0, :cond_2

    .line 49
    .line 50
    invoke-static {p1}, Lt3/k1;->f(Lt3/y;)Ld3/c;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {p0}, Ld3/c;->f()Z

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    if-eqz p0, :cond_1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_1
    const/4 p0, 0x0

    .line 62
    goto :goto_1

    .line 63
    :cond_2
    :goto_0
    const/4 p0, 0x1

    .line 64
    :goto_1
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-interface {v0, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    return-object p0

    .line 74
    :pswitch_0
    iget-object v0, p0, Lc1/u1;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v0, Lc1/w1;

    .line 77
    .line 78
    check-cast p1, Ljava/lang/Long;

    .line 79
    .line 80
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 81
    .line 82
    .line 83
    move-result-wide v1

    .line 84
    invoke-virtual {v0}, Lc1/w1;->g()Z

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    iget-object v3, v0, Lc1/w1;->g:Ll2/h1;

    .line 89
    .line 90
    if-nez p1, :cond_6

    .line 91
    .line 92
    iget-object p1, v3, Ll2/h1;->e:Ll2/l2;

    .line 93
    .line 94
    invoke-static {p1, v3}, Lv2/l;->t(Lv2/v;Lv2/t;)Lv2/v;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    check-cast p1, Ll2/l2;

    .line 99
    .line 100
    iget-wide v4, p1, Ll2/l2;->c:J

    .line 101
    .line 102
    const-wide/high16 v6, -0x8000000000000000L

    .line 103
    .line 104
    cmp-long p1, v4, v6

    .line 105
    .line 106
    if-nez p1, :cond_3

    .line 107
    .line 108
    invoke-virtual {v3, v1, v2}, Ll2/h1;->c(J)V

    .line 109
    .line 110
    .line 111
    iget-object p1, v0, Lc1/w1;->a:Lap0/o;

    .line 112
    .line 113
    iget-object p1, p1, Lap0/o;->e:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast p1, Ll2/j1;

    .line 116
    .line 117
    sget-object v4, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 118
    .line 119
    invoke-virtual {p1, v4}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    :cond_3
    iget-object p1, v3, Ll2/h1;->e:Ll2/l2;

    .line 123
    .line 124
    invoke-static {p1, v3}, Lv2/l;->t(Lv2/v;Lv2/t;)Lv2/v;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    check-cast p1, Ll2/l2;

    .line 129
    .line 130
    iget-wide v3, p1, Ll2/l2;->c:J

    .line 131
    .line 132
    sub-long/2addr v1, v3

    .line 133
    const/4 p1, 0x0

    .line 134
    iget p0, p0, Lc1/u1;->e:F

    .line 135
    .line 136
    cmpg-float p1, p0, p1

    .line 137
    .line 138
    if-nez p1, :cond_4

    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_4
    long-to-double v1, v1

    .line 142
    float-to-double v3, p0

    .line 143
    div-double/2addr v1, v3

    .line 144
    invoke-static {v1, v2}, Lcy0/a;->j(D)J

    .line 145
    .line 146
    .line 147
    move-result-wide v1

    .line 148
    :goto_3
    invoke-virtual {v0, v1, v2}, Lc1/w1;->n(J)V

    .line 149
    .line 150
    .line 151
    if-nez p1, :cond_5

    .line 152
    .line 153
    const/4 p0, 0x1

    .line 154
    goto :goto_4

    .line 155
    :cond_5
    const/4 p0, 0x0

    .line 156
    :goto_4
    invoke-virtual {v0, v1, v2, p0}, Lc1/w1;->h(JZ)V

    .line 157
    .line 158
    .line 159
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 160
    .line 161
    return-object p0

    .line 162
    nop

    .line 163
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
