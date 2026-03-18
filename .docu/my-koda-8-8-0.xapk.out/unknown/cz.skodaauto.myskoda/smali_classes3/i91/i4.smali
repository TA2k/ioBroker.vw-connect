.class public final synthetic Li91/i4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Ll2/b1;I)V
    .locals 0

    .line 1
    iput p3, p0, Li91/i4;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li91/i4;->e:Ll2/b1;

    .line 4
    .line 5
    iput-object p2, p0, Li91/i4;->f:Ll2/b1;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Li91/i4;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lg4/l0;

    .line 7
    .line 8
    const-string v0, "layoutResult"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p1, p1, Lg4/l0;->b:Lg4/o;

    .line 14
    .line 15
    iget v0, p1, Lg4/o;->f:I

    .line 16
    .line 17
    if-lez v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-virtual {p1, v0}, Lg4/o;->f(I)F

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    iget-object v2, p0, Li91/i4;->e:Ll2/b1;

    .line 29
    .line 30
    invoke-interface {v2, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p1, v0}, Lg4/o;->b(I)F

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    iget-object p0, p0, Li91/i4;->f:Ll2/b1;

    .line 42
    .line 43
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 47
    .line 48
    return-object p0

    .line 49
    :pswitch_0
    check-cast p1, Ljava/util/List;

    .line 50
    .line 51
    const-string v0, "it"

    .line 52
    .line 53
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object v0, p0, Li91/i4;->f:Ll2/b1;

    .line 57
    .line 58
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    check-cast v0, Lqe/a;

    .line 63
    .line 64
    iget-object p0, p0, Li91/i4;->e:Ll2/b1;

    .line 65
    .line 66
    invoke-static {p0, v0, p1}, Ljp/kf;->e(Ll2/b1;Lqe/a;Ljava/util/List;)V

    .line 67
    .line 68
    .line 69
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_1
    check-cast p1, Lxj0/b;

    .line 73
    .line 74
    const-string v0, "it"

    .line 75
    .line 76
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget-object v0, p0, Li91/i4;->e:Ll2/b1;

    .line 80
    .line 81
    invoke-interface {v0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget p1, p1, Lxj0/b;->b:F

    .line 85
    .line 86
    const/high16 v0, 0x41600000    # 14.0f

    .line 87
    .line 88
    cmpl-float p1, p1, v0

    .line 89
    .line 90
    if-ltz p1, :cond_1

    .line 91
    .line 92
    const/4 p1, 0x1

    .line 93
    goto :goto_1

    .line 94
    :cond_1
    const/4 p1, 0x0

    .line 95
    :goto_1
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    iget-object p0, p0, Li91/i4;->f:Ll2/b1;

    .line 100
    .line 101
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    goto :goto_0

    .line 105
    :pswitch_2
    check-cast p1, Lt3/y;

    .line 106
    .line 107
    const-string v0, "layoutCoordinates"

    .line 108
    .line 109
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    iget-object v0, p0, Li91/i4;->e:Ll2/b1;

    .line 113
    .line 114
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    check-cast v0, Ljava/lang/Boolean;

    .line 119
    .line 120
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 121
    .line 122
    .line 123
    move-result v0

    .line 124
    if-eqz v0, :cond_2

    .line 125
    .line 126
    const-wide/16 v0, 0x0

    .line 127
    .line 128
    invoke-interface {p1, v0, v1}, Lt3/y;->B(J)J

    .line 129
    .line 130
    .line 131
    move-result-wide v0

    .line 132
    new-instance p1, Ld3/b;

    .line 133
    .line 134
    invoke-direct {p1, v0, v1}, Ld3/b;-><init>(J)V

    .line 135
    .line 136
    .line 137
    iget-object p0, p0, Li91/i4;->f:Ll2/b1;

    .line 138
    .line 139
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 143
    .line 144
    return-object p0

    .line 145
    :pswitch_3
    check-cast p1, Lt4/l;

    .line 146
    .line 147
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 148
    .line 149
    iget-object v1, p0, Li91/i4;->f:Ll2/b1;

    .line 150
    .line 151
    invoke-interface {v1, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    iget-wide v0, p1, Lt4/l;->a:J

    .line 155
    .line 156
    const-wide v2, 0xffffffffL

    .line 157
    .line 158
    .line 159
    .line 160
    .line 161
    and-long/2addr v0, v2

    .line 162
    long-to-int p1, v0

    .line 163
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 164
    .line 165
    .line 166
    move-result-object p1

    .line 167
    iget-object p0, p0, Li91/i4;->e:Ll2/b1;

    .line 168
    .line 169
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    goto :goto_0

    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
