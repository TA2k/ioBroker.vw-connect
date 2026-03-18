.class public final Lf2/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le3/t;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lf2/t;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf2/t;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()J
    .locals 6

    .line 1
    iget v0, p0, Lf2/t;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lf2/t;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lh2/x7;

    .line 9
    .line 10
    iget-wide v0, p0, Lh2/x7;->c:J

    .line 11
    .line 12
    return-wide v0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lf2/t;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lf2/u;

    .line 16
    .line 17
    iget-object v0, p0, Lf2/u;->x:Le3/t;

    .line 18
    .line 19
    invoke-interface {v0}, Le3/t;->a()J

    .line 20
    .line 21
    .line 22
    move-result-wide v0

    .line 23
    const-wide/16 v2, 0x10

    .line 24
    .line 25
    cmp-long v4, v0, v2

    .line 26
    .line 27
    if-eqz v4, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    sget-object v0, Lh2/w7;->a:Ll2/e0;

    .line 31
    .line 32
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    check-cast v0, Lh2/v7;

    .line 37
    .line 38
    if-eqz v0, :cond_1

    .line 39
    .line 40
    iget-wide v0, v0, Lh2/v7;->a:J

    .line 41
    .line 42
    cmp-long v2, v0, v2

    .line 43
    .line 44
    if-eqz v2, :cond_1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    sget-object v0, Lh2/p1;->a:Ll2/e0;

    .line 48
    .line 49
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Le3/s;

    .line 54
    .line 55
    iget-wide v0, p0, Le3/s;->a:J

    .line 56
    .line 57
    :goto_0
    return-wide v0

    .line 58
    :pswitch_1
    iget-object p0, p0, Lf2/t;->e:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast p0, Lf2/j0;

    .line 61
    .line 62
    iget-wide v0, p0, Lf2/j0;->b:J

    .line 63
    .line 64
    return-wide v0

    .line 65
    :pswitch_2
    iget-object p0, p0, Lf2/t;->e:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast p0, Lf2/u;

    .line 68
    .line 69
    iget-object v0, p0, Lf2/u;->x:Le3/t;

    .line 70
    .line 71
    invoke-interface {v0}, Le3/t;->a()J

    .line 72
    .line 73
    .line 74
    move-result-wide v0

    .line 75
    const-wide/16 v2, 0x10

    .line 76
    .line 77
    cmp-long v4, v0, v2

    .line 78
    .line 79
    if-eqz v4, :cond_2

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_2
    sget-object v0, Lf2/i0;->a:Ll2/e0;

    .line 83
    .line 84
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    check-cast v0, Lf2/g0;

    .line 89
    .line 90
    if-eqz v0, :cond_3

    .line 91
    .line 92
    iget-wide v0, v0, Lf2/g0;->a:J

    .line 93
    .line 94
    cmp-long v2, v0, v2

    .line 95
    .line 96
    if-eqz v2, :cond_3

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_3
    sget-object v0, Lf2/k;->a:Ll2/e0;

    .line 100
    .line 101
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    check-cast v0, Le3/s;

    .line 106
    .line 107
    iget-wide v0, v0, Le3/s;->a:J

    .line 108
    .line 109
    sget-object v2, Lf2/h;->a:Ll2/u2;

    .line 110
    .line 111
    invoke-static {p0, v2}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    check-cast p0, Lf2/g;

    .line 116
    .line 117
    invoke-virtual {p0}, Lf2/g;->d()Z

    .line 118
    .line 119
    .line 120
    move-result p0

    .line 121
    invoke-static {v0, v1}, Le3/j0;->r(J)F

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    if-nez p0, :cond_4

    .line 126
    .line 127
    float-to-double v2, v2

    .line 128
    const-wide/high16 v4, 0x3fe0000000000000L    # 0.5

    .line 129
    .line 130
    cmpg-double p0, v2, v4

    .line 131
    .line 132
    if-gez p0, :cond_4

    .line 133
    .line 134
    sget-wide v0, Le3/s;->e:J

    .line 135
    .line 136
    :cond_4
    :goto_1
    return-wide v0

    .line 137
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
