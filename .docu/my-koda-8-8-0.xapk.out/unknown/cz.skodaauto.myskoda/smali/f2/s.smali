.class public final synthetic Lf2/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lf2/u;


# direct methods
.method public synthetic constructor <init>(Lf2/u;I)V
    .locals 0

    .line 1
    iput p2, p0, Lf2/s;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf2/s;->e:Lf2/u;

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
    .locals 7

    .line 1
    iget v0, p0, Lf2/s;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lf2/s;->e:Lf2/u;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v0, Lf2/i0;->a:Ll2/e0;

    .line 9
    .line 10
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lf2/g0;

    .line 15
    .line 16
    sget-object v0, Lf2/k;->a:Ll2/e0;

    .line 17
    .line 18
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    check-cast v0, Le3/s;

    .line 23
    .line 24
    iget-wide v0, v0, Le3/s;->a:J

    .line 25
    .line 26
    sget-object v2, Lf2/h;->a:Ll2/u2;

    .line 27
    .line 28
    invoke-static {p0, v2}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    check-cast p0, Lf2/g;

    .line 33
    .line 34
    invoke-virtual {p0}, Lf2/g;->d()Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-eqz p0, :cond_1

    .line 39
    .line 40
    invoke-static {v0, v1}, Le3/j0;->r(J)F

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    float-to-double v0, p0

    .line 45
    const-wide/high16 v2, 0x3fe0000000000000L    # 0.5

    .line 46
    .line 47
    cmpl-double p0, v0, v2

    .line 48
    .line 49
    if-lez p0, :cond_0

    .line 50
    .line 51
    sget-object p0, Lf2/i0;->c:Lg2/b;

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    sget-object p0, Lf2/i0;->d:Lg2/b;

    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_1
    sget-object p0, Lf2/i0;->e:Lg2/b;

    .line 58
    .line 59
    :goto_0
    return-object p0

    .line 60
    :pswitch_0
    sget-object v0, Lf2/i0;->a:Ll2/e0;

    .line 61
    .line 62
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    check-cast v0, Lf2/g0;

    .line 67
    .line 68
    if-nez v0, :cond_3

    .line 69
    .line 70
    iget-object v0, p0, Lf2/u;->y:Lg2/a;

    .line 71
    .line 72
    if-eqz v0, :cond_2

    .line 73
    .line 74
    invoke-virtual {p0, v0}, Lv3/n;->Y0(Lv3/m;)V

    .line 75
    .line 76
    .line 77
    :cond_2
    const/4 v0, 0x0

    .line 78
    iput-object v0, p0, Lf2/u;->y:Lg2/a;

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_3
    iget-object v0, p0, Lf2/u;->y:Lg2/a;

    .line 82
    .line 83
    if-nez v0, :cond_4

    .line 84
    .line 85
    new-instance v5, Lf2/t;

    .line 86
    .line 87
    const/4 v0, 0x0

    .line 88
    invoke-direct {v5, p0, v0}, Lf2/t;-><init>(Ljava/lang/Object;I)V

    .line 89
    .line 90
    .line 91
    new-instance v6, Lf2/s;

    .line 92
    .line 93
    const/4 v0, 0x1

    .line 94
    invoke-direct {v6, p0, v0}, Lf2/s;-><init>(Lf2/u;I)V

    .line 95
    .line 96
    .line 97
    iget-object v2, p0, Lf2/u;->u:Li1/l;

    .line 98
    .line 99
    iget-boolean v3, p0, Lf2/u;->v:Z

    .line 100
    .line 101
    iget v4, p0, Lf2/u;->w:F

    .line 102
    .line 103
    sget-object v0, Lg2/f;->a:Lc1/a2;

    .line 104
    .line 105
    new-instance v1, Lg2/a;

    .line 106
    .line 107
    invoke-direct/range {v1 .. v6}, Lg2/a;-><init>(Li1/l;ZFLe3/t;Lay0/a;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {p0, v1}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 111
    .line 112
    .line 113
    iput-object v1, p0, Lf2/u;->y:Lg2/a;

    .line 114
    .line 115
    :cond_4
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 116
    .line 117
    return-object p0

    .line 118
    nop

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
