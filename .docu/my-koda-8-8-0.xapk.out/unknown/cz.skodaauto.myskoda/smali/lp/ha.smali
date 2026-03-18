.class public abstract Llp/ha;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/Object;Lay0/o;Ll2/o;I)V
    .locals 4

    .line 1
    const-string v0, "block"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p2, Ll2/t;

    .line 7
    .line 8
    const v0, -0x154bb47a

    .line 9
    .line 10
    .line 11
    invoke-virtual {p2, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p2, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x4

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x2

    .line 23
    :goto_0
    or-int/2addr v0, p3

    .line 24
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    const/16 v1, 0x20

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    const/16 v1, 0x10

    .line 34
    .line 35
    :goto_1
    or-int/2addr v0, v1

    .line 36
    and-int/lit8 v1, v0, 0x13

    .line 37
    .line 38
    const/16 v2, 0x12

    .line 39
    .line 40
    const/4 v3, 0x1

    .line 41
    if-eq v1, v2, :cond_2

    .line 42
    .line 43
    move v1, v3

    .line 44
    goto :goto_2

    .line 45
    :cond_2
    const/4 v1, 0x0

    .line 46
    :goto_2
    and-int/2addr v0, v3

    .line 47
    invoke-virtual {p2, v0, v1}, Ll2/t;->O(IZ)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-eqz v0, :cond_5

    .line 52
    .line 53
    iget-object v0, p2, Ll2/t;->a:Leb/j0;

    .line 54
    .line 55
    check-cast v0, Luu/x;

    .line 56
    .line 57
    iget-object v0, v0, Luu/x;->h:Lqp/g;

    .line 58
    .line 59
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    invoke-virtual {p2, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    or-int/2addr v1, v2

    .line 68
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    if-nez v1, :cond_3

    .line 73
    .line 74
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 75
    .line 76
    if-ne v2, v1, :cond_4

    .line 77
    .line 78
    :cond_3
    new-instance v2, Ltr0/e;

    .line 79
    .line 80
    const/4 v1, 0x0

    .line 81
    const/16 v3, 0x11

    .line 82
    .line 83
    invoke-direct {v2, v3, p1, v0, v1}, Ltr0/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p2, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    :cond_4
    check-cast v2, Lay0/n;

    .line 90
    .line 91
    invoke-static {v2, p0, p2}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 92
    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_5
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 96
    .line 97
    .line 98
    :goto_3
    invoke-virtual {p2}, Ll2/t;->s()Ll2/u1;

    .line 99
    .line 100
    .line 101
    move-result-object p2

    .line 102
    if-eqz p2, :cond_6

    .line 103
    .line 104
    new-instance v0, Luu/q0;

    .line 105
    .line 106
    const/4 v1, 0x0

    .line 107
    invoke-direct {v0, p3, v1, p0, p1}, Luu/q0;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 111
    .line 112
    :cond_6
    return-void
.end method

.method public static final b(JJ)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-static {p1, p0}, Lly0/p;->Q(ILjava/lang/String;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-static {p2, p3}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    invoke-static {p1, p2}, Lly0/p;->Q(ILjava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    const-string p2, ":"

    .line 19
    .line 20
    const-string p3, "h"

    .line 21
    .line 22
    invoke-static {p0, p2, p1, p3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
