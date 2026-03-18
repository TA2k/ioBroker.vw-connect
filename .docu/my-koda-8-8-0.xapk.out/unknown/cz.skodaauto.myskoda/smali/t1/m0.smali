.class public final Lt1/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lw3/b2;

.field public b:Lt1/n0;

.field public c:Lc3/j;


# direct methods
.method public constructor <init>(Lw3/b2;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt1/m0;->a:Lw3/b2;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()Lt1/n0;
    .locals 0

    .line 1
    iget-object p0, p0, Lt1/m0;->b:Lt1/n0;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "keyboardActions"

    .line 7
    .line 8
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    throw p0
.end method

.method public final b(I)Z
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x5

    .line 3
    const/4 v2, 0x6

    .line 4
    const/4 v3, 0x2

    .line 5
    const/4 v4, 0x1

    .line 6
    const/4 v5, 0x7

    .line 7
    if-ne p1, v5, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lt1/m0;->a()Lt1/n0;

    .line 10
    .line 11
    .line 12
    move-result-object v6

    .line 13
    iget-object v6, v6, Lt1/n0;->a:Lay0/k;

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    if-ne p1, v3, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Lt1/m0;->a()Lt1/n0;

    .line 19
    .line 20
    .line 21
    move-result-object v6

    .line 22
    iget-object v6, v6, Lt1/n0;->b:Lay0/k;

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_1
    if-ne p1, v2, :cond_2

    .line 26
    .line 27
    invoke-virtual {p0}, Lt1/m0;->a()Lt1/n0;

    .line 28
    .line 29
    .line 30
    move-result-object v6

    .line 31
    iget-object v6, v6, Lt1/n0;->c:Lay0/k;

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_2
    if-ne p1, v1, :cond_3

    .line 35
    .line 36
    invoke-virtual {p0}, Lt1/m0;->a()Lt1/n0;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    iget-object v6, v6, Lt1/n0;->d:Lay0/k;

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_3
    const/4 v6, 0x3

    .line 44
    if-ne p1, v6, :cond_4

    .line 45
    .line 46
    invoke-virtual {p0}, Lt1/m0;->a()Lt1/n0;

    .line 47
    .line 48
    .line 49
    move-result-object v6

    .line 50
    iget-object v6, v6, Lt1/n0;->e:Lay0/k;

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_4
    const/4 v6, 0x4

    .line 54
    if-ne p1, v6, :cond_5

    .line 55
    .line 56
    invoke-virtual {p0}, Lt1/m0;->a()Lt1/n0;

    .line 57
    .line 58
    .line 59
    move-result-object v6

    .line 60
    iget-object v6, v6, Lt1/n0;->f:Lay0/k;

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_5
    if-ne p1, v4, :cond_6

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_6
    if-nez p1, :cond_d

    .line 67
    .line 68
    :goto_0
    move-object v6, v0

    .line 69
    :goto_1
    if-eqz v6, :cond_7

    .line 70
    .line 71
    invoke-interface {v6, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    return v4

    .line 75
    :cond_7
    const-string v6, "focusManager"

    .line 76
    .line 77
    if-ne p1, v2, :cond_9

    .line 78
    .line 79
    iget-object p0, p0, Lt1/m0;->c:Lc3/j;

    .line 80
    .line 81
    if-eqz p0, :cond_8

    .line 82
    .line 83
    check-cast p0, Lc3/l;

    .line 84
    .line 85
    invoke-virtual {p0, v4}, Lc3/l;->h(I)Z

    .line 86
    .line 87
    .line 88
    return v4

    .line 89
    :cond_8
    invoke-static {v6}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw v0

    .line 93
    :cond_9
    if-ne p1, v1, :cond_b

    .line 94
    .line 95
    iget-object p0, p0, Lt1/m0;->c:Lc3/j;

    .line 96
    .line 97
    if-eqz p0, :cond_a

    .line 98
    .line 99
    check-cast p0, Lc3/l;

    .line 100
    .line 101
    invoke-virtual {p0, v3}, Lc3/l;->h(I)Z

    .line 102
    .line 103
    .line 104
    return v4

    .line 105
    :cond_a
    invoke-static {v6}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw v0

    .line 109
    :cond_b
    if-ne p1, v5, :cond_c

    .line 110
    .line 111
    iget-object p0, p0, Lt1/m0;->a:Lw3/b2;

    .line 112
    .line 113
    if-eqz p0, :cond_c

    .line 114
    .line 115
    check-cast p0, Lw3/i1;

    .line 116
    .line 117
    invoke-virtual {p0}, Lw3/i1;->a()V

    .line 118
    .line 119
    .line 120
    return v4

    .line 121
    :cond_c
    const/4 p0, 0x0

    .line 122
    return p0

    .line 123
    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 124
    .line 125
    const-string p1, "invalid ImeAction"

    .line 126
    .line 127
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw p0
.end method
