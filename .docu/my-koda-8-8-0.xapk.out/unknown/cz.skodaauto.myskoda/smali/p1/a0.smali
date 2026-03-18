.class public final Lp1/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/j1;


# instance fields
.field public final a:Lh1/g;

.field public final b:Lp1/v;


# direct methods
.method public constructor <init>(Lh1/g;Lp1/v;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp1/a0;->a:Lh1/g;

    .line 5
    .line 6
    iput-object p2, p0, Lp1/a0;->b:Lp1/v;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lg1/e2;FLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p3, Lp1/z;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lp1/z;

    .line 7
    .line 8
    iget v1, v0, Lp1/z;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lp1/z;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lp1/z;

    .line 21
    .line 22
    check-cast p3, Lrx0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, p3}, Lp1/z;-><init>(Lp1/a0;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p3, v0, Lp1/z;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, v0, Lp1/z;->f:I

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v3, :cond_1

    .line 37
    .line 38
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance p3, Lla/p;

    .line 54
    .line 55
    invoke-direct {p3, p0, p1}, Lla/p;-><init>(Lp1/a0;Lg1/e2;)V

    .line 56
    .line 57
    .line 58
    iput v3, v0, Lp1/z;->f:I

    .line 59
    .line 60
    iget-object v2, p0, Lp1/a0;->a:Lh1/g;

    .line 61
    .line 62
    invoke-virtual {v2, p1, p2, p3, v0}, Lh1/g;->d(Lg1/e2;FLay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p3

    .line 66
    if-ne p3, v1, :cond_3

    .line 67
    .line 68
    return-object v1

    .line 69
    :cond_3
    :goto_1
    check-cast p3, Ljava/lang/Number;

    .line 70
    .line 71
    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    iget-object p0, p0, Lp1/a0;->b:Lp1/v;

    .line 76
    .line 77
    iget-object p2, p0, Lp1/v;->d:Lh8/o;

    .line 78
    .line 79
    iget-object p3, p0, Lp1/v;->d:Lh8/o;

    .line 80
    .line 81
    iget-object p2, p2, Lh8/o;->d:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p2, Ll2/f1;

    .line 84
    .line 85
    invoke-virtual {p2}, Ll2/f1;->o()F

    .line 86
    .line 87
    .line 88
    move-result p2

    .line 89
    const/4 v0, 0x0

    .line 90
    cmpg-float p2, p2, v0

    .line 91
    .line 92
    if-nez p2, :cond_4

    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_4
    iget-object p2, p3, Lh8/o;->d:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast p2, Ll2/f1;

    .line 98
    .line 99
    invoke-virtual {p2}, Ll2/f1;->o()F

    .line 100
    .line 101
    .line 102
    move-result p2

    .line 103
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 104
    .line 105
    .line 106
    move-result p2

    .line 107
    float-to-double v1, p2

    .line 108
    const-wide v3, 0x3f50624dd2f1a9fcL    # 0.001

    .line 109
    .line 110
    .line 111
    .line 112
    .line 113
    cmpg-double p2, v1, v3

    .line 114
    .line 115
    if-gez p2, :cond_6

    .line 116
    .line 117
    invoke-virtual {p0}, Lp1/v;->k()I

    .line 118
    .line 119
    .line 120
    move-result p2

    .line 121
    iget-object p3, p0, Lp1/v;->k:Lg1/f0;

    .line 122
    .line 123
    invoke-virtual {p3}, Lg1/f0;->a()Z

    .line 124
    .line 125
    .line 126
    move-result p3

    .line 127
    if-eqz p3, :cond_5

    .line 128
    .line 129
    iget-object p3, p0, Lp1/v;->p:Ll2/j1;

    .line 130
    .line 131
    invoke-virtual {p3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p3

    .line 135
    check-cast p3, Lp1/o;

    .line 136
    .line 137
    iget-object p3, p3, Lp1/o;->t:Lvy0/b0;

    .line 138
    .line 139
    new-instance v1, Lp1/k;

    .line 140
    .line 141
    const/4 v2, 0x2

    .line 142
    const/4 v3, 0x0

    .line 143
    invoke-direct {v1, p0, v3, v2}, Lp1/k;-><init>(Lp1/v;Lkotlin/coroutines/Continuation;I)V

    .line 144
    .line 145
    .line 146
    const/4 v2, 0x3

    .line 147
    invoke-static {p3, v3, v3, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 148
    .line 149
    .line 150
    :cond_5
    const/4 p3, 0x0

    .line 151
    invoke-virtual {p0, p2, v0, p3}, Lp1/v;->u(IFZ)V

    .line 152
    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_6
    :goto_2
    iget-object p0, p3, Lh8/o;->d:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast p0, Ll2/f1;

    .line 158
    .line 159
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 160
    .line 161
    .line 162
    move-result p0

    .line 163
    new-instance p2, Ljava/lang/Float;

    .line 164
    .line 165
    invoke-direct {p2, p0}, Ljava/lang/Float;-><init>(F)V

    .line 166
    .line 167
    .line 168
    :goto_3
    new-instance p0, Ljava/lang/Float;

    .line 169
    .line 170
    invoke-direct {p0, p1}, Ljava/lang/Float;-><init>(F)V

    .line 171
    .line 172
    .line 173
    return-object p0
.end method
