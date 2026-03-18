.class public final Lu40/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ls40/d;

.field public final b:Lfg0/d;


# direct methods
.method public constructor <init>(Ls40/d;Lfg0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu40/g;->a:Ls40/d;

    .line 5
    .line 6
    iput-object p2, p0, Lu40/g;->b:Lfg0/d;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lu40/e;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lu40/g;->b(Lu40/e;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lu40/e;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lu40/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lu40/f;

    .line 7
    .line 8
    iget v1, v0, Lu40/f;->g:I

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
    iput v1, v0, Lu40/f;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lu40/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lu40/f;-><init>(Lu40/g;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lu40/f;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lu40/f;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lu40/f;->d:Lu40/e;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p2, p0, Lu40/g;->b:Lfg0/d;

    .line 54
    .line 55
    invoke-virtual {p2}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    check-cast p2, Lyy0/i;

    .line 60
    .line 61
    iput-object p1, v0, Lu40/f;->d:Lu40/e;

    .line 62
    .line 63
    iput v3, v0, Lu40/f;->g:I

    .line 64
    .line 65
    invoke-static {p2, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    if-ne p2, v1, :cond_3

    .line 70
    .line 71
    return-object v1

    .line 72
    :cond_3
    :goto_1
    check-cast p2, Lgg0/a;

    .line 73
    .line 74
    iget-object v2, p1, Lu40/e;->a:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v3, p1, Lu40/e;->c:Ljava/lang/String;

    .line 77
    .line 78
    iget-object v4, p1, Lu40/e;->d:Ljava/time/OffsetDateTime;

    .line 79
    .line 80
    iget-boolean v5, p1, Lu40/e;->e:Z

    .line 81
    .line 82
    const/4 v0, 0x0

    .line 83
    if-eqz p2, :cond_4

    .line 84
    .line 85
    iget-wide v6, p2, Lgg0/a;->a:D

    .line 86
    .line 87
    double-to-float v1, v6

    .line 88
    new-instance v6, Ljava/lang/Float;

    .line 89
    .line 90
    invoke-direct {v6, v1}, Ljava/lang/Float;-><init>(F)V

    .line 91
    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_4
    move-object v6, v0

    .line 95
    :goto_2
    if-eqz p2, :cond_5

    .line 96
    .line 97
    iget-wide v0, p2, Lgg0/a;->b:D

    .line 98
    .line 99
    double-to-float p2, v0

    .line 100
    new-instance v0, Ljava/lang/Float;

    .line 101
    .line 102
    invoke-direct {v0, p2}, Ljava/lang/Float;-><init>(F)V

    .line 103
    .line 104
    .line 105
    :cond_5
    move-object v7, v0

    .line 106
    iget-object v8, p1, Lu40/e;->b:Ljava/lang/String;

    .line 107
    .line 108
    iget-object v1, p0, Lu40/g;->a:Ls40/d;

    .line 109
    .line 110
    const-string p0, "locationId"

    .line 111
    .line 112
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    const-string p0, "$v$c$cz-skodaauto-myskoda-library-deliveredvehicle-model-LicensePlate$-licensePlate$0"

    .line 116
    .line 117
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    iget-object p0, v1, Ls40/d;->a:Lxl0/f;

    .line 121
    .line 122
    new-instance v0, Ls40/b;

    .line 123
    .line 124
    const/4 v9, 0x0

    .line 125
    invoke-direct/range {v0 .. v9}, Ls40/b;-><init>(Ls40/d;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;ZLjava/lang/Float;Ljava/lang/Float;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 126
    .line 127
    .line 128
    new-instance p1, Lr40/e;

    .line 129
    .line 130
    const/16 p2, 0x16

    .line 131
    .line 132
    invoke-direct {p1, p2}, Lr40/e;-><init>(I)V

    .line 133
    .line 134
    .line 135
    new-instance p2, Lr40/e;

    .line 136
    .line 137
    const/16 v1, 0x17

    .line 138
    .line 139
    invoke-direct {p2, v1}, Lr40/e;-><init>(I)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {p0, v0, p1, p2}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    return-object p0
.end method
