.class public final Lz90/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lz90/p;


# direct methods
.method public constructor <init>(Lz90/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz90/f;->a:Lz90/p;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lz90/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lz90/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lz90/e;

    .line 7
    .line 8
    iget v1, v0, Lz90/e;->g:I

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
    iput v1, v0, Lz90/e;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lz90/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lz90/e;-><init>(Lz90/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lz90/e;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lz90/e;->g:I

    .line 30
    .line 31
    iget-object p0, p0, Lz90/f;->a:Lz90/p;

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    const/4 v5, 0x0

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v4, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    iget-object p0, v0, Lz90/e;->d:Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_4

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    move-object p1, p0

    .line 64
    check-cast p1, Lx90/a;

    .line 65
    .line 66
    iget-object p1, p1, Lx90/a;->e:Lyy0/l1;

    .line 67
    .line 68
    iput v4, v0, Lz90/e;->g:I

    .line 69
    .line 70
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    if-ne p1, v1, :cond_4

    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_4
    :goto_1
    check-cast p1, Laa0/c;

    .line 78
    .line 79
    if-eqz p1, :cond_5

    .line 80
    .line 81
    iget-object p1, p1, Laa0/c;->a:Ljava/lang/String;

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_5
    move-object p1, v5

    .line 85
    :goto_2
    check-cast p0, Lx90/a;

    .line 86
    .line 87
    iget-object p0, p0, Lx90/a;->h:Lyy0/l1;

    .line 88
    .line 89
    new-instance v2, Lrz/k;

    .line 90
    .line 91
    const/16 v4, 0x18

    .line 92
    .line 93
    invoke-direct {v2, p0, v4}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 94
    .line 95
    .line 96
    iput-object p1, v0, Lz90/e;->d:Ljava/lang/String;

    .line 97
    .line 98
    iput v3, v0, Lz90/e;->g:I

    .line 99
    .line 100
    invoke-static {v2, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    if-ne p0, v1, :cond_6

    .line 105
    .line 106
    :goto_3
    return-object v1

    .line 107
    :cond_6
    move-object v6, p1

    .line 108
    move-object p1, p0

    .line 109
    move-object p0, v6

    .line 110
    :goto_4
    const-string v0, "null cannot be cast to non-null type cz.skodaauto.myskoda.library.data.infrastructure.Data.Success<kotlin.collections.List<cz.skodaauto.myskoda.feature.vehicleservicesbackup.model.VehicleServicesBackup>>"

    .line 111
    .line 112
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    check-cast p1, Lne0/e;

    .line 116
    .line 117
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast p1, Ljava/lang/Iterable;

    .line 120
    .line 121
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    :cond_7
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    if-eqz v0, :cond_8

    .line 130
    .line 131
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    move-object v1, v0

    .line 136
    check-cast v1, Laa0/j;

    .line 137
    .line 138
    iget-object v1, v1, Laa0/j;->a:Ljava/lang/String;

    .line 139
    .line 140
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result v1

    .line 144
    if-eqz v1, :cond_7

    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_8
    move-object v0, v5

    .line 148
    :goto_5
    check-cast v0, Laa0/j;

    .line 149
    .line 150
    if-eqz v0, :cond_9

    .line 151
    .line 152
    iget-object p0, v0, Laa0/j;->b:Ljava/lang/String;

    .line 153
    .line 154
    return-object p0

    .line 155
    :cond_9
    return-object v5
.end method
