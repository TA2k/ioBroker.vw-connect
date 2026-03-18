.class public final Lom0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqm0/c;
.implements Lme0/a;


# instance fields
.field public final a:Lve0/u;


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>(Lve0/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lom0/c;->a:Lve0/u;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lom0/c;->a:Lve0/u;

    .line 2
    .line 3
    const-string v0, "onboarding_key"

    .line 4
    .line 5
    invoke-virtual {p0, v0, p1}, Lve0/u;->k(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 10
    .line 11
    if-ne p0, p1, :cond_0

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lom0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lom0/a;

    .line 7
    .line 8
    iget v1, v0, Lom0/a;->g:I

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
    iput v1, v0, Lom0/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lom0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lom0/a;-><init>(Lom0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lom0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lom0/a;->g:I

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
    iget-object p1, v0, Lom0/a;->d:Ljava/lang/String;

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
    iput-object p1, v0, Lom0/a;->d:Ljava/lang/String;

    .line 54
    .line 55
    iput v3, v0, Lom0/a;->g:I

    .line 56
    .line 57
    iget-object p0, p0, Lom0/c;->a:Lve0/u;

    .line 58
    .line 59
    const-string p2, "onboarding_key"

    .line 60
    .line 61
    invoke-virtual {p0, p2, v0}, Lve0/u;->g(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    if-ne p2, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    :goto_1
    check-cast p2, Ljava/util/Set;

    .line 69
    .line 70
    if-nez p2, :cond_4

    .line 71
    .line 72
    sget-object p2, Lmx0/u;->d:Lmx0/u;

    .line 73
    .line 74
    :cond_4
    new-instance p0, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    const-string v0, "onboarding_key_"

    .line 77
    .line 78
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-interface {p2, p0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0
.end method

.method public final c(Ljava/lang/String;ZLrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p3, Lom0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lom0/b;

    .line 7
    .line 8
    iget v1, v0, Lom0/b;->k:I

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
    iput v1, v0, Lom0/b;->k:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lom0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lom0/b;-><init>(Lom0/c;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lom0/b;->i:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lom0/b;->k:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    iget p0, v0, Lom0/b;->h:I

    .line 52
    .line 53
    iget-boolean p2, v0, Lom0/b;->g:Z

    .line 54
    .line 55
    iget-object p1, v0, Lom0/b;->f:Lve0/u;

    .line 56
    .line 57
    iget-object v2, v0, Lom0/b;->e:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v4, v0, Lom0/b;->d:Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    iput-object p1, v0, Lom0/b;->d:Ljava/lang/String;

    .line 69
    .line 70
    const-string v2, "onboarding_key"

    .line 71
    .line 72
    iput-object v2, v0, Lom0/b;->e:Ljava/lang/String;

    .line 73
    .line 74
    iget-object p0, p0, Lom0/c;->a:Lve0/u;

    .line 75
    .line 76
    iput-object p0, v0, Lom0/b;->f:Lve0/u;

    .line 77
    .line 78
    iput-boolean p2, v0, Lom0/b;->g:Z

    .line 79
    .line 80
    const/4 p3, 0x0

    .line 81
    iput p3, v0, Lom0/b;->h:I

    .line 82
    .line 83
    iput v4, v0, Lom0/b;->k:I

    .line 84
    .line 85
    invoke-virtual {p0, v2, v0}, Lve0/u;->g(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    if-ne v4, v1, :cond_4

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_4
    move-object v7, p1

    .line 93
    move-object p1, p0

    .line 94
    move p0, p3

    .line 95
    move-object p3, v4

    .line 96
    move-object v4, v7

    .line 97
    :goto_1
    check-cast p3, Ljava/util/Set;

    .line 98
    .line 99
    if-nez p3, :cond_5

    .line 100
    .line 101
    sget-object p3, Lmx0/u;->d:Lmx0/u;

    .line 102
    .line 103
    :cond_5
    new-instance v5, Ljava/lang/StringBuilder;

    .line 104
    .line 105
    const-string v6, "onboarding_key_"

    .line 106
    .line 107
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    invoke-static {p3, v4}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 118
    .line 119
    .line 120
    move-result-object p3

    .line 121
    const/4 v4, 0x0

    .line 122
    iput-object v4, v0, Lom0/b;->d:Ljava/lang/String;

    .line 123
    .line 124
    iput-object v4, v0, Lom0/b;->e:Ljava/lang/String;

    .line 125
    .line 126
    iput-object v4, v0, Lom0/b;->f:Lve0/u;

    .line 127
    .line 128
    iput-boolean p2, v0, Lom0/b;->g:Z

    .line 129
    .line 130
    iput p0, v0, Lom0/b;->h:I

    .line 131
    .line 132
    iput v3, v0, Lom0/b;->k:I

    .line 133
    .line 134
    invoke-virtual {p1, v2, p3, v0}, Lve0/u;->o(Ljava/lang/String;Ljava/util/Set;Lrx0/c;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    if-ne p0, v1, :cond_6

    .line 139
    .line 140
    :goto_2
    return-object v1

    .line 141
    :cond_6
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 142
    .line 143
    return-object p0
.end method
