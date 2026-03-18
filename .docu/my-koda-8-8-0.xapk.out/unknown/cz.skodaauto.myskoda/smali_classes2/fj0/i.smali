.class public final Lfj0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lfj0/f;

.field public final b:Lfj0/b;

.field public final c:Lfj0/a;


# direct methods
.method public constructor <init>(Lfj0/f;Lfj0/b;Lfj0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfj0/i;->a:Lfj0/f;

    .line 5
    .line 6
    iput-object p2, p0, Lfj0/i;->b:Lfj0/b;

    .line 7
    .line 8
    iput-object p3, p0, Lfj0/i;->c:Lfj0/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lfj0/i;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lfj0/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lfj0/h;

    .line 7
    .line 8
    iget v1, v0, Lfj0/h;->h:I

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
    iput v1, v0, Lfj0/h;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lfj0/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lfj0/h;-><init>(Lfj0/i;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lfj0/h;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lfj0/h;->h:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    const/4 v5, 0x2

    .line 35
    const/4 v6, 0x1

    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v6, :cond_3

    .line 39
    .line 40
    if-eq v2, v5, :cond_2

    .line 41
    .line 42
    if-ne v2, v4, :cond_1

    .line 43
    .line 44
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object v3

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
    iget v2, v0, Lfj0/h;->e:I

    .line 57
    .line 58
    iget-object v5, v0, Lfj0/h;->d:Ljava/lang/String;

    .line 59
    .line 60
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    iput v6, v0, Lfj0/h;->h:I

    .line 72
    .line 73
    iget-object p1, p0, Lfj0/i;->a:Lfj0/f;

    .line 74
    .line 75
    check-cast p1, Lcj0/b;

    .line 76
    .line 77
    invoke-virtual {p1, v0}, Lcj0/b;->a(Lrx0/c;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    if-ne p1, v1, :cond_5

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_5
    :goto_1
    check-cast p1, Ljava/lang/String;

    .line 85
    .line 86
    if-eqz p1, :cond_8

    .line 87
    .line 88
    iput-object p1, v0, Lfj0/h;->d:Ljava/lang/String;

    .line 89
    .line 90
    const/4 v2, 0x0

    .line 91
    iput v2, v0, Lfj0/h;->e:I

    .line 92
    .line 93
    iput v5, v0, Lfj0/h;->h:I

    .line 94
    .line 95
    iget-object v5, p0, Lfj0/i;->b:Lfj0/b;

    .line 96
    .line 97
    iget-object v5, v5, Lfj0/b;->a:Lfj0/e;

    .line 98
    .line 99
    check-cast v5, Ldj0/b;

    .line 100
    .line 101
    iget-object v5, v5, Ldj0/b;->h:Lyy0/l1;

    .line 102
    .line 103
    iget-object v5, v5, Lyy0/l1;->d:Lyy0/a2;

    .line 104
    .line 105
    invoke-interface {v5}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v5

    .line 109
    if-ne v5, v1, :cond_6

    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_6
    move-object v7, v5

    .line 113
    move-object v5, p1

    .line 114
    move-object p1, v7

    .line 115
    :goto_2
    check-cast p1, Ljava/util/Locale;

    .line 116
    .line 117
    invoke-virtual {p1}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    invoke-static {p1, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result p1

    .line 125
    if-nez p1, :cond_8

    .line 126
    .line 127
    const-string p1, "language"

    .line 128
    .line 129
    invoke-static {v5, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 133
    .line 134
    const/16 v6, 0x24

    .line 135
    .line 136
    if-lt p1, v6, :cond_7

    .line 137
    .line 138
    invoke-static {v5}, Lgj0/a;->b(Ljava/lang/String;)Ljava/util/Locale;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    goto :goto_3

    .line 146
    :cond_7
    new-instance p1, Ljava/util/Locale;

    .line 147
    .line 148
    invoke-direct {p1, v5}, Ljava/util/Locale;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    :goto_3
    const/4 v5, 0x0

    .line 152
    iput-object v5, v0, Lfj0/h;->d:Ljava/lang/String;

    .line 153
    .line 154
    iput v2, v0, Lfj0/h;->e:I

    .line 155
    .line 156
    iput v4, v0, Lfj0/h;->h:I

    .line 157
    .line 158
    iget-object p0, p0, Lfj0/i;->c:Lfj0/a;

    .line 159
    .line 160
    invoke-virtual {p0, p1}, Lfj0/a;->b(Ljava/util/Locale;)V

    .line 161
    .line 162
    .line 163
    if-ne v3, v1, :cond_8

    .line 164
    .line 165
    :goto_4
    return-object v1

    .line 166
    :cond_8
    return-object v3
.end method
