.class public final Lal0/o1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lal0/e0;

.field public final b:Lwj0/g;

.field public final c:Lwj0/x;


# direct methods
.method public constructor <init>(Lal0/e0;Lwj0/g;Lwj0/x;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/o1;->a:Lal0/e0;

    .line 5
    .line 6
    iput-object p2, p0, Lal0/o1;->b:Lwj0/g;

    .line 7
    .line 8
    iput-object p3, p0, Lal0/o1;->c:Lwj0/x;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lbl0/h0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lal0/o1;->b(Lbl0/h0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lbl0/h0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lal0/n1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lal0/n1;

    .line 7
    .line 8
    iget v1, v0, Lal0/n1;->g:I

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
    iput v1, v0, Lal0/n1;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lal0/n1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lal0/n1;-><init>(Lal0/o1;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lal0/n1;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lal0/n1;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    iget-object p1, v0, Lal0/n1;->d:Lbl0/h0;

    .line 42
    .line 43
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    iget-object p1, v0, Lal0/n1;->d:Lbl0/h0;

    .line 56
    .line 57
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iput-object p1, v0, Lal0/n1;->d:Lbl0/h0;

    .line 65
    .line 66
    iput v5, v0, Lal0/n1;->g:I

    .line 67
    .line 68
    iget-object p2, p0, Lal0/o1;->a:Lal0/e0;

    .line 69
    .line 70
    check-cast p2, Lyk0/j;

    .line 71
    .line 72
    invoke-virtual {p2, p1, v0}, Lyk0/j;->d(Lbl0/h0;Lrx0/c;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    if-ne p2, v1, :cond_4

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    :goto_1
    iput-object p1, v0, Lal0/n1;->d:Lbl0/h0;

    .line 80
    .line 81
    iput v4, v0, Lal0/n1;->g:I

    .line 82
    .line 83
    iget-object p2, p0, Lal0/o1;->b:Lwj0/g;

    .line 84
    .line 85
    invoke-virtual {p2, v3, v0}, Lwj0/g;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    if-ne p2, v1, :cond_5

    .line 90
    .line 91
    :goto_2
    return-object v1

    .line 92
    :cond_5
    :goto_3
    check-cast p2, Lxj0/b;

    .line 93
    .line 94
    if-eqz p1, :cond_6

    .line 95
    .line 96
    iget p1, p2, Lxj0/b;->b:F

    .line 97
    .line 98
    const/high16 v0, 0x41100000    # 9.0f

    .line 99
    .line 100
    cmpg-float p1, p1, v0

    .line 101
    .line 102
    if-gez p1, :cond_6

    .line 103
    .line 104
    new-instance p1, Lxj0/x;

    .line 105
    .line 106
    iget-object p2, p2, Lxj0/b;->a:Lxj0/f;

    .line 107
    .line 108
    const/high16 v0, 0x41200000    # 10.0f

    .line 109
    .line 110
    invoke-direct {p1, p2, v0}, Lxj0/x;-><init>(Lxj0/f;F)V

    .line 111
    .line 112
    .line 113
    iget-object p0, p0, Lal0/o1;->c:Lwj0/x;

    .line 114
    .line 115
    invoke-virtual {p0, p1}, Lwj0/x;->a(Lxj0/x;)V

    .line 116
    .line 117
    .line 118
    :cond_6
    return-object v3
.end method
