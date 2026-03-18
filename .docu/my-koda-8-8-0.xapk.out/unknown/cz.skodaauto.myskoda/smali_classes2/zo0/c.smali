.class public final Lzo0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Ltn0/b;

.field public final b:Lzo0/m;


# direct methods
.method public constructor <init>(Ltn0/b;Lzo0/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzo0/c;->a:Ltn0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lzo0/c;->b:Lzo0/m;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lzo0/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p1, Lzo0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lzo0/b;

    .line 7
    .line 8
    iget v1, v0, Lzo0/b;->g:I

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
    iput v1, v0, Lzo0/b;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzo0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lzo0/b;-><init>(Lzo0/c;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lzo0/b;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lzo0/b;->g:I

    .line 30
    .line 31
    const-string v3, "notification_permission_request_result"

    .line 32
    .line 33
    iget-object v4, p0, Lzo0/c;->b:Lzo0/m;

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    const/4 v6, 0x2

    .line 37
    const/4 v7, 0x1

    .line 38
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    if-eqz v2, :cond_4

    .line 41
    .line 42
    if-eq v2, v7, :cond_3

    .line 43
    .line 44
    if-eq v2, v6, :cond_2

    .line 45
    .line 46
    if-ne v2, v5, :cond_1

    .line 47
    .line 48
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    return-object v8

    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    iget-object v4, v0, Lzo0/b;->d:Lzo0/m;

    .line 61
    .line 62
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    iput v7, v0, Lzo0/b;->g:I

    .line 74
    .line 75
    move-object p1, v4

    .line 76
    check-cast p1, Lwo0/d;

    .line 77
    .line 78
    iget-object p1, p1, Lwo0/d;->a:Lve0/u;

    .line 79
    .line 80
    invoke-virtual {p1, v3, v0}, Lve0/u;->c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    if-ne p1, v1, :cond_5

    .line 85
    .line 86
    goto :goto_4

    .line 87
    :cond_5
    :goto_1
    if-nez p1, :cond_8

    .line 88
    .line 89
    sget-object p1, Lun0/a;->g:Lun0/a;

    .line 90
    .line 91
    iput-object v4, v0, Lzo0/b;->d:Lzo0/m;

    .line 92
    .line 93
    iput v6, v0, Lzo0/b;->g:I

    .line 94
    .line 95
    iget-object p0, p0, Lzo0/c;->a:Ltn0/b;

    .line 96
    .line 97
    invoke-virtual {p0, p1, v0}, Ltn0/b;->b(Lun0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    if-ne p1, v1, :cond_6

    .line 102
    .line 103
    goto :goto_4

    .line 104
    :cond_6
    :goto_2
    check-cast p1, Lun0/b;

    .line 105
    .line 106
    iget-boolean p0, p1, Lun0/b;->b:Z

    .line 107
    .line 108
    const/4 p1, 0x0

    .line 109
    iput-object p1, v0, Lzo0/b;->d:Lzo0/m;

    .line 110
    .line 111
    iput v5, v0, Lzo0/b;->g:I

    .line 112
    .line 113
    check-cast v4, Lwo0/d;

    .line 114
    .line 115
    iget-object p1, v4, Lwo0/d;->a:Lve0/u;

    .line 116
    .line 117
    invoke-virtual {p1, p0, v3, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    if-ne p0, v1, :cond_7

    .line 122
    .line 123
    goto :goto_3

    .line 124
    :cond_7
    move-object p0, v8

    .line 125
    :goto_3
    if-ne p0, v1, :cond_8

    .line 126
    .line 127
    :goto_4
    return-object v1

    .line 128
    :cond_8
    return-object v8
.end method
