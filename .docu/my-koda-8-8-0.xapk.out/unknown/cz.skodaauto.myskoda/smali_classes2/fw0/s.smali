.class public abstract Lfw0/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt21/b;

.field public static final b:Lgw0/c;

.field public static final c:Lvw0/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "io.ktor.client.plugins.HttpCallValidator"

    .line 2
    .line 3
    invoke-static {v0}, Lt21/d;->b(Ljava/lang/String;)Lt21/b;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lfw0/s;->a:Lt21/b;

    .line 8
    .line 9
    sget-object v0, Lfw0/m;->d:Lfw0/m;

    .line 10
    .line 11
    new-instance v1, Lf31/n;

    .line 12
    .line 13
    const/16 v2, 0x1a

    .line 14
    .line 15
    invoke-direct {v1, v2}, Lf31/n;-><init>(I)V

    .line 16
    .line 17
    .line 18
    const-string v2, "HttpResponseValidator"

    .line 19
    .line 20
    invoke-static {v2, v0, v1}, Lkp/q9;->a(Ljava/lang/String;Lay0/a;Lay0/k;)Lgw0/c;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    sput-object v0, Lfw0/s;->b:Lgw0/c;

    .line 25
    .line 26
    const-class v0, Ljava/lang/Boolean;

    .line 27
    .line 28
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 29
    .line 30
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    :try_start_0
    sget-object v1, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 35
    .line 36
    invoke-static {v1}, Lkotlin/jvm/internal/g0;->b(Ljava/lang/Class;)Lhy0/a0;

    .line 37
    .line 38
    .line 39
    move-result-object v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    goto :goto_0

    .line 41
    :catchall_0
    const/4 v1, 0x0

    .line 42
    :goto_0
    new-instance v2, Lzw0/a;

    .line 43
    .line 44
    invoke-direct {v2, v0, v1}, Lzw0/a;-><init>(Lhy0/d;Lhy0/a0;)V

    .line 45
    .line 46
    .line 47
    new-instance v0, Lvw0/a;

    .line 48
    .line 49
    const-string v1, "ExpectSuccessAttributeKey"

    .line 50
    .line 51
    invoke-direct {v0, v1, v2}, Lvw0/a;-><init>(Ljava/lang/String;Lzw0/a;)V

    .line 52
    .line 53
    .line 54
    sput-object v0, Lfw0/s;->c:Lvw0/a;

    .line 55
    .line 56
    return-void
.end method

.method public static final a(Ljava/util/List;Ljava/lang/Throwable;Lkw0/b;Lrx0/c;)V
    .locals 4

    .line 1
    instance-of v0, p3, Lfw0/p;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lfw0/p;

    .line 7
    .line 8
    iget v1, v0, Lfw0/p;->e:I

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
    iput v1, v0, Lfw0/p;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lfw0/p;

    .line 21
    .line 22
    invoke-direct {v0, p3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lfw0/p;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v0, v0, Lfw0/p;->e:I

    .line 30
    .line 31
    if-eqz v0, :cond_3

    .line 32
    .line 33
    const/4 p0, 0x1

    .line 34
    if-eq v0, p0, :cond_1

    .line 35
    .line 36
    const/4 p0, 0x2

    .line 37
    if-ne v0, p0, :cond_2

    .line 38
    .line 39
    :cond_1
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_2
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
    :goto_1
    const/4 p0, 0x0

    .line 52
    goto :goto_2

    .line 53
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    new-instance p3, Ljava/lang/StringBuilder;

    .line 57
    .line 58
    const-string v0, "Processing exception "

    .line 59
    .line 60
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string p1, " for request "

    .line 67
    .line 68
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-interface {p2}, Lkw0/b;->getUrl()Low0/f0;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    sget-object p2, Lfw0/s;->a:Lt21/b;

    .line 83
    .line 84
    invoke-interface {p2, p1}, Lt21/b;->h(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    check-cast p0, Ljava/lang/Iterable;

    .line 88
    .line 89
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    if-nez p1, :cond_4

    .line 98
    .line 99
    return-void

    .line 100
    :cond_4
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    if-nez p0, :cond_5

    .line 105
    .line 106
    new-instance p0, La8/r0;

    .line 107
    .line 108
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_5
    new-instance p0, Ljava/lang/ClassCastException;

    .line 113
    .line 114
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 115
    .line 116
    .line 117
    throw p0
.end method

.method public static final b(Ljava/util/List;Law0/h;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lfw0/q;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lfw0/q;

    .line 7
    .line 8
    iget v1, v0, Lfw0/q;->h:I

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
    iput v1, v0, Lfw0/q;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lfw0/q;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lfw0/q;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lfw0/q;->h:I

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
    iget p0, v0, Lfw0/q;->f:I

    .line 37
    .line 38
    iget-object p1, v0, Lfw0/q;->e:Ljava/util/Iterator;

    .line 39
    .line 40
    iget-object v2, v0, Lfw0/q;->d:Law0/h;

    .line 41
    .line 42
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    move-object p2, v2

    .line 46
    goto :goto_1

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    new-instance p2, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string v2, "Validating response for request "

    .line 61
    .line 62
    invoke-direct {p2, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1}, Law0/h;->M()Law0/c;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-virtual {v2}, Law0/c;->c()Lkw0/b;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    invoke-interface {v2}, Lkw0/b;->getUrl()Low0/f0;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    sget-object v2, Lfw0/s;->a:Lt21/b;

    .line 85
    .line 86
    invoke-interface {v2, p2}, Lt21/b;->h(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    check-cast p0, Ljava/lang/Iterable;

    .line 90
    .line 91
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    const/4 p2, 0x0

    .line 96
    move-object v4, p1

    .line 97
    move-object p1, p0

    .line 98
    move p0, p2

    .line 99
    move-object p2, v4

    .line 100
    :cond_3
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 101
    .line 102
    .line 103
    move-result v2

    .line 104
    if-eqz v2, :cond_4

    .line 105
    .line 106
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    check-cast v2, Lay0/n;

    .line 111
    .line 112
    iput-object p2, v0, Lfw0/q;->d:Law0/h;

    .line 113
    .line 114
    iput-object p1, v0, Lfw0/q;->e:Ljava/util/Iterator;

    .line 115
    .line 116
    iput p0, v0, Lfw0/q;->f:I

    .line 117
    .line 118
    iput v3, v0, Lfw0/q;->h:I

    .line 119
    .line 120
    invoke-interface {v2, p2, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v2

    .line 124
    if-ne v2, v1, :cond_3

    .line 125
    .line 126
    return-object v1

    .line 127
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 128
    .line 129
    return-object p0
.end method
