.class public final Lbo0/r;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lyn0/e;

.field public final i:Lyn0/o;

.field public final j:Lij0/a;

.field public final k:Ltr0/b;

.field public final l:Lqf0/g;

.field public m:Lao0/c;


# direct methods
.method public constructor <init>(Lyn0/e;Lyn0/o;Lij0/a;Ltr0/b;Lqf0/g;)V
    .locals 12

    .line 1
    new-instance v0, Lbo0/q;

    .line 2
    .line 3
    sget-object v4, Lbo0/p;->d:Lbo0/p;

    .line 4
    .line 5
    invoke-static {}, Ljava/time/LocalTime;->now()Ljava/time/LocalTime;

    .line 6
    .line 7
    .line 8
    move-result-object v11

    .line 9
    const-string v1, "now(...)"

    .line 10
    .line 11
    invoke-static {v11, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v1, ""

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    sget-object v3, Lmx0/u;->d:Lmx0/u;

    .line 18
    .line 19
    const/4 v5, 0x0

    .line 20
    const/4 v6, 0x0

    .line 21
    const/4 v7, 0x0

    .line 22
    const/4 v8, 0x0

    .line 23
    const/4 v9, 0x0

    .line 24
    const/4 v10, 0x0

    .line 25
    invoke-direct/range {v0 .. v11}, Lbo0/q;-><init>(Ljava/lang/String;ZLjava/util/Set;Lbo0/p;ZZZZZZLjava/time/LocalTime;)V

    .line 26
    .line 27
    .line 28
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Lbo0/r;->h:Lyn0/e;

    .line 32
    .line 33
    iput-object p2, p0, Lbo0/r;->i:Lyn0/o;

    .line 34
    .line 35
    iput-object p3, p0, Lbo0/r;->j:Lij0/a;

    .line 36
    .line 37
    move-object/from16 p1, p4

    .line 38
    .line 39
    iput-object p1, p0, Lbo0/r;->k:Ltr0/b;

    .line 40
    .line 41
    move-object/from16 p1, p5

    .line 42
    .line 43
    iput-object p1, p0, Lbo0/r;->l:Lqf0/g;

    .line 44
    .line 45
    new-instance p1, Lbo0/m;

    .line 46
    .line 47
    const/4 p2, 0x0

    .line 48
    const/4 v0, 0x0

    .line 49
    invoke-direct {p1, p0, v0, p2}, Lbo0/m;-><init>(Lbo0/r;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 53
    .line 54
    .line 55
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    new-instance p2, Lbo0/m;

    .line 60
    .line 61
    const/4 v1, 0x1

    .line 62
    invoke-direct {p2, p0, v0, v1}, Lbo0/m;-><init>(Lbo0/r;Lkotlin/coroutines/Continuation;I)V

    .line 63
    .line 64
    .line 65
    const/4 p0, 0x3

    .line 66
    invoke-static {p1, v0, v0, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 67
    .line 68
    .line 69
    return-void
.end method


# virtual methods
.method public final h(Lbo0/q;)Lbo0/q;
    .locals 13

    .line 1
    invoke-virtual {p0, p1}, Lbo0/r;->j(Lbo0/q;)Lao0/c;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p1, Lbo0/q;->c:Ljava/util/Set;

    .line 6
    .line 7
    check-cast v1, Ljava/util/Collection;

    .line 8
    .line 9
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lbo0/r;->m:Lao0/c;

    .line 16
    .line 17
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_0

    .line 22
    .line 23
    iget-boolean p0, p1, Lbo0/q;->j:Z

    .line 24
    .line 25
    if-nez p0, :cond_0

    .line 26
    .line 27
    const/4 p0, 0x1

    .line 28
    :goto_0
    move v8, p0

    .line 29
    goto :goto_1

    .line 30
    :cond_0
    const/4 p0, 0x0

    .line 31
    goto :goto_0

    .line 32
    :goto_1
    const/4 v11, 0x0

    .line 33
    const/16 v12, 0x77f

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    const/4 v2, 0x0

    .line 37
    const/4 v3, 0x0

    .line 38
    const/4 v4, 0x0

    .line 39
    const/4 v5, 0x0

    .line 40
    const/4 v6, 0x0

    .line 41
    const/4 v7, 0x0

    .line 42
    const/4 v9, 0x0

    .line 43
    const/4 v10, 0x0

    .line 44
    move-object v0, p1

    .line 45
    invoke-static/range {v0 .. v12}, Lbo0/q;->a(Lbo0/q;Ljava/lang/String;ZLjava/util/Set;Lbo0/p;ZZZZZZLjava/time/LocalTime;I)Lbo0/q;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0
.end method

.method public final j(Lbo0/q;)Lao0/c;
    .locals 7

    .line 1
    iget-object v0, p0, Lbo0/r;->m:Lao0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_6

    .line 4
    .line 5
    iget-object v2, p1, Lbo0/q;->k:Ljava/time/LocalTime;

    .line 6
    .line 7
    iget-object v1, p1, Lbo0/q;->c:Ljava/util/Set;

    .line 8
    .line 9
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lbo0/q;

    .line 14
    .line 15
    iget-object p0, p0, Lbo0/q;->d:Lbo0/p;

    .line 16
    .line 17
    sget-object v3, Lbo0/p;->f:Lbo0/p;

    .line 18
    .line 19
    if-ne p0, v3, :cond_1

    .line 20
    .line 21
    move-object p0, v1

    .line 22
    check-cast p0, Ljava/util/Collection;

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-eqz v3, :cond_0

    .line 29
    .line 30
    sget-object p0, Lbo0/n;->a:Lsx0/b;

    .line 31
    .line 32
    invoke-static {p0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    :cond_0
    check-cast p0, Ljava/util/Set;

    .line 37
    .line 38
    move-object v4, p0

    .line 39
    goto :goto_0

    .line 40
    :cond_1
    move-object v4, v1

    .line 41
    :goto_0
    iget-object p0, p1, Lbo0/q;->d:Lbo0/p;

    .line 42
    .line 43
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    if-eqz p0, :cond_5

    .line 48
    .line 49
    const/4 v3, 0x1

    .line 50
    if-eq p0, v3, :cond_4

    .line 51
    .line 52
    const/4 v3, 0x2

    .line 53
    if-ne p0, v3, :cond_3

    .line 54
    .line 55
    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    if-eqz p0, :cond_2

    .line 60
    .line 61
    sget-object p0, Lao0/f;->e:Lao0/f;

    .line 62
    .line 63
    :goto_1
    move-object v3, p0

    .line 64
    goto :goto_2

    .line 65
    :cond_2
    sget-object p0, Lao0/f;->d:Lao0/f;

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_3
    new-instance p0, La8/r0;

    .line 69
    .line 70
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 71
    .line 72
    .line 73
    throw p0

    .line 74
    :cond_4
    sget-object p0, Lao0/f;->e:Lao0/f;

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_5
    sget-object p0, Lao0/f;->d:Lao0/f;

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :goto_2
    iget-boolean v5, p1, Lbo0/q;->e:Z

    .line 81
    .line 82
    const/4 v1, 0x0

    .line 83
    const/4 v6, 0x3

    .line 84
    invoke-static/range {v0 .. v6}, Lao0/c;->a(Lao0/c;ZLjava/time/LocalTime;Lao0/f;Ljava/util/Set;ZI)Lao0/c;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    return-object p0

    .line 89
    :cond_6
    const/4 p0, 0x0

    .line 90
    return-object p0
.end method
