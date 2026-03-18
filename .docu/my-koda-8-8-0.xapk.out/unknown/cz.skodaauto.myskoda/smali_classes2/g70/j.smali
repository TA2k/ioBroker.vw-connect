.class public final Lg70/j;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Ltn0/b;

.field public final j:Ltn0/e;

.field public final k:Lf70/b;

.field public final l:Lkf0/z;

.field public final m:Lrq0/f;

.field public final n:Lcf0/h;

.field public final o:Lij0/a;


# direct methods
.method public constructor <init>(Ltr0/b;Ltn0/b;Ltn0/e;Lf70/b;Lkf0/z;Lrq0/f;Lcf0/h;Lij0/a;)V
    .locals 12

    .line 1
    new-instance v0, Lg70/i;

    .line 2
    .line 3
    const/16 v1, 0x7ff

    .line 4
    .line 5
    and-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    const-string v2, ""

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const-string v2, "Enyaq"

    .line 13
    .line 14
    :goto_0
    and-int/lit8 v1, v1, 0x2

    .line 15
    .line 16
    if-eqz v1, :cond_1

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    const-string v1, "SOMEVIN"

    .line 21
    .line 22
    :goto_1
    const/4 v8, 0x0

    .line 23
    const/4 v9, 0x0

    .line 24
    const/4 v3, 0x0

    .line 25
    const/4 v4, 0x0

    .line 26
    const/4 v5, 0x0

    .line 27
    const/4 v6, 0x0

    .line 28
    const/4 v7, 0x0

    .line 29
    const/4 v10, 0x0

    .line 30
    move-object v11, v2

    .line 31
    move-object v2, v1

    .line 32
    move-object v1, v11

    .line 33
    invoke-direct/range {v0 .. v10}, Lg70/i;-><init>(Ljava/lang/String;Ljava/lang/String;Lhp0/e;ZZZZZZLql0/g;)V

    .line 34
    .line 35
    .line 36
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 37
    .line 38
    .line 39
    iput-object p1, p0, Lg70/j;->h:Ltr0/b;

    .line 40
    .line 41
    iput-object p2, p0, Lg70/j;->i:Ltn0/b;

    .line 42
    .line 43
    iput-object p3, p0, Lg70/j;->j:Ltn0/e;

    .line 44
    .line 45
    move-object/from16 p1, p4

    .line 46
    .line 47
    iput-object p1, p0, Lg70/j;->k:Lf70/b;

    .line 48
    .line 49
    move-object/from16 p1, p5

    .line 50
    .line 51
    iput-object p1, p0, Lg70/j;->l:Lkf0/z;

    .line 52
    .line 53
    move-object/from16 p1, p6

    .line 54
    .line 55
    iput-object p1, p0, Lg70/j;->m:Lrq0/f;

    .line 56
    .line 57
    move-object/from16 p1, p7

    .line 58
    .line 59
    iput-object p1, p0, Lg70/j;->n:Lcf0/h;

    .line 60
    .line 61
    move-object/from16 p1, p8

    .line 62
    .line 63
    iput-object p1, p0, Lg70/j;->o:Lij0/a;

    .line 64
    .line 65
    new-instance p1, Lg70/h;

    .line 66
    .line 67
    const/4 p2, 0x0

    .line 68
    const/4 p3, 0x0

    .line 69
    invoke-direct {p1, p0, p2, p3}, Lg70/h;-><init>(Lg70/j;Lkotlin/coroutines/Continuation;I)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 73
    .line 74
    .line 75
    return-void
.end method


# virtual methods
.method public final h()Lql0/g;
    .locals 10

    .line 1
    new-instance v0, Lql0/g;

    .line 2
    .line 3
    new-instance v1, Lql0/a;

    .line 4
    .line 5
    const-string v2, "rpa_pairing"

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lql0/a;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 11
    .line 12
    .line 13
    move-result-wide v2

    .line 14
    invoke-static {v2, v3}, Lzo/e;->c(J)Ljava/time/OffsetDateTime;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-static {v2}, Lvo/a;->l(Ljava/time/OffsetDateTime;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    const-string v2, "8.8.0"

    .line 23
    .line 24
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    iget-object p0, p0, Lg70/j;->o:Lij0/a;

    .line 29
    .line 30
    move-object v4, p0

    .line 31
    check-cast v4, Ljj0/f;

    .line 32
    .line 33
    const v5, 0x7f1202b6

    .line 34
    .line 35
    .line 36
    invoke-virtual {v4, v5, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    const/4 v2, 0x0

    .line 41
    new-array v5, v2, [Ljava/lang/Object;

    .line 42
    .line 43
    move-object v6, p0

    .line 44
    check-cast v6, Ljj0/f;

    .line 45
    .line 46
    const v7, 0x7f120f76

    .line 47
    .line 48
    .line 49
    invoke-virtual {v6, v7, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v5

    .line 53
    new-array v6, v2, [Ljava/lang/Object;

    .line 54
    .line 55
    move-object v7, p0

    .line 56
    check-cast v7, Ljj0/f;

    .line 57
    .line 58
    const v8, 0x7f120f75

    .line 59
    .line 60
    .line 61
    invoke-virtual {v7, v8, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v6

    .line 65
    new-array v7, v2, [Ljava/lang/Object;

    .line 66
    .line 67
    move-object v8, p0

    .line 68
    check-cast v8, Ljj0/f;

    .line 69
    .line 70
    const v9, 0x7f12038b

    .line 71
    .line 72
    .line 73
    invoke-virtual {v8, v9, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v7

    .line 77
    new-array v2, v2, [Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Ljj0/f;

    .line 80
    .line 81
    const v8, 0x7f120373

    .line 82
    .line 83
    .line 84
    invoke-virtual {p0, v8, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v8

    .line 88
    const/4 v2, 0x0

    .line 89
    invoke-direct/range {v0 .. v8}, Lql0/g;-><init>(Lql0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    return-object v0
.end method

.method public final j()V
    .locals 13

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lg70/i;

    .line 6
    .line 7
    iget-boolean v0, v0, Lg70/i;->e:Z

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    move-object v1, v0

    .line 16
    check-cast v1, Lg70/i;

    .line 17
    .line 18
    const/4 v11, 0x0

    .line 19
    const/16 v12, 0x7cf

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    const/4 v3, 0x0

    .line 23
    const/4 v4, 0x0

    .line 24
    const/4 v5, 0x0

    .line 25
    const/4 v6, 0x0

    .line 26
    const/4 v7, 0x0

    .line 27
    const/4 v8, 0x0

    .line 28
    const/4 v9, 0x0

    .line 29
    const/4 v10, 0x0

    .line 30
    invoke-static/range {v1 .. v12}, Lg70/i;->a(Lg70/i;Ljava/lang/String;Ljava/lang/String;Lhp0/e;ZZZZZZLql0/g;I)Lg70/i;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_0
    iget-object p0, p0, Lg70/j;->h:Ltr0/b;

    .line 39
    .line 40
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    return-void
.end method
