.class public final Lqg/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lqg/a;

.field public static final b:Lqg/i;


# direct methods
.method static constructor <clinit>()V
    .locals 13

    .line 1
    new-instance v0, Lqg/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lqg/a;->a:Lqg/a;

    .line 7
    .line 8
    new-instance v1, Lqg/i;

    .line 9
    .line 10
    new-instance v2, Lqg/j;

    .line 11
    .line 12
    new-instance v10, Lqg/b;

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    const/4 v3, 0x0

    .line 16
    const-string v4, ""

    .line 17
    .line 18
    invoke-direct {v10, v0, v4, v3, v4}, Lqg/b;-><init>(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v12, ""

    .line 22
    .line 23
    const-string v3, ""

    .line 24
    .line 25
    const-string v4, ""

    .line 26
    .line 27
    const-string v5, ""

    .line 28
    .line 29
    const-string v6, ""

    .line 30
    .line 31
    const-string v7, ""

    .line 32
    .line 33
    const/4 v8, 0x0

    .line 34
    sget-object v9, Lmx0/s;->d:Lmx0/s;

    .line 35
    .line 36
    move-object v11, v9

    .line 37
    invoke-direct/range {v2 .. v12}, Lqg/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/util/List;Lqg/b;Ljava/util/List;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    const/4 v6, 0x0

    .line 41
    const-string v7, ""

    .line 42
    .line 43
    const/4 v3, 0x0

    .line 44
    const/4 v4, 0x0

    .line 45
    const-string v5, ""

    .line 46
    .line 47
    invoke-direct/range {v1 .. v7}, Lqg/i;-><init>(Lqg/j;ZZLjava/lang/String;ZLjava/lang/String;)V

    .line 48
    .line 49
    .line 50
    sput-object v1, Lqg/a;->b:Lqg/i;

    .line 51
    .line 52
    return-void
.end method

.method public static a(Lkg/p0;Lqg/b;)Lqg/j;
    .locals 11

    .line 1
    iget-object v1, p0, Lkg/p0;->d:Ljava/lang/String;

    .line 2
    .line 3
    iget-object v0, p0, Lkg/p0;->g:Lkg/o;

    .line 4
    .line 5
    iget-object v2, v0, Lkg/o;->d:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, v0, Lkg/o;->e:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lkg/p0;->e:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, Lkg/p0;->n:Ljava/lang/String;

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    const-string v5, ""

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move-object v5, v0

    .line 19
    :goto_0
    const/4 v6, 0x1

    .line 20
    if-eqz v0, :cond_2

    .line 21
    .line 22
    invoke-static {v0}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    const/4 v0, 0x0

    .line 30
    goto :goto_2

    .line 31
    :cond_2
    :goto_1
    move v0, v6

    .line 32
    :goto_2
    xor-int/2addr v6, v0

    .line 33
    iget-object v0, p0, Lkg/p0;->i:Ljava/util/List;

    .line 34
    .line 35
    check-cast v0, Ljava/lang/Iterable;

    .line 36
    .line 37
    new-instance v7, Ljava/util/ArrayList;

    .line 38
    .line 39
    const/16 v8, 0xa

    .line 40
    .line 41
    invoke-static {v0, v8}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 42
    .line 43
    .line 44
    move-result v8

    .line 45
    invoke-direct {v7, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 46
    .line 47
    .line 48
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result v8

    .line 56
    if-eqz v8, :cond_3

    .line 57
    .line 58
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v8

    .line 62
    check-cast v8, Lkg/i;

    .line 63
    .line 64
    invoke-static {v8}, Llp/q1;->b(Lkg/i;)Lug/d;

    .line 65
    .line 66
    .line 67
    move-result-object v8

    .line 68
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_3
    iget-object v9, p0, Lkg/p0;->f:Ljava/util/List;

    .line 73
    .line 74
    iget-object v10, p0, Lkg/p0;->l:Ljava/lang/String;

    .line 75
    .line 76
    new-instance v0, Lqg/j;

    .line 77
    .line 78
    move-object v8, p1

    .line 79
    invoke-direct/range {v0 .. v10}, Lqg/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLjava/util/List;Lqg/b;Ljava/util/List;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    return-object v0
.end method
