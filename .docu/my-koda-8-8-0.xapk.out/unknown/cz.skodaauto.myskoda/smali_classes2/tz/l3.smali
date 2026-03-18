.class public final Ltz/l3;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final m:Ljava/util/Set;


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lbh0/g;

.field public final j:Lbh0/j;

.field public final k:Lbd0/c;

.field public final l:Lfj0/b;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    const-string v7, "no"

    .line 2
    .line 3
    const-string v8, "sv"

    .line 4
    .line 5
    const-string v0, "cs"

    .line 6
    .line 7
    const-string v1, "da"

    .line 8
    .line 9
    const-string v2, "de"

    .line 10
    .line 11
    const-string v3, "es"

    .line 12
    .line 13
    const-string v4, "fi"

    .line 14
    .line 15
    const-string v5, "fr"

    .line 16
    .line 17
    const-string v6, "it"

    .line 18
    .line 19
    filled-new-array/range {v0 .. v8}, [Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sput-object v0, Ltz/l3;->m:Ljava/util/Set;

    .line 28
    .line 29
    return-void
.end method

.method public constructor <init>(Ltr0/b;Lbh0/g;Lbh0/j;Lbd0/c;Lfj0/b;)V
    .locals 1

    .line 1
    sget-object v0, Ltz/b3;->b:Ltz/b3;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltz/l3;->h:Ltr0/b;

    .line 7
    .line 8
    iput-object p2, p0, Ltz/l3;->i:Lbh0/g;

    .line 9
    .line 10
    iput-object p3, p0, Ltz/l3;->j:Lbh0/j;

    .line 11
    .line 12
    iput-object p4, p0, Ltz/l3;->k:Lbd0/c;

    .line 13
    .line 14
    iput-object p5, p0, Ltz/l3;->l:Lfj0/b;

    .line 15
    .line 16
    return-void
.end method

.method public static final h(Ltz/l3;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Ltz/j3;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Ltz/j3;

    .line 10
    .line 11
    iget v1, v0, Ltz/j3;->i:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    and-int v3, v1, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    iput v1, v0, Ltz/j3;->i:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Ltz/j3;

    .line 24
    .line 25
    invoke-direct {v0, p0, p1}, Ltz/j3;-><init>(Ltz/l3;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p1, v0, Ltz/j3;->g:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Ltz/j3;->i:I

    .line 33
    .line 34
    const/4 v3, 0x1

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-object p0, v0, Ltz/j3;->f:[Ljava/lang/Object;

    .line 40
    .line 41
    iget-object v1, v0, Ltz/j3;->e:[Ljava/lang/Object;

    .line 42
    .line 43
    iget-object v0, v0, Ltz/j3;->d:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    new-array p1, v3, [Ljava/lang/Object;

    .line 61
    .line 62
    const-string v2, "https://elli.my.site.com/PowerpassFaq/s/?language=%s"

    .line 63
    .line 64
    iput-object v2, v0, Ltz/j3;->d:Ljava/lang/String;

    .line 65
    .line 66
    iput-object p1, v0, Ltz/j3;->e:[Ljava/lang/Object;

    .line 67
    .line 68
    iput-object p1, v0, Ltz/j3;->f:[Ljava/lang/Object;

    .line 69
    .line 70
    iput v3, v0, Ltz/j3;->i:I

    .line 71
    .line 72
    invoke-virtual {p0, v0}, Ltz/l3;->j(Lrx0/c;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    if-ne p0, v1, :cond_3

    .line 77
    .line 78
    return-object v1

    .line 79
    :cond_3
    move-object v1, p1

    .line 80
    move-object v0, v2

    .line 81
    move-object p1, p0

    .line 82
    move-object p0, v1

    .line 83
    :goto_1
    const/4 v2, 0x0

    .line 84
    aput-object p1, p0, v2

    .line 85
    .line 86
    array-length p0, v1

    .line 87
    invoke-static {v1, p0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-static {v0, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0
.end method


# virtual methods
.method public final j(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Ltz/i3;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Ltz/i3;

    .line 7
    .line 8
    iget v1, v0, Ltz/i3;->f:I

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
    iput v1, v0, Ltz/i3;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ltz/i3;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Ltz/i3;-><init>(Ltz/l3;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Ltz/i3;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ltz/i3;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput v3, v0, Ltz/i3;->f:I

    .line 52
    .line 53
    iget-object p0, p0, Ltz/l3;->l:Lfj0/b;

    .line 54
    .line 55
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Lfj0/b;->a:Lfj0/e;

    .line 59
    .line 60
    check-cast p0, Ldj0/b;

    .line 61
    .line 62
    iget-object p0, p0, Ldj0/b;->h:Lyy0/l1;

    .line 63
    .line 64
    iget-object p0, p0, Lyy0/l1;->d:Lyy0/a2;

    .line 65
    .line 66
    invoke-interface {p0}, Lyy0/a2;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v1, :cond_3

    .line 71
    .line 72
    return-object v1

    .line 73
    :cond_3
    :goto_1
    check-cast p1, Ljava/util/Locale;

    .line 74
    .line 75
    invoke-virtual {p1}, Ljava/util/Locale;->getLanguage()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    sget-object p1, Ltz/l3;->m:Ljava/util/Set;

    .line 80
    .line 81
    invoke-interface {p1, p0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result p1

    .line 85
    if-eqz p1, :cond_4

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    const/4 p0, 0x0

    .line 89
    :goto_2
    if-nez p0, :cond_5

    .line 90
    .line 91
    const-string p0, "en_US"

    .line 92
    .line 93
    :cond_5
    return-object p0
.end method
