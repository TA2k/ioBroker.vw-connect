.class public final Lp2/i;
.super Lp2/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lp2/i;


# instance fields
.field public final d:[Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lp2/i;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v1, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0, v1}, Lp2/i;-><init>([Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lp2/i;->e:Lp2/i;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>([Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final c()I
    .locals 0

    .line 1
    iget-object p0, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length p0, p0

    .line 4
    return p0
.end method

.method public final e(ILjava/lang/Object;)Lp2/c;
    .locals 5

    .line 1
    iget-object v0, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    invoke-static {p1, v1}, Lkp/w6;->b(II)V

    .line 5
    .line 6
    .line 7
    array-length v1, v0

    .line 8
    if-ne p1, v1, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0, p2}, Lp2/i;->g(Ljava/lang/Object;)Lp2/c;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0

    .line 15
    :cond_0
    array-length p0, v0

    .line 16
    const/16 v1, 0x20

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    if-ge p0, v1, :cond_1

    .line 20
    .line 21
    array-length p0, v0

    .line 22
    add-int/lit8 p0, p0, 0x1

    .line 23
    .line 24
    new-array p0, p0, [Ljava/lang/Object;

    .line 25
    .line 26
    const/4 v1, 0x6

    .line 27
    invoke-static {v2, p1, v1, v0, p0}, Lmx0/n;->m(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    add-int/lit8 v1, p1, 0x1

    .line 31
    .line 32
    array-length v2, v0

    .line 33
    invoke-static {v1, p1, v2, v0, p0}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    aput-object p2, p0, p1

    .line 37
    .line 38
    new-instance p1, Lp2/i;

    .line 39
    .line 40
    invoke-direct {p1, p0}, Lp2/i;-><init>([Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    return-object p1

    .line 44
    :cond_1
    array-length p0, v0

    .line 45
    invoke-static {v0, p0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    const-string v3, "copyOf(...)"

    .line 50
    .line 51
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    add-int/lit8 v3, p1, 0x1

    .line 55
    .line 56
    array-length v4, v0

    .line 57
    add-int/lit8 v4, v4, -0x1

    .line 58
    .line 59
    invoke-static {v3, p1, v4, v0, p0}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    aput-object p2, p0, p1

    .line 63
    .line 64
    const/16 p1, 0x1f

    .line 65
    .line 66
    aget-object p1, v0, p1

    .line 67
    .line 68
    new-array p2, v1, [Ljava/lang/Object;

    .line 69
    .line 70
    aput-object p1, p2, v2

    .line 71
    .line 72
    new-instance p1, Lp2/e;

    .line 73
    .line 74
    array-length v0, v0

    .line 75
    add-int/lit8 v0, v0, 0x1

    .line 76
    .line 77
    invoke-direct {p1, p0, p2, v0, v2}, Lp2/e;-><init>([Ljava/lang/Object;[Ljava/lang/Object;II)V

    .line 78
    .line 79
    .line 80
    return-object p1
.end method

.method public final g(Ljava/lang/Object;)Lp2/c;
    .locals 3

    .line 1
    iget-object p0, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    const/16 v1, 0x20

    .line 5
    .line 6
    if-ge v0, v1, :cond_0

    .line 7
    .line 8
    array-length v0, p0

    .line 9
    add-int/lit8 v0, v0, 0x1

    .line 10
    .line 11
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, "copyOf(...)"

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    array-length p0, p0

    .line 21
    aput-object p1, v0, p0

    .line 22
    .line 23
    new-instance p0, Lp2/i;

    .line 24
    .line 25
    invoke-direct {p0, v0}, Lp2/i;-><init>([Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_0
    new-array v0, v1, [Ljava/lang/Object;

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    aput-object p1, v0, v1

    .line 33
    .line 34
    new-instance p1, Lp2/e;

    .line 35
    .line 36
    array-length v2, p0

    .line 37
    add-int/lit8 v2, v2, 0x1

    .line 38
    .line 39
    invoke-direct {p1, p0, v0, v2, v1}, Lp2/e;-><init>([Ljava/lang/Object;[Ljava/lang/Object;II)V

    .line 40
    .line 41
    .line 42
    return-object p1
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lp2/i;->c()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p1, v0}, Lkp/w6;->a(II)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 9
    .line 10
    aget-object p0, p0, p1

    .line 11
    .line 12
    return-object p0
.end method

.method public final i(Ljava/util/Collection;)Lp2/c;
    .locals 3

    .line 1
    iget-object v0, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 5
    .line 6
    .line 7
    move-result v2

    .line 8
    add-int/2addr v2, v1

    .line 9
    const/16 v1, 0x20

    .line 10
    .line 11
    if-gt v2, v1, :cond_1

    .line 12
    .line 13
    array-length p0, v0

    .line 14
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    add-int/2addr v1, p0

    .line 19
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string v1, "copyOf(...)"

    .line 24
    .line 25
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    array-length v0, v0

    .line 29
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_0

    .line 38
    .line 39
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    add-int/lit8 v2, v0, 0x1

    .line 44
    .line 45
    aput-object v1, p0, v0

    .line 46
    .line 47
    move v0, v2

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    new-instance p1, Lp2/i;

    .line 50
    .line 51
    invoke-direct {p1, p0}, Lp2/i;-><init>([Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    return-object p1

    .line 55
    :cond_1
    invoke-virtual {p0}, Lp2/i;->k()Lp2/f;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-virtual {p0, p1}, Lp2/f;->addAll(Ljava/util/Collection;)Z

    .line 60
    .line 61
    .line 62
    invoke-virtual {p0}, Lp2/f;->g()Lp2/c;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0
.end method

.method public final indexOf(Ljava/lang/Object;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    invoke-static {p1, p0}, Lmx0/n;->D(Ljava/lang/Object;[Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final k()Lp2/f;
    .locals 4

    .line 1
    new-instance v0, Lp2/f;

    .line 2
    .line 3
    iget-object v1, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, p0, v3, v1, v2}, Lp2/f;-><init>(Lp2/c;[Ljava/lang/Object;[Ljava/lang/Object;I)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public final lastIndexOf(Ljava/lang/Object;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    invoke-static {p1, p0}, Lmx0/n;->J(Ljava/lang/Object;[Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final listIterator(I)Ljava/util/ListIterator;
    .locals 2

    .line 1
    iget-object p0, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    invoke-static {p1, v0}, Lkp/w6;->b(II)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lp2/d;

    .line 8
    .line 9
    array-length v1, p0

    .line 10
    invoke-direct {v0, p0, p1, v1}, Lp2/d;-><init>([Ljava/lang/Object;II)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public final m(Lp2/b;)Lp2/c;
    .locals 9

    .line 1
    iget-object v0, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    array-length v2, v0

    .line 5
    const/4 v3, 0x0

    .line 6
    move-object v6, v0

    .line 7
    move v4, v3

    .line 8
    move v5, v4

    .line 9
    :goto_0
    if-ge v4, v2, :cond_2

    .line 10
    .line 11
    aget-object v7, v0, v4

    .line 12
    .line 13
    invoke-virtual {p1, v7}, Lp2/b;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v8

    .line 17
    check-cast v8, Ljava/lang/Boolean;

    .line 18
    .line 19
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 20
    .line 21
    .line 22
    move-result v8

    .line 23
    if-eqz v8, :cond_0

    .line 24
    .line 25
    if-nez v5, :cond_1

    .line 26
    .line 27
    array-length v1, v0

    .line 28
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v6

    .line 32
    const-string v1, "copyOf(...)"

    .line 33
    .line 34
    invoke-static {v6, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const/4 v5, 0x1

    .line 38
    move v1, v4

    .line 39
    goto :goto_1

    .line 40
    :cond_0
    if-eqz v5, :cond_1

    .line 41
    .line 42
    add-int/lit8 v8, v1, 0x1

    .line 43
    .line 44
    aput-object v7, v6, v1

    .line 45
    .line 46
    move v1, v8

    .line 47
    :cond_1
    :goto_1
    add-int/lit8 v4, v4, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_2
    array-length p1, v0

    .line 51
    if-ne v1, p1, :cond_3

    .line 52
    .line 53
    return-object p0

    .line 54
    :cond_3
    if-nez v1, :cond_4

    .line 55
    .line 56
    sget-object p0, Lp2/i;->e:Lp2/i;

    .line 57
    .line 58
    return-object p0

    .line 59
    :cond_4
    new-instance p0, Lp2/i;

    .line 60
    .line 61
    invoke-static {v3, v1, v6}, Lmx0/n;->o(II[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-direct {p0, p1}, Lp2/i;-><init>([Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    return-object p0
.end method

.method public final n(I)Lp2/c;
    .locals 3

    .line 1
    iget-object p0, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    invoke-static {p1, v0}, Lkp/w6;->a(II)V

    .line 5
    .line 6
    .line 7
    array-length v0, p0

    .line 8
    const/4 v1, 0x1

    .line 9
    if-ne v0, v1, :cond_0

    .line 10
    .line 11
    sget-object p0, Lp2/i;->e:Lp2/i;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    array-length v0, p0

    .line 15
    sub-int/2addr v0, v1

    .line 16
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const-string v1, "copyOf(...)"

    .line 21
    .line 22
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    add-int/lit8 v1, p1, 0x1

    .line 26
    .line 27
    array-length v2, p0

    .line 28
    invoke-static {p1, v1, v2, p0, v0}, Lmx0/n;->i(III[Ljava/lang/Object;[Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    new-instance p0, Lp2/i;

    .line 32
    .line 33
    invoke-direct {p0, v0}, Lp2/i;-><init>([Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    return-object p0
.end method

.method public final o(ILjava/lang/Object;)Lp2/c;
    .locals 1

    .line 1
    iget-object p0, p0, Lp2/i;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    invoke-static {p1, v0}, Lkp/w6;->a(II)V

    .line 5
    .line 6
    .line 7
    array-length v0, p0

    .line 8
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    const-string v0, "copyOf(...)"

    .line 13
    .line 14
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    aput-object p2, p0, p1

    .line 18
    .line 19
    new-instance p1, Lp2/i;

    .line 20
    .line 21
    invoke-direct {p1, p0}, Lp2/i;-><init>([Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-object p1
.end method
