.class public final Lly0/k;
.super Lmx0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lly0/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lly0/k;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final c()I
    .locals 1

    .line 1
    iget v0, p0, Lly0/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lly0/k;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lsy0/c;

    .line 9
    .line 10
    invoke-virtual {p0}, Lsy0/c;->c()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lly0/k;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lq2/b;

    .line 18
    .line 19
    invoke-virtual {p0}, Lq2/b;->c()I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :pswitch_1
    iget-object p0, p0, Lly0/k;->e:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, Lly0/l;

    .line 27
    .line 28
    iget-object p0, p0, Lly0/l;->a:Ljava/util/regex/Matcher;

    .line 29
    .line 30
    invoke-virtual {p0}, Ljava/util/regex/Matcher;->groupCount()I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    add-int/lit8 p0, p0, 0x1

    .line 35
    .line 36
    return p0

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget v0, p0, Lly0/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lly0/k;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lsy0/c;

    .line 9
    .line 10
    invoke-virtual {p0, p1}, Lmx0/f;->containsValue(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lly0/k;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lq2/b;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Lmx0/f;->containsValue(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0

    .line 24
    :pswitch_1
    if-nez p1, :cond_0

    .line 25
    .line 26
    const/4 v0, 0x1

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    instance-of v0, p1, Lly0/i;

    .line 29
    .line 30
    :goto_0
    if-nez v0, :cond_1

    .line 31
    .line 32
    const/4 p0, 0x0

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    check-cast p1, Lly0/i;

    .line 35
    .line 36
    invoke-super {p0, p1}, Lmx0/a;->contains(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    :goto_1
    return p0

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public e(I)Lly0/i;
    .locals 2

    .line 1
    iget-object p0, p0, Lly0/k;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lly0/l;

    .line 4
    .line 5
    iget-object p0, p0, Lly0/l;->a:Ljava/util/regex/Matcher;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/util/regex/Matcher;->start(I)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p0, p1}, Ljava/util/regex/Matcher;->end(I)I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    invoke-static {v0, v1}, Lkp/r9;->m(II)Lgy0/j;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    iget v1, v0, Lgy0/h;->d:I

    .line 20
    .line 21
    if-ltz v1, :cond_0

    .line 22
    .line 23
    new-instance v1, Lly0/i;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const-string p1, "group(...)"

    .line 30
    .line 31
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-direct {v1, p0, v0}, Lly0/i;-><init>(Ljava/lang/String;Lgy0/j;)V

    .line 35
    .line 36
    .line 37
    return-object v1

    .line 38
    :cond_0
    const/4 p0, 0x0

    .line 39
    return-object p0
.end method

.method public isEmpty()Z
    .locals 1

    .line 1
    iget v0, p0, Lly0/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Lmx0/a;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    const/4 p0, 0x0

    .line 12
    return p0

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 6

    .line 1
    iget v0, p0, Lly0/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lsy0/i;

    .line 7
    .line 8
    iget-object p0, p0, Lly0/k;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lsy0/c;

    .line 11
    .line 12
    iget-object p0, p0, Lsy0/c;->d:Lsy0/j;

    .line 13
    .line 14
    const-string v1, "node"

    .line 15
    .line 16
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const/16 v1, 0x8

    .line 20
    .line 21
    new-array v2, v1, [Lq2/j;

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    :goto_0
    if-ge v3, v1, :cond_0

    .line 25
    .line 26
    new-instance v4, Lsy0/k;

    .line 27
    .line 28
    const/4 v5, 0x2

    .line 29
    invoke-direct {v4, v5}, Lsy0/k;-><init>(I)V

    .line 30
    .line 31
    .line 32
    aput-object v4, v2, v3

    .line 33
    .line 34
    add-int/lit8 v3, v3, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    invoke-direct {v0, p0, v2}, Lq2/c;-><init>(Lsy0/j;[Lq2/j;)V

    .line 38
    .line 39
    .line 40
    return-object v0

    .line 41
    :pswitch_0
    new-instance v0, Lq2/h;

    .line 42
    .line 43
    iget-object p0, p0, Lly0/k;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Lq2/b;

    .line 46
    .line 47
    iget-object p0, p0, Lq2/b;->d:Lq2/i;

    .line 48
    .line 49
    const/16 v1, 0x8

    .line 50
    .line 51
    new-array v2, v1, [Lq2/j;

    .line 52
    .line 53
    const/4 v3, 0x0

    .line 54
    :goto_1
    if-ge v3, v1, :cond_1

    .line 55
    .line 56
    new-instance v4, Lq2/k;

    .line 57
    .line 58
    const/4 v5, 0x2

    .line 59
    invoke-direct {v4, v5}, Lq2/k;-><init>(I)V

    .line 60
    .line 61
    .line 62
    aput-object v4, v2, v3

    .line 63
    .line 64
    add-int/lit8 v3, v3, 0x1

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_1
    invoke-direct {v0, p0, v2}, Lq2/c;-><init>(Lq2/i;[Lq2/j;)V

    .line 68
    .line 69
    .line 70
    return-object v0

    .line 71
    :pswitch_1
    invoke-static {p0}, Ljp/k1;->g(Ljava/util/Collection;)Lgy0/j;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-static {v0}, Lmx0/q;->z(Ljava/lang/Iterable;)Lky0/m;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    new-instance v1, Lla/p;

    .line 80
    .line 81
    const/4 v2, 0x1

    .line 82
    invoke-direct {v1, p0, v2}, Lla/p;-><init>(Ljava/lang/Object;I)V

    .line 83
    .line 84
    .line 85
    invoke-static {v0, v1}, Lky0/l;->n(Lky0/j;Lay0/k;)Lky0/s;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    new-instance v0, Ld6/b0;

    .line 90
    .line 91
    invoke-direct {v0, p0}, Ld6/b0;-><init>(Lky0/s;)V

    .line 92
    .line 93
    .line 94
    return-object v0

    .line 95
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
