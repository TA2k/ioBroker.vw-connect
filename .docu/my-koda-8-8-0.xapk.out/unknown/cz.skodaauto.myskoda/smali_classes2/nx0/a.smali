.class public final Lnx0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/ListIterator;
.implements Lby0/a;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:I

.field public g:I

.field public final h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lnx0/b;I)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lnx0/a;->d:I

    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    iput-object p1, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 19
    iput p2, p0, Lnx0/a;->e:I

    const/4 p2, -0x1

    .line 20
    iput p2, p0, Lnx0/a;->f:I

    .line 21
    invoke-static {p1}, Lnx0/b;->g(Lnx0/b;)I

    move-result p1

    iput p1, p0, Lnx0/a;->g:I

    return-void
.end method

.method public constructor <init>(Lnx0/c;I)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lnx0/a;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 6
    iput p2, p0, Lnx0/a;->e:I

    const/4 p2, -0x1

    .line 7
    iput p2, p0, Lnx0/a;->f:I

    .line 8
    invoke-static {p1}, Lnx0/c;->g(Lnx0/c;)I

    move-result p1

    iput p1, p0, Lnx0/a;->g:I

    return-void
.end method

.method public constructor <init>(Lv2/o;I)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lnx0/a;->d:I

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lnx0/a;->h:Ljava/lang/Object;

    add-int/lit8 p2, p2, -0x1

    .line 10
    iput p2, p0, Lnx0/a;->e:I

    const/4 p2, -0x1

    .line 11
    iput p2, p0, Lnx0/a;->f:I

    .line 12
    invoke-static {p1}, Lv2/p;->f(Lv2/o;)I

    move-result p1

    iput p1, p0, Lnx0/a;->g:I

    return-void
.end method

.method public constructor <init>(Lv3/s;II)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lnx0/a;->d:I

    and-int/lit8 p3, p3, 0x1

    const/4 v0, 0x0

    if-eqz p3, :cond_0

    move p2, v0

    .line 1
    :cond_0
    iget-object p3, p1, Lv3/s;->d:Landroidx/collection/l0;

    .line 2
    iget p3, p3, Landroidx/collection/l0;->b:I

    .line 3
    invoke-direct {p0, p1, p2, v0, p3}, Lnx0/a;-><init>(Lv3/s;III)V

    return-void
.end method

.method public constructor <init>(Lv3/s;III)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lnx0/a;->d:I

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 14
    iput p2, p0, Lnx0/a;->e:I

    .line 15
    iput p3, p0, Lnx0/a;->f:I

    .line 16
    iput p4, p0, Lnx0/a;->g:I

    return-void
.end method


# virtual methods
.method public a()V
    .locals 1

    .line 1
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lnx0/b;

    .line 4
    .line 5
    iget-object v0, v0, Lnx0/b;->h:Lnx0/c;

    .line 6
    .line 7
    invoke-static {v0}, Lnx0/c;->g(Lnx0/c;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget p0, p0, Lnx0/a;->g:I

    .line 12
    .line 13
    if-ne v0, p0, :cond_0

    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 17
    .line 18
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 19
    .line 20
    .line 21
    throw p0
.end method

.method public final add(Ljava/lang/Object;)V
    .locals 3

    .line 1
    iget v0, p0, Lnx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 7
    .line 8
    const-string p1, "Operation is not supported for read-only collection"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    invoke-virtual {p0}, Lnx0/a;->c()V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lv2/o;

    .line 20
    .line 21
    iget v1, p0, Lnx0/a;->e:I

    .line 22
    .line 23
    add-int/lit8 v1, v1, 0x1

    .line 24
    .line 25
    invoke-virtual {v0, v1, p1}, Lv2/o;->add(ILjava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    const/4 p1, -0x1

    .line 29
    iput p1, p0, Lnx0/a;->f:I

    .line 30
    .line 31
    iget p1, p0, Lnx0/a;->e:I

    .line 32
    .line 33
    add-int/lit8 p1, p1, 0x1

    .line 34
    .line 35
    iput p1, p0, Lnx0/a;->e:I

    .line 36
    .line 37
    invoke-static {v0}, Lv2/p;->f(Lv2/o;)I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    iput p1, p0, Lnx0/a;->g:I

    .line 42
    .line 43
    return-void

    .line 44
    :pswitch_1
    invoke-virtual {p0}, Lnx0/a;->b()V

    .line 45
    .line 46
    .line 47
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v0, Lnx0/c;

    .line 50
    .line 51
    iget v1, p0, Lnx0/a;->e:I

    .line 52
    .line 53
    add-int/lit8 v2, v1, 0x1

    .line 54
    .line 55
    iput v2, p0, Lnx0/a;->e:I

    .line 56
    .line 57
    invoke-virtual {v0, v1, p1}, Lnx0/c;->add(ILjava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    const/4 p1, -0x1

    .line 61
    iput p1, p0, Lnx0/a;->f:I

    .line 62
    .line 63
    invoke-static {v0}, Lnx0/c;->g(Lnx0/c;)I

    .line 64
    .line 65
    .line 66
    move-result p1

    .line 67
    iput p1, p0, Lnx0/a;->g:I

    .line 68
    .line 69
    return-void

    .line 70
    :pswitch_2
    invoke-virtual {p0}, Lnx0/a;->a()V

    .line 71
    .line 72
    .line 73
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v0, Lnx0/b;

    .line 76
    .line 77
    iget v1, p0, Lnx0/a;->e:I

    .line 78
    .line 79
    add-int/lit8 v2, v1, 0x1

    .line 80
    .line 81
    iput v2, p0, Lnx0/a;->e:I

    .line 82
    .line 83
    invoke-virtual {v0, v1, p1}, Lnx0/b;->add(ILjava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    const/4 p1, -0x1

    .line 87
    iput p1, p0, Lnx0/a;->f:I

    .line 88
    .line 89
    invoke-static {v0}, Lnx0/b;->g(Lnx0/b;)I

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    iput p1, p0, Lnx0/a;->g:I

    .line 94
    .line 95
    return-void

    .line 96
    nop

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public b()V
    .locals 1

    .line 1
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lnx0/c;

    .line 4
    .line 5
    invoke-static {v0}, Lnx0/c;->g(Lnx0/c;)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget p0, p0, Lnx0/a;->g:I

    .line 10
    .line 11
    if-ne v0, p0, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public c()V
    .locals 1

    .line 1
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lv2/o;

    .line 4
    .line 5
    invoke-static {v0}, Lv2/p;->f(Lv2/o;)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget p0, p0, Lnx0/a;->g:I

    .line 10
    .line 11
    if-ne v0, p0, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public final hasNext()Z
    .locals 2

    .line 1
    iget v0, p0, Lnx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lnx0/a;->e:I

    .line 7
    .line 8
    iget p0, p0, Lnx0/a;->g:I

    .line 9
    .line 10
    if-ge v0, p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    :goto_0
    return p0

    .line 16
    :pswitch_0
    iget v0, p0, Lnx0/a;->e:I

    .line 17
    .line 18
    iget-object p0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lv2/o;

    .line 21
    .line 22
    invoke-virtual {p0}, Lv2/o;->size()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    const/4 v1, 0x1

    .line 27
    sub-int/2addr p0, v1

    .line 28
    if-ge v0, p0, :cond_1

    .line 29
    .line 30
    goto :goto_1

    .line 31
    :cond_1
    const/4 v1, 0x0

    .line 32
    :goto_1
    return v1

    .line 33
    :pswitch_1
    iget v0, p0, Lnx0/a;->e:I

    .line 34
    .line 35
    iget-object p0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Lnx0/c;

    .line 38
    .line 39
    iget p0, p0, Lnx0/c;->e:I

    .line 40
    .line 41
    if-ge v0, p0, :cond_2

    .line 42
    .line 43
    const/4 p0, 0x1

    .line 44
    goto :goto_2

    .line 45
    :cond_2
    const/4 p0, 0x0

    .line 46
    :goto_2
    return p0

    .line 47
    :pswitch_2
    iget v0, p0, Lnx0/a;->e:I

    .line 48
    .line 49
    iget-object p0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Lnx0/b;

    .line 52
    .line 53
    iget p0, p0, Lnx0/b;->f:I

    .line 54
    .line 55
    if-ge v0, p0, :cond_3

    .line 56
    .line 57
    const/4 p0, 0x1

    .line 58
    goto :goto_3

    .line 59
    :cond_3
    const/4 p0, 0x0

    .line 60
    :goto_3
    return p0

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final hasPrevious()Z
    .locals 1

    .line 1
    iget v0, p0, Lnx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lnx0/a;->e:I

    .line 7
    .line 8
    iget p0, p0, Lnx0/a;->f:I

    .line 9
    .line 10
    if-le v0, p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    :goto_0
    return p0

    .line 16
    :pswitch_0
    iget p0, p0, Lnx0/a;->e:I

    .line 17
    .line 18
    if-ltz p0, :cond_1

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    goto :goto_1

    .line 22
    :cond_1
    const/4 p0, 0x0

    .line 23
    :goto_1
    return p0

    .line 24
    :pswitch_1
    iget p0, p0, Lnx0/a;->e:I

    .line 25
    .line 26
    if-lez p0, :cond_2

    .line 27
    .line 28
    const/4 p0, 0x1

    .line 29
    goto :goto_2

    .line 30
    :cond_2
    const/4 p0, 0x0

    .line 31
    :goto_2
    return p0

    .line 32
    :pswitch_2
    iget p0, p0, Lnx0/a;->e:I

    .line 33
    .line 34
    if-lez p0, :cond_3

    .line 35
    .line 36
    const/4 p0, 0x1

    .line 37
    goto :goto_3

    .line 38
    :cond_3
    const/4 p0, 0x0

    .line 39
    :goto_3
    return p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lnx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lv3/s;

    .line 9
    .line 10
    iget-object v0, v0, Lv3/s;->d:Landroidx/collection/l0;

    .line 11
    .line 12
    iget v1, p0, Lnx0/a;->e:I

    .line 13
    .line 14
    add-int/lit8 v2, v1, 0x1

    .line 15
    .line 16
    iput v2, p0, Lnx0/a;->e:I

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.Modifier.Node"

    .line 23
    .line 24
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    check-cast p0, Lx2/r;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    invoke-virtual {p0}, Lnx0/a;->c()V

    .line 31
    .line 32
    .line 33
    iget v0, p0, Lnx0/a;->e:I

    .line 34
    .line 35
    add-int/lit8 v0, v0, 0x1

    .line 36
    .line 37
    iput v0, p0, Lnx0/a;->f:I

    .line 38
    .line 39
    iget-object v1, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v1, Lv2/o;

    .line 42
    .line 43
    invoke-virtual {v1}, Lv2/o;->size()I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    invoke-static {v0, v2}, Lv2/p;->a(II)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v1, v0}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    iput v0, p0, Lnx0/a;->e:I

    .line 55
    .line 56
    return-object v1

    .line 57
    :pswitch_1
    invoke-virtual {p0}, Lnx0/a;->b()V

    .line 58
    .line 59
    .line 60
    iget v0, p0, Lnx0/a;->e:I

    .line 61
    .line 62
    iget-object v1, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast v1, Lnx0/c;

    .line 65
    .line 66
    iget v2, v1, Lnx0/c;->e:I

    .line 67
    .line 68
    if-ge v0, v2, :cond_0

    .line 69
    .line 70
    add-int/lit8 v2, v0, 0x1

    .line 71
    .line 72
    iput v2, p0, Lnx0/a;->e:I

    .line 73
    .line 74
    iput v0, p0, Lnx0/a;->f:I

    .line 75
    .line 76
    iget-object p0, v1, Lnx0/c;->d:[Ljava/lang/Object;

    .line 77
    .line 78
    aget-object p0, p0, v0

    .line 79
    .line 80
    return-object p0

    .line 81
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 82
    .line 83
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :pswitch_2
    invoke-virtual {p0}, Lnx0/a;->a()V

    .line 88
    .line 89
    .line 90
    iget v0, p0, Lnx0/a;->e:I

    .line 91
    .line 92
    iget-object v1, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v1, Lnx0/b;

    .line 95
    .line 96
    iget v2, v1, Lnx0/b;->f:I

    .line 97
    .line 98
    if-ge v0, v2, :cond_1

    .line 99
    .line 100
    add-int/lit8 v2, v0, 0x1

    .line 101
    .line 102
    iput v2, p0, Lnx0/a;->e:I

    .line 103
    .line 104
    iput v0, p0, Lnx0/a;->f:I

    .line 105
    .line 106
    iget-object p0, v1, Lnx0/b;->d:[Ljava/lang/Object;

    .line 107
    .line 108
    iget v1, v1, Lnx0/b;->e:I

    .line 109
    .line 110
    add-int/2addr v1, v0

    .line 111
    aget-object p0, p0, v1

    .line 112
    .line 113
    return-object p0

    .line 114
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 115
    .line 116
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 117
    .line 118
    .line 119
    throw p0

    .line 120
    nop

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final nextIndex()I
    .locals 1

    .line 1
    iget v0, p0, Lnx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lnx0/a;->e:I

    .line 7
    .line 8
    iget p0, p0, Lnx0/a;->f:I

    .line 9
    .line 10
    sub-int/2addr v0, p0

    .line 11
    return v0

    .line 12
    :pswitch_0
    iget p0, p0, Lnx0/a;->e:I

    .line 13
    .line 14
    add-int/lit8 p0, p0, 0x1

    .line 15
    .line 16
    return p0

    .line 17
    :pswitch_1
    iget p0, p0, Lnx0/a;->e:I

    .line 18
    .line 19
    return p0

    .line 20
    :pswitch_2
    iget p0, p0, Lnx0/a;->e:I

    .line 21
    .line 22
    return p0

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final previous()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lnx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lv3/s;

    .line 9
    .line 10
    iget-object v0, v0, Lv3/s;->d:Landroidx/collection/l0;

    .line 11
    .line 12
    iget v1, p0, Lnx0/a;->e:I

    .line 13
    .line 14
    add-int/lit8 v1, v1, -0x1

    .line 15
    .line 16
    iput v1, p0, Lnx0/a;->e:I

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.Modifier.Node"

    .line 23
    .line 24
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    check-cast p0, Lx2/r;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    invoke-virtual {p0}, Lnx0/a;->c()V

    .line 31
    .line 32
    .line 33
    iget v0, p0, Lnx0/a;->e:I

    .line 34
    .line 35
    iget-object v1, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v1, Lv2/o;

    .line 38
    .line 39
    invoke-virtual {v1}, Lv2/o;->size()I

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    invoke-static {v0, v2}, Lv2/p;->a(II)V

    .line 44
    .line 45
    .line 46
    iget v0, p0, Lnx0/a;->e:I

    .line 47
    .line 48
    iput v0, p0, Lnx0/a;->f:I

    .line 49
    .line 50
    invoke-virtual {v1, v0}, Lv2/o;->get(I)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    iget v1, p0, Lnx0/a;->e:I

    .line 55
    .line 56
    add-int/lit8 v1, v1, -0x1

    .line 57
    .line 58
    iput v1, p0, Lnx0/a;->e:I

    .line 59
    .line 60
    return-object v0

    .line 61
    :pswitch_1
    invoke-virtual {p0}, Lnx0/a;->b()V

    .line 62
    .line 63
    .line 64
    iget v0, p0, Lnx0/a;->e:I

    .line 65
    .line 66
    if-lez v0, :cond_0

    .line 67
    .line 68
    add-int/lit8 v0, v0, -0x1

    .line 69
    .line 70
    iput v0, p0, Lnx0/a;->e:I

    .line 71
    .line 72
    iput v0, p0, Lnx0/a;->f:I

    .line 73
    .line 74
    iget-object p0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p0, Lnx0/c;

    .line 77
    .line 78
    iget-object p0, p0, Lnx0/c;->d:[Ljava/lang/Object;

    .line 79
    .line 80
    aget-object p0, p0, v0

    .line 81
    .line 82
    return-object p0

    .line 83
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 84
    .line 85
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :pswitch_2
    invoke-virtual {p0}, Lnx0/a;->a()V

    .line 90
    .line 91
    .line 92
    iget v0, p0, Lnx0/a;->e:I

    .line 93
    .line 94
    if-lez v0, :cond_1

    .line 95
    .line 96
    add-int/lit8 v0, v0, -0x1

    .line 97
    .line 98
    iput v0, p0, Lnx0/a;->e:I

    .line 99
    .line 100
    iput v0, p0, Lnx0/a;->f:I

    .line 101
    .line 102
    iget-object p0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast p0, Lnx0/b;

    .line 105
    .line 106
    iget-object v1, p0, Lnx0/b;->d:[Ljava/lang/Object;

    .line 107
    .line 108
    iget p0, p0, Lnx0/b;->e:I

    .line 109
    .line 110
    add-int/2addr p0, v0

    .line 111
    aget-object p0, v1, p0

    .line 112
    .line 113
    return-object p0

    .line 114
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 115
    .line 116
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 117
    .line 118
    .line 119
    throw p0

    .line 120
    nop

    .line 121
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final previousIndex()I
    .locals 1

    .line 1
    iget v0, p0, Lnx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lnx0/a;->e:I

    .line 7
    .line 8
    iget p0, p0, Lnx0/a;->f:I

    .line 9
    .line 10
    sub-int/2addr v0, p0

    .line 11
    add-int/lit8 v0, v0, -0x1

    .line 12
    .line 13
    return v0

    .line 14
    :pswitch_0
    iget p0, p0, Lnx0/a;->e:I

    .line 15
    .line 16
    return p0

    .line 17
    :pswitch_1
    iget p0, p0, Lnx0/a;->e:I

    .line 18
    .line 19
    :goto_0
    add-int/lit8 p0, p0, -0x1

    .line 20
    .line 21
    return p0

    .line 22
    :pswitch_2
    iget p0, p0, Lnx0/a;->e:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove()V
    .locals 3

    .line 1
    iget v0, p0, Lnx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 7
    .line 8
    const-string v0, "Operation is not supported for read-only collection"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    invoke-virtual {p0}, Lnx0/a;->c()V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lv2/o;

    .line 20
    .line 21
    iget v1, p0, Lnx0/a;->f:I

    .line 22
    .line 23
    invoke-virtual {v0, v1}, Lv2/o;->remove(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    iget v1, p0, Lnx0/a;->e:I

    .line 27
    .line 28
    const/4 v2, -0x1

    .line 29
    add-int/2addr v1, v2

    .line 30
    iput v1, p0, Lnx0/a;->e:I

    .line 31
    .line 32
    iput v2, p0, Lnx0/a;->f:I

    .line 33
    .line 34
    invoke-static {v0}, Lv2/p;->f(Lv2/o;)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    iput v0, p0, Lnx0/a;->g:I

    .line 39
    .line 40
    return-void

    .line 41
    :pswitch_1
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Lnx0/c;

    .line 44
    .line 45
    invoke-virtual {p0}, Lnx0/a;->b()V

    .line 46
    .line 47
    .line 48
    iget v1, p0, Lnx0/a;->f:I

    .line 49
    .line 50
    const/4 v2, -0x1

    .line 51
    if-eq v1, v2, :cond_0

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Lnx0/c;->e(I)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    iget v1, p0, Lnx0/a;->f:I

    .line 57
    .line 58
    iput v1, p0, Lnx0/a;->e:I

    .line 59
    .line 60
    iput v2, p0, Lnx0/a;->f:I

    .line 61
    .line 62
    invoke-static {v0}, Lnx0/c;->g(Lnx0/c;)I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    iput v0, p0, Lnx0/a;->g:I

    .line 67
    .line 68
    return-void

    .line 69
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string v0, "Call next() or previous() before removing element from the iterator."

    .line 72
    .line 73
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :pswitch_2
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v0, Lnx0/b;

    .line 80
    .line 81
    invoke-virtual {p0}, Lnx0/a;->a()V

    .line 82
    .line 83
    .line 84
    iget v1, p0, Lnx0/a;->f:I

    .line 85
    .line 86
    const/4 v2, -0x1

    .line 87
    if-eq v1, v2, :cond_1

    .line 88
    .line 89
    invoke-virtual {v0, v1}, Lnx0/b;->e(I)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    iget v1, p0, Lnx0/a;->f:I

    .line 93
    .line 94
    iput v1, p0, Lnx0/a;->e:I

    .line 95
    .line 96
    iput v2, p0, Lnx0/a;->f:I

    .line 97
    .line 98
    invoke-static {v0}, Lnx0/b;->g(Lnx0/b;)I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    iput v0, p0, Lnx0/a;->g:I

    .line 103
    .line 104
    return-void

    .line 105
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 106
    .line 107
    const-string v0, "Call next() or previous() before removing element from the iterator."

    .line 108
    .line 109
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    throw p0

    .line 113
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final set(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget v0, p0, Lnx0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 7
    .line 8
    const-string p1, "Operation is not supported for read-only collection"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    iget-object v0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lv2/o;

    .line 17
    .line 18
    invoke-virtual {p0}, Lnx0/a;->c()V

    .line 19
    .line 20
    .line 21
    iget v1, p0, Lnx0/a;->f:I

    .line 22
    .line 23
    if-ltz v1, :cond_0

    .line 24
    .line 25
    invoke-virtual {v0, v1, p1}, Lv2/o;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    invoke-static {v0}, Lv2/p;->f(Lv2/o;)I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    iput p1, p0, Lnx0/a;->g:I

    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 36
    .line 37
    const-string p1, "Cannot call set before the first call to next() or previous() or immediately after a call to add() or remove()"

    .line 38
    .line 39
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :pswitch_1
    invoke-virtual {p0}, Lnx0/a;->b()V

    .line 44
    .line 45
    .line 46
    iget v0, p0, Lnx0/a;->f:I

    .line 47
    .line 48
    const/4 v1, -0x1

    .line 49
    if-eq v0, v1, :cond_1

    .line 50
    .line 51
    iget-object p0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast p0, Lnx0/c;

    .line 54
    .line 55
    invoke-virtual {p0, v0, p1}, Lnx0/c;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string p1, "Call next() or previous() before replacing element from the iterator."

    .line 62
    .line 63
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p0

    .line 67
    :pswitch_2
    invoke-virtual {p0}, Lnx0/a;->a()V

    .line 68
    .line 69
    .line 70
    iget v0, p0, Lnx0/a;->f:I

    .line 71
    .line 72
    const/4 v1, -0x1

    .line 73
    if-eq v0, v1, :cond_2

    .line 74
    .line 75
    iget-object p0, p0, Lnx0/a;->h:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p0, Lnx0/b;

    .line 78
    .line 79
    invoke-virtual {p0, v0, p1}, Lnx0/b;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    return-void

    .line 83
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 84
    .line 85
    const-string p1, "Call next() or previous() before replacing element from the iterator."

    .line 86
    .line 87
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
