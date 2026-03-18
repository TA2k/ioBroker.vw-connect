.class public final Landroidx/collection/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;
.implements Lby0/a;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroidx/collection/p0;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Landroidx/collection/o0;->d:I

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    iput-object p1, p0, Landroidx/collection/o0;->g:Ljava/lang/Object;

    const/4 v0, -0x1

    .line 14
    iput v0, p0, Landroidx/collection/o0;->e:I

    .line 15
    new-instance v0, Landroidx/collection/n0;

    const/4 v1, 0x0

    invoke-direct {v0, p1, p0, v1}, Landroidx/collection/n0;-><init>(Landroidx/collection/p0;Landroidx/collection/o0;Lkotlin/coroutines/Continuation;)V

    invoke-static {v0}, Llp/ke;->a(Lay0/n;)Lky0/k;

    move-result-object p1

    iput-object p1, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/collection/t0;)V
    .locals 2

    const/4 v0, 0x1

    iput v0, p0, Landroidx/collection/o0;->d:I

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-object p1, p0, Landroidx/collection/o0;->g:Ljava/lang/Object;

    const/4 v0, -0x1

    .line 10
    iput v0, p0, Landroidx/collection/o0;->e:I

    .line 11
    new-instance v0, Landroidx/collection/s0;

    const/4 v1, 0x0

    invoke-direct {v0, p1, p0, v1}, Landroidx/collection/s0;-><init>(Landroidx/collection/t0;Landroidx/collection/o0;Lkotlin/coroutines/Continuation;)V

    invoke-static {v0}, Llp/ke;->a(Lay0/n;)Lky0/k;

    move-result-object p1

    iput-object p1, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lky0/i;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Landroidx/collection/o0;->d:I

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput-object p1, p0, Landroidx/collection/o0;->g:Ljava/lang/Object;

    const/4 p1, -0x2

    .line 7
    iput p1, p0, Landroidx/collection/o0;->e:I

    return-void
.end method

.method public constructor <init>(Lky0/r;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Landroidx/collection/o0;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Landroidx/collection/o0;->g:Ljava/lang/Object;

    .line 3
    iget-object p1, p1, Lky0/r;->a:Lky0/j;

    .line 4
    invoke-interface {p1}, Lky0/j;->iterator()Ljava/util/Iterator;

    move-result-object p1

    iput-object p1, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a()V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/collection/o0;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lky0/i;

    .line 4
    .line 5
    iget v1, p0, Landroidx/collection/o0;->e:I

    .line 6
    .line 7
    const/4 v2, -0x2

    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    iget-object v0, v0, Lky0/i;->c:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lay0/a;

    .line 13
    .line 14
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    iget-object v0, v0, Lky0/i;->b:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v0, Lay0/k;

    .line 22
    .line 23
    iget-object v1, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    .line 24
    .line 25
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    :goto_0
    iput-object v0, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    .line 33
    .line 34
    if-nez v0, :cond_1

    .line 35
    .line 36
    const/4 v0, 0x0

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/4 v0, 0x1

    .line 39
    :goto_1
    iput v0, p0, Landroidx/collection/o0;->e:I

    .line 40
    .line 41
    return-void
.end method

.method public final hasNext()Z
    .locals 5

    .line 1
    iget v0, p0, Landroidx/collection/o0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/collection/o0;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lky0/r;

    .line 9
    .line 10
    iget-object v1, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ljava/util/Iterator;

    .line 13
    .line 14
    :goto_0
    iget v2, p0, Landroidx/collection/o0;->e:I

    .line 15
    .line 16
    iget v3, v0, Lky0/r;->b:I

    .line 17
    .line 18
    const/4 v4, 0x1

    .line 19
    if-ge v2, v3, :cond_0

    .line 20
    .line 21
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    iget v2, p0, Landroidx/collection/o0;->e:I

    .line 31
    .line 32
    add-int/2addr v2, v4

    .line 33
    iput v2, p0, Landroidx/collection/o0;->e:I

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    iget p0, p0, Landroidx/collection/o0;->e:I

    .line 37
    .line 38
    iget v0, v0, Lky0/r;->c:I

    .line 39
    .line 40
    if-ge p0, v0, :cond_1

    .line 41
    .line 42
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_1

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    const/4 v4, 0x0

    .line 50
    :goto_1
    return v4

    .line 51
    :pswitch_0
    iget v0, p0, Landroidx/collection/o0;->e:I

    .line 52
    .line 53
    if-gez v0, :cond_2

    .line 54
    .line 55
    invoke-virtual {p0}, Landroidx/collection/o0;->a()V

    .line 56
    .line 57
    .line 58
    :cond_2
    iget p0, p0, Landroidx/collection/o0;->e:I

    .line 59
    .line 60
    const/4 v0, 0x1

    .line 61
    if-ne p0, v0, :cond_3

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_3
    const/4 v0, 0x0

    .line 65
    :goto_2
    return v0

    .line 66
    :pswitch_1
    iget-object p0, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p0, Lky0/k;

    .line 69
    .line 70
    invoke-virtual {p0}, Lky0/k;->hasNext()Z

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    return p0

    .line 75
    :pswitch_2
    iget-object p0, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p0, Lky0/k;

    .line 78
    .line 79
    invoke-virtual {p0}, Lky0/k;->hasNext()Z

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    return p0

    .line 84
    nop

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Landroidx/collection/o0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/collection/o0;->g:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lky0/r;

    .line 9
    .line 10
    iget-object v1, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Ljava/util/Iterator;

    .line 13
    .line 14
    :goto_0
    iget v2, p0, Landroidx/collection/o0;->e:I

    .line 15
    .line 16
    iget v3, v0, Lky0/r;->b:I

    .line 17
    .line 18
    if-ge v2, v3, :cond_0

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    iget v2, p0, Landroidx/collection/o0;->e:I

    .line 30
    .line 31
    add-int/lit8 v2, v2, 0x1

    .line 32
    .line 33
    iput v2, p0, Landroidx/collection/o0;->e:I

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    iget v2, p0, Landroidx/collection/o0;->e:I

    .line 37
    .line 38
    iget v0, v0, Lky0/r;->c:I

    .line 39
    .line 40
    if-ge v2, v0, :cond_1

    .line 41
    .line 42
    add-int/lit8 v2, v2, 0x1

    .line 43
    .line 44
    iput v2, p0, Landroidx/collection/o0;->e:I

    .line 45
    .line 46
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 52
    .line 53
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :pswitch_0
    iget v0, p0, Landroidx/collection/o0;->e:I

    .line 58
    .line 59
    if-gez v0, :cond_2

    .line 60
    .line 61
    invoke-virtual {p0}, Landroidx/collection/o0;->a()V

    .line 62
    .line 63
    .line 64
    :cond_2
    iget v0, p0, Landroidx/collection/o0;->e:I

    .line 65
    .line 66
    if-eqz v0, :cond_3

    .line 67
    .line 68
    iget-object v0, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    .line 69
    .line 70
    const-string v1, "null cannot be cast to non-null type T of kotlin.sequences.GeneratorSequence"

    .line 71
    .line 72
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    const/4 v1, -0x1

    .line 76
    iput v1, p0, Landroidx/collection/o0;->e:I

    .line 77
    .line 78
    return-object v0

    .line 79
    :cond_3
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 80
    .line 81
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :pswitch_1
    iget-object p0, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast p0, Lky0/k;

    .line 88
    .line 89
    invoke-virtual {p0}, Lky0/k;->next()Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    return-object p0

    .line 94
    :pswitch_2
    iget-object p0, p0, Landroidx/collection/o0;->f:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast p0, Lky0/k;

    .line 97
    .line 98
    invoke-virtual {p0}, Lky0/k;->next()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0

    .line 103
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
    iget v0, p0, Landroidx/collection/o0;->d:I

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
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 15
    .line 16
    const-string v0, "Operation is not supported for read-only collection"

    .line 17
    .line 18
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :pswitch_1
    iget v0, p0, Landroidx/collection/o0;->e:I

    .line 23
    .line 24
    const/4 v1, -0x1

    .line 25
    if-eq v0, v1, :cond_0

    .line 26
    .line 27
    iget-object v2, p0, Landroidx/collection/o0;->g:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v2, Landroidx/collection/t0;

    .line 30
    .line 31
    iget-object v2, v2, Landroidx/collection/t0;->e:Landroidx/collection/r0;

    .line 32
    .line 33
    invoke-virtual {v2, v0}, Landroidx/collection/r0;->m(I)V

    .line 34
    .line 35
    .line 36
    iput v1, p0, Landroidx/collection/o0;->e:I

    .line 37
    .line 38
    :cond_0
    return-void

    .line 39
    :pswitch_2
    iget v0, p0, Landroidx/collection/o0;->e:I

    .line 40
    .line 41
    const/4 v1, -0x1

    .line 42
    if-eq v0, v1, :cond_1

    .line 43
    .line 44
    iget-object v2, p0, Landroidx/collection/o0;->g:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v2, Landroidx/collection/p0;

    .line 47
    .line 48
    iget-object v2, v2, Landroidx/collection/p0;->e:Landroidx/collection/m0;

    .line 49
    .line 50
    invoke-virtual {v2, v0}, Landroidx/collection/m0;->h(I)V

    .line 51
    .line 52
    .line 53
    iput v1, p0, Landroidx/collection/o0;->e:I

    .line 54
    .line 55
    :cond_1
    return-void

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
