.class public final Lg1/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ln2/b;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    packed-switch p1, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    .line 6
    .line 7
    new-instance p1, Ln2/b;

    .line 8
    .line 9
    const/16 v0, 0x10

    .line 10
    .line 11
    new-array v0, v0, [Lg1/x;

    .line 12
    .line 13
    invoke-direct {p1, v0}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lg1/r;->a:Ln2/b;

    .line 17
    .line 18
    return-void

    .line 19
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    .line 21
    .line 22
    new-instance p1, Ln2/b;

    .line 23
    .line 24
    const/16 v0, 0x10

    .line 25
    .line 26
    new-array v0, v0, [Lo1/k;

    .line 27
    .line 28
    invoke-direct {p1, v0}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, Lg1/r;->a:Ln2/b;

    .line 32
    .line 33
    return-void

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public a(Ljava/util/concurrent/CancellationException;)V
    .locals 5

    .line 1
    iget-object p0, p0, Lg1/r;->a:Ln2/b;

    .line 2
    .line 3
    iget v0, p0, Ln2/b;->f:I

    .line 4
    .line 5
    new-array v1, v0, [Lvy0/k;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    move v3, v2

    .line 9
    :goto_0
    if-ge v3, v0, :cond_0

    .line 10
    .line 11
    iget-object v4, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 12
    .line 13
    aget-object v4, v4, v3

    .line 14
    .line 15
    check-cast v4, Lg1/x;

    .line 16
    .line 17
    iget-object v4, v4, Lg1/x;->b:Lvy0/l;

    .line 18
    .line 19
    aput-object v4, v1, v3

    .line 20
    .line 21
    add-int/lit8 v3, v3, 0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    :goto_1
    if-ge v2, v0, :cond_1

    .line 25
    .line 26
    aget-object v3, v1, v2

    .line 27
    .line 28
    invoke-interface {v3, p1}, Lvy0/k;->c(Ljava/lang/Throwable;)Z

    .line 29
    .line 30
    .line 31
    add-int/lit8 v2, v2, 0x1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    iget p0, p0, Ln2/b;->f:I

    .line 35
    .line 36
    if-nez p0, :cond_2

    .line 37
    .line 38
    return-void

    .line 39
    :cond_2
    const-string p0, "uncancelled requests present"

    .line 40
    .line 41
    invoke-static {p0}, Lj1/b;->c(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public b()V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Lg1/r;->a:Ln2/b;

    .line 3
    .line 4
    iget v1, p0, Ln2/b;->f:I

    .line 5
    .line 6
    invoke-static {v0, v1}, Lkp/r9;->m(II)Lgy0/j;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iget v1, v0, Lgy0/h;->d:I

    .line 11
    .line 12
    iget v0, v0, Lgy0/h;->e:I

    .line 13
    .line 14
    if-gt v1, v0, :cond_0

    .line 15
    .line 16
    :goto_0
    iget-object v2, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 17
    .line 18
    aget-object v2, v2, v1

    .line 19
    .line 20
    check-cast v2, Lg1/x;

    .line 21
    .line 22
    iget-object v2, v2, Lg1/x;->b:Lvy0/l;

    .line 23
    .line 24
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    invoke-virtual {v2, v3}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    if-eq v1, v0, :cond_0

    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-virtual {p0}, Ln2/b;->i()V

    .line 35
    .line 36
    .line 37
    return-void
.end method
