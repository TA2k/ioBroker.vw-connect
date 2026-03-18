.class public final Lj3/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;
.implements Lby0/a;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/util/Iterator;


# direct methods
.method public constructor <init>(Lj3/g0;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lj3/f0;->d:I

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iget-object p1, p1, Lj3/g0;->m:Ljava/util/List;

    .line 9
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    iput-object p1, p0, Lj3/f0;->e:Ljava/util/Iterator;

    return-void
.end method

.method public constructor <init>(Lsy0/d;)V
    .locals 4

    const/4 v0, 0x2

    iput v0, p0, Lj3/f0;->d:I

    const-string v0, "builder"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/16 v0, 0x8

    .line 5
    new-array v1, v0, [Lq2/j;

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_0

    new-instance v3, Lsy0/l;

    invoke-direct {v3, p0}, Lsy0/l;-><init>(Lj3/f0;)V

    aput-object v3, v1, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 6
    :cond_0
    new-instance v0, Lsy0/e;

    invoke-direct {v0, p1, v1}, Lsy0/e;-><init>(Lsy0/d;[Lq2/j;)V

    iput-object v0, p0, Lj3/f0;->e:Ljava/util/Iterator;

    return-void
.end method

.method public constructor <init>(Lt2/f;)V
    .locals 4

    const/4 v0, 0x1

    iput v0, p0, Lj3/f0;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/16 v0, 0x8

    .line 2
    new-array v1, v0, [Lq2/j;

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_0

    new-instance v3, Lq2/l;

    invoke-direct {v3, p0}, Lq2/l;-><init>(Lj3/f0;)V

    aput-object v3, v1, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 3
    :cond_0
    new-instance v0, Lq2/d;

    invoke-direct {v0, p1, v1}, Lq2/d;-><init>(Lt2/f;[Lq2/j;)V

    iput-object v0, p0, Lj3/f0;->e:Ljava/util/Iterator;

    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lj3/f0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lj3/f0;->e:Ljava/util/Iterator;

    .line 7
    .line 8
    check-cast p0, Lsy0/e;

    .line 9
    .line 10
    iget-boolean p0, p0, Lq2/c;->f:Z

    .line 11
    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lj3/f0;->e:Ljava/util/Iterator;

    .line 14
    .line 15
    check-cast p0, Lq2/d;

    .line 16
    .line 17
    iget-boolean p0, p0, Lq2/c;->f:Z

    .line 18
    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lj3/f0;->e:Ljava/util/Iterator;

    .line 21
    .line 22
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lj3/f0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lj3/f0;->e:Ljava/util/Iterator;

    .line 7
    .line 8
    check-cast p0, Lsy0/e;

    .line 9
    .line 10
    invoke-virtual {p0}, Lsy0/e;->next()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljava/util/Map$Entry;

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_0
    iget-object p0, p0, Lj3/f0;->e:Ljava/util/Iterator;

    .line 18
    .line 19
    check-cast p0, Lq2/d;

    .line 20
    .line 21
    invoke-virtual {p0}, Lq2/d;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ljava/util/Map$Entry;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_1
    iget-object p0, p0, Lj3/f0;->e:Ljava/util/Iterator;

    .line 29
    .line 30
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Lj3/i0;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove()V
    .locals 1

    .line 1
    iget v0, p0, Lj3/f0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lj3/f0;->e:Ljava/util/Iterator;

    .line 7
    .line 8
    check-cast p0, Lsy0/e;

    .line 9
    .line 10
    invoke-virtual {p0}, Lsy0/e;->remove()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    iget-object p0, p0, Lj3/f0;->e:Ljava/util/Iterator;

    .line 15
    .line 16
    check-cast p0, Lq2/d;

    .line 17
    .line 18
    invoke-virtual {p0}, Lq2/d;->remove()V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 23
    .line 24
    const-string v0, "Operation is not supported for read-only collection"

    .line 25
    .line 26
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
