.class public final Lxw/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public final d:I

.field public e:I

.field public final synthetic f:Lxw/a;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lxw/a;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxw/b;->f:Lxw/a;

    .line 5
    .line 6
    iput-object p2, p0, Lxw/b;->g:Ljava/lang/Object;

    .line 7
    .line 8
    iget p1, p1, Lxw/a;->a:I

    .line 9
    .line 10
    packed-switch p1, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    check-cast p2, [C

    .line 14
    .line 15
    array-length p1, p2

    .line 16
    goto :goto_0

    .line 17
    :pswitch_0
    check-cast p2, [B

    .line 18
    .line 19
    array-length p1, p2

    .line 20
    goto :goto_0

    .line 21
    :pswitch_1
    check-cast p2, [Z

    .line 22
    .line 23
    array-length p1, p2

    .line 24
    goto :goto_0

    .line 25
    :pswitch_2
    check-cast p2, [Ljava/lang/Object;

    .line 26
    .line 27
    array-length p1, p2

    .line 28
    goto :goto_0

    .line 29
    :pswitch_3
    check-cast p2, [D

    .line 30
    .line 31
    array-length p1, p2

    .line 32
    goto :goto_0

    .line 33
    :pswitch_4
    check-cast p2, [F

    .line 34
    .line 35
    array-length p1, p2

    .line 36
    goto :goto_0

    .line 37
    :pswitch_5
    check-cast p2, [J

    .line 38
    .line 39
    array-length p1, p2

    .line 40
    goto :goto_0

    .line 41
    :pswitch_6
    check-cast p2, [I

    .line 42
    .line 43
    array-length p1, p2

    .line 44
    goto :goto_0

    .line 45
    :pswitch_7
    check-cast p2, [S

    .line 46
    .line 47
    array-length p1, p2

    .line 48
    :goto_0
    iput p1, p0, Lxw/b;->d:I

    .line 49
    .line 50
    return-void

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lxw/b;->e:I

    .line 2
    .line 3
    iget p0, p0, Lxw/b;->d:I

    .line 4
    .line 5
    if-ge v0, p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final next()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lxw/b;->e:I

    .line 2
    .line 3
    add-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    iput v1, p0, Lxw/b;->e:I

    .line 6
    .line 7
    iget-object v1, p0, Lxw/b;->f:Lxw/a;

    .line 8
    .line 9
    iget-object p0, p0, Lxw/b;->g:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-virtual {v1, v0, p0}, Lxw/a;->a(ILjava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final remove()V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method
