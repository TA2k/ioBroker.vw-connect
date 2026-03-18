.class public final Ldx0/a;
.super Ldx0/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Ldx0/a;->i:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Ldx0/c;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget p0, p0, Ldx0/a;->i:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-object p1

    .line 7
    :pswitch_0
    check-cast p1, [I

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    array-length v0, p1

    .line 11
    const/4 v1, -0x1

    .line 12
    invoke-static {p1, p0, v0, v1}, Ljava/util/Arrays;->fill([IIII)V

    .line 13
    .line 14
    .line 15
    return-object p1

    .line 16
    :pswitch_1
    check-cast p1, Lpw0/c;

    .line 17
    .line 18
    iget-object p0, p1, Lpw0/c;->a:Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_0

    .line 29
    .line 30
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    check-cast v1, [I

    .line 35
    .line 36
    sget-object v2, Lpw0/e;->a:Ldx0/a;

    .line 37
    .line 38
    invoke-virtual {v2, v1}, Ldx0/c;->o0(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 43
    .line 44
    .line 45
    return-object p1

    .line 46
    nop

    .line 47
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b()Ljava/lang/Object;
    .locals 3

    .line 1
    iget p0, p0, Ldx0/a;->i:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/16 p0, 0x800

    .line 7
    .line 8
    new-array p0, p0, [C

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_0
    const/16 p0, 0x300

    .line 12
    .line 13
    new-array v0, p0, [I

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    :goto_0
    if-ge v1, p0, :cond_0

    .line 17
    .line 18
    const/4 v2, -0x1

    .line 19
    aput v2, v0, v1

    .line 20
    .line 21
    add-int/lit8 v1, v1, 0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    return-object v0

    .line 25
    :pswitch_1
    new-instance p0, Lpw0/c;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    new-instance v0, Ljava/util/ArrayList;

    .line 31
    .line 32
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 33
    .line 34
    .line 35
    iput-object v0, p0, Lpw0/c;->a:Ljava/util/ArrayList;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_2
    const/16 p0, 0x1000

    .line 39
    .line 40
    new-array p0, p0, [B

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
