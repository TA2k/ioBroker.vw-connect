.class public final synthetic Luz0/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Luz0/d1;


# direct methods
.method public synthetic constructor <init>(Luz0/d1;I)V
    .locals 0

    .line 1
    iput p2, p0, Luz0/c1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Luz0/c1;->e:Luz0/d1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Luz0/c1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Luz0/c1;->e:Luz0/d1;

    .line 7
    .line 8
    iget-object v0, p0, Luz0/d1;->k:Ljava/lang/Object;

    .line 9
    .line 10
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, [Lsz0/g;

    .line 15
    .line 16
    invoke-static {p0, v0}, Luz0/b1;->g(Lsz0/g;[Lsz0/g;)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0

    .line 25
    :pswitch_0
    iget-object p0, p0, Luz0/c1;->e:Luz0/d1;

    .line 26
    .line 27
    iget-object p0, p0, Luz0/d1;->b:Luz0/c0;

    .line 28
    .line 29
    if-eqz p0, :cond_0

    .line 30
    .line 31
    invoke-interface {p0}, Luz0/c0;->typeParametersSerializers()[Lqz0/a;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    if-eqz p0, :cond_0

    .line 36
    .line 37
    new-instance v0, Ljava/util/ArrayList;

    .line 38
    .line 39
    array-length v1, p0

    .line 40
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 41
    .line 42
    .line 43
    array-length v1, p0

    .line 44
    const/4 v2, 0x0

    .line 45
    :goto_0
    if-ge v2, v1, :cond_1

    .line 46
    .line 47
    aget-object v3, p0, v2

    .line 48
    .line 49
    invoke-interface {v3}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    add-int/lit8 v2, v2, 0x1

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_0
    const/4 v0, 0x0

    .line 60
    :cond_1
    invoke-static {v0}, Luz0/b1;->c(Ljava/util/List;)[Lsz0/g;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :pswitch_1
    iget-object p0, p0, Luz0/c1;->e:Luz0/d1;

    .line 66
    .line 67
    iget-object p0, p0, Luz0/d1;->b:Luz0/c0;

    .line 68
    .line 69
    if-eqz p0, :cond_2

    .line 70
    .line 71
    invoke-interface {p0}, Luz0/c0;->childSerializers()[Lqz0/a;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    if-nez p0, :cond_3

    .line 76
    .line 77
    :cond_2
    sget-object p0, Luz0/b1;->b:[Lqz0/a;

    .line 78
    .line 79
    :cond_3
    return-object p0

    .line 80
    nop

    .line 81
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
