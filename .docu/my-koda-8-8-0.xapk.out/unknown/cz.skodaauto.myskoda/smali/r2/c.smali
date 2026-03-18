.class public Lr2/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;
.implements Lby0/a;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public final f:Ljava/util/Map;

.field public g:I


# direct methods
.method public constructor <init>(Ljava/lang/Object;Ljava/util/Map;I)V
    .locals 0

    .line 1
    iput p3, p0, Lr2/c;->d:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lr2/c;->e:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p2, p0, Lr2/c;->f:Ljava/util/Map;

    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    const-string p3, "map"

    .line 15
    .line 16
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object p1, p0, Lr2/c;->e:Ljava/lang/Object;

    .line 23
    .line 24
    iput-object p2, p0, Lr2/c;->f:Ljava/util/Map;

    .line 25
    .line 26
    return-void

    .line 27
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lr2/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lr2/c;->g:I

    .line 7
    .line 8
    iget-object p0, p0, Lr2/c;->f:Ljava/util/Map;

    .line 9
    .line 10
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-ge v0, p0, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    :goto_0
    return p0

    .line 20
    :pswitch_0
    iget v0, p0, Lr2/c;->g:I

    .line 21
    .line 22
    iget-object p0, p0, Lr2/c;->f:Ljava/util/Map;

    .line 23
    .line 24
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-ge v0, p0, :cond_1

    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    const/4 p0, 0x0

    .line 33
    :goto_1
    return p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public next()Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lr2/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lr2/c;->hasNext()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    iget-object v0, p0, Lr2/c;->e:Ljava/lang/Object;

    .line 13
    .line 14
    iget v1, p0, Lr2/c;->g:I

    .line 15
    .line 16
    add-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    iput v1, p0, Lr2/c;->g:I

    .line 19
    .line 20
    iget-object v1, p0, Lr2/c;->f:Ljava/util/Map;

    .line 21
    .line 22
    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    if-eqz v1, :cond_0

    .line 27
    .line 28
    check-cast v1, Lty0/a;

    .line 29
    .line 30
    iget-object v1, v1, Lty0/a;->b:Ljava/lang/Object;

    .line 31
    .line 32
    iput-object v1, p0, Lr2/c;->e:Ljava/lang/Object;

    .line 33
    .line 34
    return-object v0

    .line 35
    :cond_0
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 36
    .line 37
    const-string v1, "Hash code of an element ("

    .line 38
    .line 39
    const-string v2, ") has changed after it was added to the persistent set."

    .line 40
    .line 41
    invoke-static {v0, v1, v2}, Lf2/m0;->g(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-direct {p0, v0}, Ljava/util/ConcurrentModificationException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 50
    .line 51
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :pswitch_0
    invoke-virtual {p0}, Lr2/c;->hasNext()Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-eqz v0, :cond_3

    .line 60
    .line 61
    iget-object v0, p0, Lr2/c;->e:Ljava/lang/Object;

    .line 62
    .line 63
    iget v1, p0, Lr2/c;->g:I

    .line 64
    .line 65
    add-int/lit8 v1, v1, 0x1

    .line 66
    .line 67
    iput v1, p0, Lr2/c;->g:I

    .line 68
    .line 69
    iget-object v1, p0, Lr2/c;->f:Ljava/util/Map;

    .line 70
    .line 71
    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    if-eqz v1, :cond_2

    .line 76
    .line 77
    check-cast v1, Lr2/a;

    .line 78
    .line 79
    iget-object v1, v1, Lr2/a;->b:Ljava/lang/Object;

    .line 80
    .line 81
    iput-object v1, p0, Lr2/c;->e:Ljava/lang/Object;

    .line 82
    .line 83
    return-object v0

    .line 84
    :cond_2
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 85
    .line 86
    const-string v1, "Hash code of an element ("

    .line 87
    .line 88
    const-string v2, ") has changed after it was added to the persistent set."

    .line 89
    .line 90
    invoke-static {v0, v1, v2}, Lf2/m0;->g(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-direct {p0, v0}, Ljava/util/ConcurrentModificationException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw p0

    .line 98
    :cond_3
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 99
    .line 100
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 101
    .line 102
    .line 103
    throw p0

    .line 104
    nop

    .line 105
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public remove()V
    .locals 1

    .line 1
    iget p0, p0, Lr2/c;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

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
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
